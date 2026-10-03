"""Sighting counts stay correct under OpenCTI's ACTUAL upsert semantics.

What OpenCTI 7.x does with an incoming Sighting (opencti-graphql
``utils/upsert-utils.js`` buildUpdatePatchForUpsert and
``database/middleware.ts`` getExistingRelations, read from the running
7.260609.0 image and confirmed on the live platform 2026-10-03 with a
throwaway Indicator and identity, then deleted):

  * MATCH: by id (standard_id or any x_opencti_stix_ids alias) OR by the
    same (sighting_of, where_sighted) pair with first_seen and last_seen
    each within +-30 days (``relations_deduplication``). A new id for an
    existing pair becomes an alias of the stored object.
  * COUNT: if the incoming first_seen is earlier OR last_seen is later than
    the stored one (millisecond precision), count = stored + incoming
    (ADD); otherwise count = incoming (REPLACE). The window is widened.

The live probe, in order (stored count after each write):
  create 100 -> same window 40 (REPLACE) -> last_seen later +50 = 90 (ADD)
  -> NEW id next day +7 = 97 (merged, ADD, 2 aliases) -> inside window 5
  (REPLACE) -> first_seen earlier +3 = 8 (ADD) -> last_seen +1 ms, count 0
  -> 8 (ADD).

The old code sent each day's RUNNING TOTAL every cycle with a later
last_seen, so OpenCTI summed the running totals: one live Sighting read
205,973,057 against 11.6M hive events. These tests drive the real builder,
the real ledger (CycleState) and main.sighting_replay_for_window against a
model of exactly those semantics, and require the stored count to equal the
true number of events after clean cycles, retried cycles, repeated cycles
and cursor rewinds.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from tpot2cti.main import (
    fold_window_counts, sighting_count_scope, sighting_plan_for_window)
from tpot2cti.parsers.base import AttackSession, ParsedEvent
from tpot2cti.state import CycleState
from tpot2cti.stix.builder import STIXBuilder, sighting_floor
from tpot2cti.stix_ids import attacker_ip_indicator_id, attacker_ip_observable_id

T0 = datetime(2026, 9, 20, 22, 0, tzinfo=timezone.utc)
MS = timedelta(milliseconds=1)


# ---------------------------------------------------------------------------
# A model of OpenCTI's sighting upsert (see the module docstring)
# ---------------------------------------------------------------------------

def _dt(v):
    d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    d = d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
    return d.replace(microsecond=(d.microsecond // 1000) * 1000)   # ms, as stored


class OpenCTISightings:
    DEDUP = timedelta(days=30)

    def __init__(self):
        self.objects: list[dict] = []

    def _match(self, s):
        for o in self.objects:
            if s["id"] in o["ids"]:
                return o
        fs, ls = _dt(s["first_seen"]), _dt(s["last_seen"])
        for o in self.objects:
            if (o["from"], o["to"]) == (s["sighting_of_ref"], s["where_sighted_refs"][0]) \
                    and fs - self.DEDUP < o["first_seen"] < fs + self.DEDUP \
                    and ls - self.DEDUP < o["last_seen"] < ls + self.DEDUP:
                return o
        return None

    def upsert(self, s: dict) -> None:
        fs, ls = _dt(s["first_seen"]), _dt(s["last_seen"])
        n = s.get("count", 1)
        o = self._match(s)
        if o is None:
            self.objects.append({"ids": {s["id"]}, "from": s["sighting_of_ref"],
                                 "to": s["where_sighted_refs"][0], "first_seen": fs,
                                 "last_seen": ls, "count": n})
            return
        o["ids"].add(s["id"])
        widen = fs < o["first_seen"] or ls > o["last_seen"]
        o["first_seen"], o["last_seen"] = min(fs, o["first_seen"]), max(ls, o["last_seen"])
        o["count"] = o["count"] + n if widen else n

    def lookup(self, ids):
        """The OpenCTI client's sighting_last_seen, against this model."""
        out = {}
        for o in self.objects:
            for i in o["ids"] & set(ids):
                out[i] = o["last_seen"].isoformat()
        return out

    def count(self, target, sensor_id):
        hits = [o for o in self.objects if o["from"] == target and o["to"] == sensor_id]
        assert len(hits) <= 1, f"{len(hits)} stored objects for one (target, sensor)"
        return hits[0]["count"] if hits else 0


def _sighting(sid, fs, ls, n, target="indicator--t", where="identity--w"):
    return {"type": "sighting", "id": sid, "sighting_of_ref": target,
            "where_sighted_refs": [where], "first_seen": fs, "last_seen": ls, "count": n}


def test_the_model_reproduces_the_live_probe():
    """Pins the model to what the live platform did, step for step."""
    st, D1, D2 = OpenCTISightings(), "2026-09-20", "2026-09-21"
    steps = [
        ("A", f"{D1}T10:00:00.000Z", f"{D1}T10:10:00.000Z", 100, 100),
        ("A", f"{D1}T10:00:00.000Z", f"{D1}T10:10:00.000Z", 40, 40),
        ("A", f"{D1}T10:00:00.000Z", f"{D1}T10:20:00.000Z", 50, 90),
        ("B", f"{D2}T09:00:00.000Z", f"{D2}T09:05:00.000Z", 7, 97),
        ("A", f"{D1}T10:05:00.000Z", f"{D1}T10:15:00.000Z", 5, 5),
        ("A", f"{D1}T09:00:00.000Z", f"{D1}T10:15:00.000Z", 3, 8),
        ("A", f"{D1}T10:00:00.000Z", f"{D2}T09:05:00.001Z", 0, 8),
    ]
    for sid, fs, ls, n, want in steps:
        st.upsert(_sighting("sighting--" + sid, fs, ls, n))
        assert len(st.objects) == 1 and st.objects[0]["count"] == want, (sid, fs, ls, n)
    assert st.objects[0]["ids"] == {"sighting--A", "sighting--B"}


def test_the_old_running_day_total_inflates_under_these_semantics():
    """Why 205,973,057: a day's running total, re-sent each cycle with a
    later last_seen, is ADDED each time."""
    st = OpenCTISightings()
    true_total = 0
    for k in range(96):                      # one day of 15-minute cycles
        true_total += 10                     # 10 events per window
        t = T0.replace(hour=0) + timedelta(minutes=15 * k)
        st.upsert(_sighting("sighting--day", T0.replace(hour=0).isoformat(),
                            (t + timedelta(minutes=14)).isoformat(), true_total))
    assert true_total == 960
    assert st.objects[0]["count"] == sum(10 * (k + 1) for k in range(96)) == 46_560


# ---------------------------------------------------------------------------
# Driving the real code
# ---------------------------------------------------------------------------

SENSOR = "s1"


class Fleet:
    """Events, cycles and a publish into the model; the cursor is explicit.
    One cycle runs exactly what main.run_cycle runs for Sightings:
    sighting_count_scope -> counts over the uncounted parts -> build ->
    sighting_plan_for_window -> finalize_sighting_counts ->
    record_sightings_sent -> publish -> mark_window_counted (clean only)."""

    def __init__(self, cfg, tmp_path):
        self.cfg = cfg
        self.state = CycleState(db_path=tmp_path / "state.db")
        self.store = OpenCTISightings()
        self.events: list[tuple[str, str, datetime]] = []   # (ip, sensor, ts)
        self.seq = 0
        self.last_scope = None
        self.last_stats = {}

    def add(self, ip, start, n, every=timedelta(seconds=7), sensor=SENSOR):
        for k in range(n):
            self.events.append((ip, sensor, start + k * every))

    def truth(self, ip, sensor=SENSOR, upto=None):
        return sum(1 for e in self.events if e[0] == ip and e[1] == sensor
                   and (upto is None or e[2] < upto))

    def stored(self, ip, sensor=SENSOR):
        from tpot2cti.stix_ids import generate_sensor_id
        sid = generate_sensor_id(sensor)
        ind = self.store.count(attacker_ip_indicator_id(ip), sid)
        obs = self.store.count(attacker_ip_observable_id(ip), sid)
        assert ind == obs, "both sides carry the same count"
        return ind

    def cycle(self, ws, we, *, land=lambda i, obj: True, clean=True,
              lookup="store", es_counts=True):
        """Returns the Sightings sent, or None when the cycle wrote nothing
        (rejected)."""
        scope = self.last_scope = sighting_count_scope(self.state, ws, we)
        if scope["mode"] == "reject":
            return None
        b = STIXBuilder(self.cfg)
        b.window_start = ws
        if scope["mode"] == "none":
            b.window_counts_strict = True
        elif es_counts or scope["mode"] == "backfill":
            by_day: dict = {}
            for ip, sensor, ts in self.events:
                if any(a <= ts < z for a, z in scope["parts"]):
                    k = (ip, sensor, ts.strftime("%Y-%m-%d"))
                    by_day[k] = by_day.get(k, 0) + 1
            b.window_event_counts = fold_window_counts(by_day)
            b.window_counts_strict = scope["mode"] == "backfill"
        groups: dict = {}
        for ip, sensor, ts in self.events:
            if ws <= ts < we:
                groups.setdefault((ip, sensor), []).append(ts)
        objs: list[dict] = []
        for (ip, sensor), stamps in sorted(groups.items()):
            self.seq += 1
            ev = ParsedEvent(src_ip=ip, timestamp=min(stamps), sensor_hostname=sensor,
                             event_type="honeytrap", dst_port=445)
            x = AttackSession.from_event(ev)
            x.first_seen, x.last_seen = min(stamps), max(stamps)
            x.session_id = f"sess-{self.seq}"
            objs += b.build_dual_sighting(attacker_ip_indicator_id(ip),
                                          attacker_ip_observable_id(ip), sensor, x,
                                          count=len(stamps))
        lk = self.store.lookup if lookup == "store" else lookup
        plan, self.last_stats, err = sighting_plan_for_window(
            self.state, ws, [o["id"] for o in objs], lk,
            platform_floors=scope["mode"] == "backfill")
        if err:
            self.last_stats["rejected"] = err
            return None
        b.sighting_replay = plan
        objs = b.finalize_sighting_counts(objs)
        self.state.record_sightings_sent(ws, we, b.sighting_sent_records, cycle_id="t")
        for i, o in enumerate(objs):
            if land(i, o):
                self.store.upsert(o)
        if clean:
            self.state.mark_window_counted(ws, we)
        return objs


@pytest.fixture
def fleet(cfg, tmp_path):
    return Fleet(cfg, tmp_path)


def _windows(start, n, step=timedelta(minutes=15)):
    return [(start + k * step, start + (k + 1) * step) for k in range(n)]


def test_clean_cycles_count_every_event_exactly_once(fleet):
    """Three days of 15-minute cycles, across midnight: stored == true."""
    for d in range(3):
        fleet.add("45.1.1.1", T0 + timedelta(days=d, minutes=3), 40, every=timedelta(minutes=2))
        fleet.add("45.2.2.2", T0 + timedelta(days=d, hours=1, minutes=50), 25)
    for ws, we in _windows(T0, 3 * 96):
        fleet.cycle(ws, we)
    assert fleet.stored("45.1.1.1") == fleet.truth("45.1.1.1") == 120
    assert fleet.stored("45.2.2.2") == fleet.truth("45.2.2.2") == 75


def test_without_es_counts_the_per_session_sum_is_also_exact(fleet):
    fleet.add("45.1.1.1", T0, 30, every=timedelta(minutes=1))
    for ws, we in _windows(T0, 4):
        fleet.cycle(ws, we, es_counts=False)
    assert fleet.stored("45.1.1.1") == 30


def test_a_repeated_cycle_does_not_inflate(fleet):
    """THE requirement: run a window again after it was published cleanly
    (an operator re-running it, or a cursor reset to its start)."""
    fleet.add("45.1.1.1", T0, 90, every=timedelta(seconds=20))
    wins = _windows(T0, 3)
    for ws, we in wins:
        fleet.cycle(ws, we)
    before = fleet.stored("45.1.1.1")
    assert before == 90
    for _ in range(3):
        sent = fleet.cycle(*wins[1])                       # the same window, again
        assert sent == [], "nothing new: the Sighting must not be sent at all"
        assert fleet.last_scope["mode"] == "none"
        assert fleet.stored("45.1.1.1") == before


def test_retry_after_a_partly_landed_publish_is_exact(fleet):
    """Publish not clean: the cursor stays, the next cycle covers the same
    start to a later end. One side landed, the other did not."""
    fleet.add("45.1.1.1", T0, 60, every=timedelta(seconds=20))      # 20 min
    (w1s, w1e), (w2s, w2e) = _windows(T0, 2)
    fleet.cycle(w1s, w1e)                                            # clean
    fleet.cycle(w2s, w2e, clean=False,
                land=lambda i, o: "indicator" in o["sighting_of_ref"])
    fleet.add("45.1.1.1", w2e + timedelta(minutes=1), 10)
    fleet.cycle(w2s, w2e + timedelta(minutes=15))                    # the retry
    assert fleet.stored("45.1.1.1") == fleet.truth("45.1.1.1") == 70
    assert fleet.last_stats["landed"] == 1 and fleet.last_stats["not_landed"] == 1


def test_retry_with_no_new_events_is_dropped_not_replaced(fleet):
    """A fully landed attempt whose publish was not clean for another
    reason, retried with nothing new: sending it again would be a
    non-widening write, i.e. a REPLACE of the total by a delta."""
    fleet.add("45.1.1.1", T0, 100, every=timedelta(seconds=5))
    (w1s, w1e), (w2s, w2e) = _windows(T0, 2)
    fleet.cycle(w1s, w1e)
    fleet.add("45.1.1.1", w2s + timedelta(minutes=1), 5)
    fleet.cycle(w2s, w2e, clean=False)          # lands, but "not clean"
    sent = fleet.cycle(w2s, w2e)                # retry: same events
    assert sent == []
    assert fleet.stored("45.1.1.1") == fleet.truth("45.1.1.1") == 105


def test_retry_when_the_lookup_fails_never_inflates(fleet):
    fleet.add("45.1.1.1", T0, 30, every=timedelta(seconds=20))
    (w1s, w1e), = _windows(T0, 1)
    fleet.cycle(w1s, w1e, clean=False)
    fleet.cycle(w1s, w1e, lookup=None)          # no platform answer: assume landed
    assert fleet.stored("45.1.1.1") == 30
    assert fleet.last_stats["assumed_landed"] == 2


def test_a_crashed_attempt_is_never_subtracted(fleet):
    """Codex: rows written before a publish that never happened must not
    count as published. Recorded, nothing lands, not clean; the retry finds
    nothing landed and counts it all; a later rewind over it counts nothing."""
    fleet.add("45.1.1.1", T0, 30, every=timedelta(seconds=20))
    (w1s, w1e), (w2s, w2e) = _windows(T0, 2)
    fleet.cycle(w1s, w1e, land=lambda i, o: False, clean=False)    # crash
    fleet.cycle(w1s, w1e)                                           # retry
    assert fleet.last_stats["not_landed"] == 2
    fleet.cycle(w2s, w2e)
    assert fleet.stored("45.1.1.1") == 30
    fleet.cycle(w1s, w2e)                                           # rewind over both
    assert fleet.last_scope["mode"] == "none" and fleet.stored("45.1.1.1") == 30


def test_a_cursor_rewind_over_published_windows_does_not_inflate(fleet):
    """Rewind to an earlier window boundary; one wide window re-reads
    published windows plus new events. Only the uncounted tail is counted,
    and last_seen is floored after the latest one ever written, so the
    write is still an ADD (a REPLACE here would collapse the total)."""
    fleet.add("45.1.1.1", T0, 120, every=timedelta(seconds=30))     # 60 min
    wins = _windows(T0, 4)
    for ws, we in wins:
        fleet.cycle(ws, we)
    assert fleet.stored("45.1.1.1") == 120
    fleet.add("45.1.1.1", wins[-1][1] + timedelta(minutes=2), 6)
    fleet.cycle(wins[1][0], wins[-1][1] + timedelta(minutes=15))    # rewind to window 2
    assert fleet.last_scope["mode"] == "backfill"
    assert fleet.stored("45.1.1.1") == fleet.truth("45.1.1.1") == 126


def test_a_rewind_off_a_window_boundary_is_exact(fleet):
    """Codex: a partial overlap used to double-count. The uncounted parts
    are computed from the counted intervals, not from whole ledger rows."""
    fleet.add("45.1.1.1", T0, 120, every=timedelta(seconds=30))
    for ws, we in _windows(T0, 4):
        fleet.cycle(ws, we)
    fleet.add("45.1.1.1", T0 + timedelta(minutes=62), 4, every=timedelta(minutes=1))
    fleet.cycle(T0 + timedelta(minutes=22, seconds=13), T0 + timedelta(minutes=75))
    assert fleet.last_scope["parts"] == [(T0 + timedelta(minutes=60), T0 + timedelta(minutes=75))]
    assert fleet.stored("45.1.1.1") == fleet.truth("45.1.1.1") == 124


def test_a_rewind_older_than_any_retention_is_exact(fleet):
    """Codex: rewinds beyond the 48 h row retention were silently absent.
    The counted intervals are kept for ever: a 3-day rewind counts nothing
    twice."""
    for d in range(4):
        fleet.add("45.1.1.1", T0 + timedelta(days=d, hours=2), 10, every=timedelta(minutes=5))
    for ws, we in _windows(T0, 4 * 24, step=timedelta(hours=1)):
        fleet.cycle(ws, we)
    assert fleet.stored("45.1.1.1") == 40
    fleet.cycle(T0 + timedelta(days=1), T0 + timedelta(days=4))
    assert fleet.last_scope["mode"] == "none"
    assert fleet.stored("45.1.1.1") == 40


def test_a_gap_backfill_counts_the_gap_with_platform_floors(fleet):
    """A window that was SKIPPED (cursor jumped) and is read later lies below
    the counted frontier: its events are counted once, and last_seen is
    floored after what OpenCTI stores (later than the gap), so it ADDS."""
    fleet.add("45.1.1.1", T0, 90, every=timedelta(seconds=30))       # 45 min
    w = _windows(T0, 3)
    fleet.cycle(*w[0])
    fleet.cycle(*w[2])                                               # w[1] skipped
    assert fleet.stored("45.1.1.1") == 60
    fleet.cycle(*w[1])                                               # the backfill
    assert fleet.last_scope["mode"] == "backfill"
    assert fleet.last_stats["platform_floors"] == 2
    assert fleet.stored("45.1.1.1") == 90


def test_a_backfill_without_platform_floors_writes_nothing(fleet):
    fleet.add("45.1.1.1", T0, 90, every=timedelta(seconds=30))
    w = _windows(T0, 3)
    fleet.cycle(*w[0]); fleet.cycle(*w[2])
    assert fleet.cycle(*w[1], lookup=None) is None
    assert "lookup unavailable" in fleet.last_stats["rejected"]
    assert fleet.stored("45.1.1.1") == 60


def test_an_unclean_attempt_then_a_moved_cursor_is_rejected(fleet):
    """Codex: unsupported rewinds are rejected explicitly: logged, nothing
    written. An unclean attempt over W2 is unresolved; a cycle over another
    window writes nothing until the cursor is set back to W2."""
    fleet.add("45.1.1.1", T0, 90, every=timedelta(seconds=30))
    w = _windows(T0, 3)
    fleet.cycle(*w[0])
    fleet.cycle(*w[1], clean=False, land=lambda i, o: i == 0)
    ids = [i for o in fleet.store.objects for i in o["ids"]]
    floors, unclean = fleet.state.max_last_sent(ids), fleet.state.unclean_sighting_windows()
    assert fleet.cycle(*w[2]) is None
    assert fleet.last_scope["mode"] == "reject"
    assert "set last_run back" in fleet.last_scope["reason"]
    assert fleet.state.max_last_sent(ids) == floors                 # nothing written
    assert fleet.state.unclean_sighting_windows() == unclean
    fleet.cycle(w[1][0], w[2][1])                                   # resolved
    assert fleet.stored("45.1.1.1") == fleet.truth("45.1.1.1") == 90


def test_every_write_widens_even_on_a_millisecond_tie(fleet):
    """An event stored at .968 ms of a window boundary, and this window's
    first event in the same millisecond: without the floor the write would
    not widen and would REPLACE."""
    ws = T0 + timedelta(microseconds=968_655)
    fleet.events.append(("45.1.1.1", SENSOR, ws - timedelta(microseconds=200)))
    fleet.cycle(ws - timedelta(minutes=15), ws)
    fleet.events.append(("45.1.1.1", SENSOR, ws + timedelta(microseconds=100)))
    fleet.cycle(ws, ws + timedelta(minutes=15))
    assert fleet.stored("45.1.1.1") == 2


def test_one_stored_object_per_target_and_sensor(fleet):
    """No day in the id: what OpenCTI keeps anyway, now without an alias a
    day. Two sensors stay two objects."""
    fleet.add("45.1.1.1", T0, 5, every=timedelta(hours=7))
    fleet.add("45.1.1.1", T0, 3, every=timedelta(hours=9), sensor="s2")
    for ws, we in _windows(T0, 4 * 24, step=timedelta(hours=1)):
        fleet.cycle(ws, we)
    assert fleet.stored("45.1.1.1") == 5 and fleet.stored("45.1.1.1", "s2") == 3
    assert all(len(o["ids"]) == 1 for o in fleet.store.objects)


# ---------------------------------------------------------------------------
# The stable-id migration (Codex blocker 1)
# ---------------------------------------------------------------------------

def _old_code_object(fleet, ip, first, last, count, sensor=SENSOR):
    """A Sighting the OLD code wrote: per-day id, 40+ days ago."""
    from tpot2cti.stix_ids import generate_sensor_id, generate_sighting_id
    for target, disc in ((attacker_ip_indicator_id(ip), ""),
                         (attacker_ip_observable_id(ip), "ipv4")):
        day_id = generate_sighting_id(sensor, f"{target}:{first:%Y-%m-%d}", disc)
        fleet.store.upsert(_sighting(day_id, first.isoformat(), last.isoformat(), count,
                                     target=target, where=generate_sensor_id(sensor)))


@pytest.mark.parametrize("migrated", [False, True])
def test_an_old_sighting_older_than_30_days_needs_the_stable_id_alias(fleet, migrated):
    """Codex: the stable id matches none of the old per-day ids, so when the
    stored object's first_seen is over 30 days old, OpenCTI's time match
    fails and the first new-code cycle creates a SECOND Sighting (confirmed
    live with throwaway objects, 2026-10-03). The migration adds the stable
    id as an alias of each pair's latest Sighting before that cycle; the
    write then matches by id and ADDS."""
    from tpot2cti.stix_ids import stable_sighting_id
    old = T0 - timedelta(days=40)
    _old_code_object(fleet, "45.1.1.1", old, old + timedelta(days=2), 100)
    if migrated:
        for o in fleet.store.objects:
            disc = "ipv4" if o["from"].startswith(("ipv4-addr", "ipv6-addr")) else ""
            o["ids"].add(stable_sighting_id(SENSOR, o["from"], disc))
    fleet.add("45.1.1.1", T0, 7, every=timedelta(minutes=1))
    fleet.cycle(T0, T0 + timedelta(minutes=15))
    from tpot2cti.stix_ids import generate_sensor_id
    sid = generate_sensor_id(SENSOR)
    objs = [o for o in fleet.store.objects
            if o["from"] == attacker_ip_indicator_id("45.1.1.1") and o["to"] == sid]
    if migrated:
        assert len(objs) == 1 and objs[0]["count"] == 107
    else:
        assert len(objs) == 2, "without the alias the new code mints a second Sighting"


def test_the_builder_sends_exactly_the_migrated_id(builder):
    from tpot2cti.stix_ids import stable_sighting_id
    ev = ParsedEvent(src_ip="45.1.1.1", timestamp=T0, sensor_hostname=SENSOR,
                     event_type="honeytrap", dst_port=445)
    x = AttackSession.from_event(ev)
    x.first_seen = x.last_seen = T0
    out = builder.build_dual_sighting(attacker_ip_indicator_id("45.1.1.1"),
                                      attacker_ip_observable_id("45.1.1.1"), SENSOR, x)
    assert [o["id"] for o in out] == [
        stable_sighting_id(SENSOR, attacker_ip_indicator_id("45.1.1.1"), ""),
        stable_sighting_id(SENSOR, attacker_ip_observable_id("45.1.1.1"), "ipv4")]


# ---------------------------------------------------------------------------
# The single-writer cycle lease (Codex blocker 2)
# ---------------------------------------------------------------------------

def test_the_lease_admits_one_writer(tmp_path):
    a = CycleState(db_path=tmp_path / "s.db")
    b = CycleState(db_path=tmp_path / "s.db")          # a second process
    assert a.acquire_lease("A", 60)
    assert not b.acquire_lease("B", 60)
    assert a.acquire_lease("A", 60), "re-entrant for its holder"
    assert a.renew_lease("A", 60) and not b.renew_lease("B", 60)
    assert a.lease_held("A") and not b.lease_held("B")
    a.release_lease("A")
    assert b.acquire_lease("B", 60)


def test_an_expired_lease_is_taken_over_and_the_old_holder_knows(tmp_path):
    a = CycleState(db_path=tmp_path / "s.db")
    b = CycleState(db_path=tmp_path / "s.db")
    t = datetime.now(timezone.utc)
    assert a.acquire_lease("A", 10, now=t)
    assert b.acquire_lease("B", 60, now=t + timedelta(seconds=11))
    assert not a.lease_held("A", now=t + timedelta(seconds=12))
    assert not a.renew_lease("A", 60)


def test_heartbeat_renews_the_lease(tmp_path):
    a = CycleState(db_path=tmp_path / "s.db")
    t = datetime.now(timezone.utc)
    assert a.acquire_lease("A", 5, now=t - timedelta(seconds=4))
    a.lease_holder, a.lease_ttl_s = "A", 600
    a.heartbeat()
    assert a.lease_held("A", now=t + timedelta(seconds=300))


def test_run_cycle_does_nothing_while_another_process_holds_the_lease(tmp_path):
    from tests import dr02_harness as H
    from tpot2cti.main import CycleLeaseHeld, run_cycle
    cfg = H.make_cfg({})
    docs, _ = H.load_cycle_docs()
    es = H.FakeES(docs, {})
    state = CycleState(db_path=tmp_path / "state.db")
    other = CycleState(db_path=tmp_path / "state.db")
    assert other.acquire_lease("other-process", 600)
    pub = H.CapturingPublisher()
    with pytest.raises(CycleLeaseHeld):
        run_cycle(cfg, state, es, lambda: H._fixed_builder(cfg), pub, now=H.FIXED_NOW)
    assert es.stream_patterns == [] and pub.objects == []
    assert state.get_last_run() is None and state.counted_intervals() == []
    other.release_lease("other-process")
    run_cycle(cfg, state, es, lambda: H._fixed_builder(cfg), pub, now=H.FIXED_NOW)
    assert pub.objects and state.get_last_run() is not None
    assert len(state.counted_intervals()) == 1, "a clean cycle marks its window counted"
    assert not other.lease_held("other-process") and other.acquire_lease("x", 1), \
        "run_cycle released the lease"


def test_run_cycle_rejects_while_an_unclean_attempt_is_unresolved(tmp_path, caplog):
    """End to end: an unclean attempt's 'sent' rows over another window make
    run_cycle write nothing: no publish, cursor kept, logged."""
    import logging
    from tests import dr02_harness as H
    from tpot2cti.main import run_cycle
    cfg = H.make_cfg({})
    docs, _ = H.load_cycle_docs()
    state = CycleState(db_path=tmp_path / "state.db")
    w0 = H.FIXED_NOW - timedelta(hours=3)
    state.record_sightings_sent(w0, w0 + timedelta(minutes=15),
                                {"sighting--x": (5, 0, w0.isoformat())})
    pub = H.CapturingPublisher()
    with caplog.at_level(logging.ERROR, logger="tpot2cti.main"):
        summary = run_cycle(cfg, state, H.FakeES(docs, {}), lambda: H._fixed_builder(cfg),
                            pub, now=H.FIXED_NOW)
    assert pub.objects == [] and summary["publish_ok"] is False
    assert state.get_last_run() is None
    assert "set last_run back" in summary["sightings"]["rejected"]
    assert any("REJECTED" in r.getMessage() for r in caplog.records)


def test_sighting_floor_is_strictly_after_at_millisecond_precision():
    t = datetime(2026, 10, 3, 12, 25, 50, 968_655, tzinfo=timezone.utc)
    f = sighting_floor(t)
    assert f == datetime(2026, 10, 3, 12, 25, 50, 969_000, tzinfo=timezone.utc)
    assert sighting_floor(t.replace(tzinfo=None)) == f


def test_es_counts_fold_across_days():
    by_day = {("a", "s", "2026-09-20"): 3, ("a", "s", "2026-09-21"): 4,
              ("b", "s", "2026-09-21"): 1, ("bad",): 9, ("c", "s", "x"): "no"}
    assert fold_window_counts(by_day) == {("a", "s"): 7, ("b", "s"): 1}


def test_window_counts_beat_the_per_session_sum_and_are_not_summed(builder):
    """ES's window count covers every type; every session of the address
    carries the same window total, so the fold takes MAX, not SUM."""
    builder.window_event_counts = {("45.1.1.1", SENSOR): 500}
    def s(at, sid):
        ev = ParsedEvent(src_ip="45.1.1.1", timestamp=at, sensor_hostname=SENSOR,
                         event_type="honeytrap", dst_port=445)
        x = AttackSession.from_event(ev)
        x.first_seen, x.last_seen, x.session_id = at, at, sid
        return x
    kept = builder.build_sighting(attacker_ip_indicator_id("45.1.1.1"), SENSOR,
                                  s(T0, "a"), count=10)
    builder.build_sighting(attacker_ip_indicator_id("45.1.1.1"), SENSOR,
                           s(T0 + timedelta(minutes=5), "b"), count=10)
    assert kept["count"] == 500


def test_the_count_query_is_bounded_by_the_uncounted_parts_of_the_window():
    """Upper bound window_end (never claim unread events); the ranges are the
    window's UNCOUNTED parts (a delta), never the day's running total."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(root, "tpot2cti", "main.py")).read()
    i = src.index("builder.window_event_counts = fold_parts_counts(")
    call = src[i:i + 160]
    assert 'sighting_scope["parts"]' in call
    assert "_day_start" not in call and "now" not in call
    j = src.index("sighting_scope = sighting_count_scope(")
    assert "window_start, window_end" in src[j:j + 90]


def test_the_es_method_is_actually_a_method_on_the_client():
    """The producer, not just the consumer (it once landed inside the
    module's __main__ block and every cycle silently fell back)."""
    import inspect
    from tpot2cti.es_client import TpotESClient
    assert callable(getattr(TpotESClient, "daily_event_counts", None))
    params = inspect.signature(TpotESClient.daily_event_counts).parameters
    assert {"day_start", "upper", "index_pattern", "ignore_types"} <= set(params)


def test_only_sightings_changed_from_the_parent_commit(tmp_path):
    """The golden rebaseline of 2026-10-03 changed Sightings only: every
    other object of both harness bundles is byte-identical to origin/main
    2d23cb7 (digests taken there, with Sightings removed)."""
    from tests import dr02_harness as H
    rb = [r for r in H.golden_original()["rebaselines"] if "minus_sightings" in r][-1]
    objs, *_ = H.cycle_bundle(tmp_path)
    d_objs, _ = H.direct_bundle()
    strip = lambda L: [o for o in L if o["type"] != "sighting"]
    assert H.digest(strip(objs)) == rb["minus_sightings"]["cycle"]
    assert H.digest(strip(d_objs)) == rb["minus_sightings"]["direct"]
