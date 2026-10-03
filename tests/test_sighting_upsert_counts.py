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

from tpot2cti.main import fold_window_counts, sighting_replay_for_window
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
    """Events, cycles and a publish into the model; the cursor is explicit."""

    def __init__(self, cfg, tmp_path):
        self.cfg = cfg
        self.state = CycleState(db_path=tmp_path / "state.db")
        self.store = OpenCTISightings()
        self.events: list[tuple[str, str, datetime]] = []   # (ip, sensor, ts)
        self.seq = 0

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

    def cycle(self, ws, we, *, land=lambda i, obj: True, lookup="store",
              es_counts=True):
        """Build, ledger, finalize, record, publish (subject to ``land``).
        Returns the sightings sent."""
        b = STIXBuilder(self.cfg)
        b.window_start = ws
        inwin = [e for e in self.events if ws <= e[2] < we]
        if es_counts:
            by_day: dict = {}
            for ip, sensor, ts in inwin:
                k = (ip, sensor, ts.strftime("%Y-%m-%d"))
                by_day[k] = by_day.get(k, 0) + 1
            b.window_event_counts = fold_window_counts(by_day)
        objs: list[dict] = []
        groups: dict = {}
        for ip, sensor, ts in inwin:
            groups.setdefault((ip, sensor), []).append(ts)
        for (ip, sensor), stamps in sorted(groups.items()):
            self.seq += 1
            ev = ParsedEvent(src_ip=ip, timestamp=min(stamps), sensor_hostname=sensor,
                             event_type="honeytrap", dst_port=445)
            s = AttackSession.from_event(ev)
            s.first_seen, s.last_seen = min(stamps), max(stamps)
            s.session_id = f"sess-{self.seq}"
            objs += b.build_dual_sighting(attacker_ip_indicator_id(ip),
                                          attacker_ip_observable_id(ip), sensor, s,
                                          count=len(stamps))
        ids = [o["id"] for o in objs]
        lk = self.store.lookup if lookup == "store" else lookup
        b.sighting_replay, self.last_stats = sighting_replay_for_window(
            self.state, ws, we, ids, lk)
        objs = b.finalize_sighting_counts(objs)
        self.state.record_sightings_sent(ws, we, b.sighting_sent_records, cycle_id="t")
        for i, o in enumerate(objs):
            if land(i, o):
                self.store.upsert(o)
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
        assert fleet.stored("45.1.1.1") == before
    assert fleet.last_stats["retried_sightings"] == 2 and fleet.last_stats["landed"] == 2


def test_retry_after_a_partly_landed_publish_is_exact(fleet):
    """Publish not clean: the cursor stays, the next cycle covers the same
    start to a later end. One side landed, the other did not."""
    fleet.add("45.1.1.1", T0, 60, every=timedelta(seconds=20))      # 20 min
    (w1s, w1e), (w2s, w2e) = _windows(T0, 2)
    fleet.cycle(w1s, w1e)                                            # clean
    fleet.cycle(w2s, w2e, land=lambda i, o: "indicator" in o["sighting_of_ref"])
    # cursor kept at w2s; the retry window also covers new events
    fleet.add("45.1.1.1", w2e + timedelta(minutes=1), 10)
    fleet.cycle(w2s, w2e + timedelta(minutes=15))
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
    fleet.cycle(w2s, w2e)                       # lands, but "not clean"
    sent = fleet.cycle(w2s, w2e)                # retry: same events
    assert sent == []
    assert fleet.stored("45.1.1.1") == fleet.truth("45.1.1.1") == 105


def test_retry_when_the_lookup_fails_never_inflates(fleet):
    fleet.add("45.1.1.1", T0, 30, every=timedelta(seconds=20))
    (w1s, w1e), = _windows(T0, 1)
    fleet.cycle(w1s, w1e)
    fleet.cycle(w1s, w1e, lookup=None)          # no platform answer: assume landed
    assert fleet.stored("45.1.1.1") == 30
    assert fleet.last_stats["assumed_landed"] == 2


def test_a_cursor_rewind_over_published_windows_does_not_inflate(fleet):
    """Rewind to an earlier window boundary; one wide window re-reads
    windows that were already published. Their totals are subtracted and
    last_seen is floored after the latest one ever written, so the write
    is still an ADD (a REPLACE here would collapse the total)."""
    fleet.add("45.1.1.1", T0, 120, every=timedelta(seconds=30))     # 60 min
    wins = _windows(T0, 4)
    for ws, we in wins:
        fleet.cycle(ws, we)
    assert fleet.stored("45.1.1.1") == 120
    fleet.add("45.1.1.1", wins[-1][1] + timedelta(minutes=2), 6)
    fleet.cycle(wins[1][0], wins[-1][1] + timedelta(minutes=15))    # rewind to window 2
    assert fleet.stored("45.1.1.1") == fleet.truth("45.1.1.1") == 126
    assert fleet.last_stats["partial_overlap"] == 0


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


def test_the_count_query_is_bounded_by_the_window_not_the_clock_or_day():
    """Upper bound window_end (never claim unread events); lower bound
    window_start (a DELTA, not the day's running total)."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(root, "tpot2cti", "main.py")).read()
    i = src.index("_by_day = es.daily_event_counts(")
    call = src[i:i + 120]
    assert "window_start, window_end" in call
    assert "_day_start" not in call and "now" not in call


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
