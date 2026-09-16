"""Sightings aggregate per (sensor, target, UTC day) — not per session.

Seeding the Sighting id on ``session_id`` minted one Sighting per session
(two, under the dual-sighting pattern). Measured on v2 cycle 92: **21,628
sightings from 613 addresses in a single 15-minute window** — roughly one
per parsed event, 80% of every object emitted, and the reason the
relationships pass ran 13.7h without completing.

v1 learned the same lesson expensively: a microsecond-resolution
``first_seen`` in its sighting seed caused an id alias explosion that cost
758 GB of history. It day-buckets now.

The trap this file mostly guards is what day-bucketing does to ``_dedup``.
Colliding ids are the POINT here, but ``_dedup`` answers a repeat id with
None and only widens *relationships* — so without a sighting-aware merge
the second and every later session of the day would be dropped outright,
and the published Sighting would assert that one session's count and
window were the whole day's. Aggregation that silently discards its inputs
is worse than no aggregation: the object looks authoritative and is wrong.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tpot2cti.parsers.base import AttackSession, ParsedEvent
from tpot2cti.stix_ids import attacker_ip_indicator_id, attacker_ip_observable_id

IP_A = "203.0.113.10"
IP_B = "198.51.100.20"
DAY = datetime(2026, 8, 26, 4, 0, tzinfo=timezone.utc)


def _session(*, ip=IP_A, at=DAY, sensor="s1", session_id=None, span=timedelta(minutes=5)):
    ev = ParsedEvent(
        src_ip=ip, timestamp=at, sensor_hostname=sensor, event_type="honeytrap",
        dst_port=445, src_country_code="DE", src_asn=64512,
    )
    s = AttackSession.from_event(ev)
    s.first_seen = at
    s.last_seen = at + span
    if session_id is not None:
        s.session_id = session_id
    return s


def _emit(builder, session, *, count=1, description=None):
    """Emit the Indicator-side sighting for one session."""
    return builder.build_sighting(
        attacker_ip_indicator_id(session.src_ip),
        session.sensor_hostname, session, count=count, description=description,
    )


# ---------------------------------------------------------------------------
# Bucketing
# ---------------------------------------------------------------------------

def test_two_sessions_same_day_collapse_to_one_sighting(builder):
    """The headline behaviour: same address, same sensor, same day -> one id."""
    a = _emit(builder, _session(at=DAY, session_id="s-a"))
    b = _emit(builder, _session(at=DAY + timedelta(hours=6), session_id="s-b"))

    assert a is not None, "guard: the first session must actually emit"
    assert b is None, (
        "the second session of the day must fold into the first, not emit a "
        "second Sighting — that is the 21,628-objects-per-window defect"
    )


def test_sessions_on_different_days_stay_separate(builder):
    """Aggregation must not swallow a genuinely different day."""
    a = _emit(builder, _session(at=DAY, session_id="s-a"))
    b = _emit(builder, _session(at=DAY + timedelta(days=1), session_id="s-b"))

    assert a is not None and b is not None
    assert a["id"] != b["id"], "one Sighting per DAY, not one forever"


def test_different_addresses_stay_separate(builder):
    a = _emit(builder, _session(ip=IP_A, session_id="s-a"))
    b = _emit(builder, _session(ip=IP_B, session_id="s-b"))
    assert a is not None and b is not None
    assert a["id"] != b["id"]


def test_different_sensors_stay_separate(builder):
    """The sensor is part of the bucket: two sensors seeing one address is
    two observations, and collapsing them would erase the fleet-wide view."""
    a = _emit(builder, _session(sensor="s1", session_id="s-a"))
    b = _emit(builder, _session(sensor="s2", session_id="s-b"))
    assert a is not None and b is not None
    assert a["id"] != b["id"]


def test_day_boundary_is_utc_not_local(builder):
    """23:59Z and 00:01Z are different days even though they are 2 min apart."""
    late = _emit(builder, _session(
        at=datetime(2026, 8, 26, 23, 59, tzinfo=timezone.utc), session_id="s-a"))
    early = _emit(builder, _session(
        at=datetime(2026, 8, 27, 0, 1, tzinfo=timezone.utc), session_id="s-b"))
    assert late is not None and early is not None
    assert late["id"] != early["id"]


# ---------------------------------------------------------------------------
# The merge: what the surviving object must say
# ---------------------------------------------------------------------------

def test_count_sums_across_the_days_sessions(builder):
    """A folded session must add to the count, not vanish from it."""
    kept = _emit(builder, _session(at=DAY, session_id="s-a"), count=3)
    _emit(builder, _session(at=DAY + timedelta(hours=2), session_id="s-b"), count=5)
    _emit(builder, _session(at=DAY + timedelta(hours=4), session_id="s-c"), count=7)

    assert kept["count"] == 15, (
        f"count must total the day (3+5+7), got {kept['count']} — a dropped "
        "session under-reports exactly the busiest addresses"
    )


def test_count_does_not_double_when_one_session_emits_twice(builder):
    """Summing is per DISTINCT session.

    Several builders call build_dual_sighting more than once for a session.
    Under session-seeded ids those repeats collided and were dropped, so a
    naive sum would silently inflate the count the day this changed.
    """
    kept = _emit(builder, _session(session_id="s-a"), count=4)
    _emit(builder, _session(session_id="s-a"), count=4)
    _emit(builder, _session(session_id="s-a"), count=4)

    assert kept["count"] == 4, (
        f"one session counted three times, got {kept['count']}"
    )


def test_window_spans_the_whole_day(builder):
    """first_seen earliest, last_seen latest — across every folded session."""
    first = _session(at=DAY + timedelta(hours=6), session_id="s-a")
    kept = _emit(builder, first)
    _emit(builder, _session(at=DAY, session_id="s-b"))                   # earlier
    # +14h, deliberately NOT +20h: DAY is 04:00Z, so +20h lands on the
    # NEXT UTC day and would open its own bucket rather than fold.
    _emit(builder, _session(at=DAY + timedelta(hours=14), session_id="s-c"))  # later

    assert kept["first_seen"] == DAY.isoformat(), (
        "a later-arriving EARLIER session must move first_seen back"
    )
    assert kept["last_seen"] == (
        DAY + timedelta(hours=14, minutes=5)).isoformat(), (
        "the window must reach the last observation of the day"
    )


def test_window_comparison_is_chronological_not_lexicographic(builder):
    """The offset trap _as_dt exists for.

    "…T09:00+02:00" is 07:00Z — EARLIER than "…T08:30+00:00" — but sorts
    after it as a string. Comparing raw strings would keep the wrong bound.
    """
    base = _session(at=datetime(2026, 8, 26, 8, 30, tzinfo=timezone.utc),
                    session_id="s-a", span=timedelta(0))
    kept = _emit(builder, base)

    earlier = _session(session_id="s-b", span=timedelta(0))
    earlier.first_seen = datetime(
        2026, 8, 26, 9, 0, tzinfo=timezone(timedelta(hours=2)))  # == 07:00Z
    earlier.last_seen = earlier.first_seen
    _emit(builder, earlier)

    from tpot2cti.stix.builder import STIXBuilder
    got = STIXBuilder._as_dt(kept["first_seen"])
    assert got == datetime(2026, 8, 26, 7, 0, tzinfo=timezone.utc), (
        f"first_seen must be the chronologically earliest (07:00Z), got {got}"
    )


# ---------------------------------------------------------------------------
# Descriptions — the LESSONS §7.1 channel
# ---------------------------------------------------------------------------

def test_folded_sessions_keep_their_descriptions(builder):
    """Sighting.description is where low-signal protocols put their per-session
    summary instead of spewing Notes. Last-write-wins would throw the day's
    other summaries away, which is data loss dressed as deduplication."""
    kept = _emit(builder, _session(session_id="s-a"), description="probe of 445")
    _emit(builder, _session(session_id="s-b"), description="probe of 3389")

    assert "probe of 445" in kept["description"]
    assert "probe of 3389" in kept["description"], (
        "the folded session's summary must survive the merge"
    )


def test_description_list_is_bounded(builder):
    """Unbounded concatenation would put a day of a flood source's summaries
    into one field. Cap the listing and say how many were omitted."""
    kept = _emit(builder, _session(session_id="s-0"), description="line 0")
    for n in range(1, 12):
        _emit(builder, _session(session_id=f"s-{n}"), description=f"line {n}")

    lines = kept["description"].splitlines()
    assert len(lines) == builder._SIGHTING_DESC_MAX + 1, (
        f"expected {builder._SIGHTING_DESC_MAX} lines + a remainder note, "
        f"got {len(lines)}"
    )
    assert "(+7 further session(s) this day)" in kept["description"], (
        f"the omitted count must be stated, got: {kept['description']!r}"
    )


def test_identical_descriptions_are_not_repeated(builder):
    kept = _emit(builder, _session(session_id="s-a"), description="same text")
    _emit(builder, _session(session_id="s-b"), description="same text")
    assert kept["description"] == "same text"


# ---------------------------------------------------------------------------
# Publisher-side second line of defence
# ---------------------------------------------------------------------------

def test_publisher_merges_sightings_with_max_not_sum():
    """Two copies of one ALREADY-AGGREGATED sighting are the same observations
    twice. Summing them would invent activity; max keeps the fuller one."""
    from tpot2cti.publisher import Publisher

    sighting = {
        "type": "sighting", "id": "sighting--1", "sighting_of_ref": "indicator--1",
        "count": 10, "first_seen": "2026-08-26T06:00:00+00:00",
        "last_seen": "2026-08-26T10:00:00+00:00",
    }
    dupe = dict(sighting, count=10,
                first_seen="2026-08-26T04:00:00+00:00",
                last_seen="2026-08-26T20:00:00+00:00")

    # __new__ without __init__: the merge is pure, and building a real
    # Publisher would demand an OpenCTI connection this test does not need.
    pub = Publisher.__new__(Publisher)
    out = pub._dedup_label_union([sighting, dupe])
    merged = [o for o in out if o["id"] == "sighting--1"]
    assert len(merged) == 1
    assert merged[0]["count"] == 10, (
        f"max, not sum — got {merged[0]['count']}, which would double the day"
    )
    assert merged[0]["first_seen"] == "2026-08-26T04:00:00+00:00"
    assert merged[0]["last_seen"] == "2026-08-26T20:00:00+00:00"


def test_publisher_sighting_window_is_chronological():
    """Same offset trap, on the publisher side."""
    from tpot2cti.publisher import Publisher

    a = {"type": "sighting", "id": "sighting--2", "count": 1,
         "first_seen": "2026-08-26T08:30:00+00:00",
         "last_seen": "2026-08-26T08:30:00+00:00"}
    b = dict(a, first_seen="2026-08-26T09:00:00+02:00",   # == 07:00Z, earlier
             last_seen="2026-08-26T09:00:00+02:00")

    pub = Publisher.__new__(Publisher)
    out = pub._dedup_label_union([a, b])
    merged = [o for o in out if o["id"] == "sighting--2"][0]
    assert merged["first_seen"] == "2026-08-26T09:00:00+02:00", (
        "07:00Z is earlier than 08:30Z despite sorting later as a string; "
        f"got {merged['first_seen']}"
    )


# ---------------------------------------------------------------------------
# The reduction this whole change exists for
# ---------------------------------------------------------------------------

def test_a_day_of_sessions_yields_one_sighting_per_side(builder):
    """End-to-end via the dual pattern: 50 sessions -> 2 Sightings, not 100."""
    emitted = []
    for n in range(50):
        s = _session(at=DAY + timedelta(minutes=n * 10), session_id=f"s-{n}")
        emitted.extend(builder.build_dual_sighting(
            attacker_ip_indicator_id(s.src_ip),
            attacker_ip_observable_id(s.src_ip),
            s.sensor_hostname, s, count=1,
        ))

    sightings = [o for o in emitted if o.get("type") == "sighting"]
    assert len(sightings) == 2, (
        f"expected 2 (Indicator side + Observable side), got {len(sightings)}"
    )
    assert {o["count"] for o in sightings} == {50}, (
        "both sides must carry the day's full count"
    )
