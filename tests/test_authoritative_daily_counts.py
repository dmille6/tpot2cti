"""A day's Sighting count must not be clobbered by a narrower later cycle.

OpenCTI REPLACES a Sighting's `count` on upsert; it does not sum. That was
measured, not assumed. Sighting--261af9e4… on day 2026-08-26 read 22,119
after cycle 94 (a 16.3h window), then read 3,484 after cycle 95 re-covered
only 2.6h of the same day. The published number went DOWN by 6x.

That makes a per-cycle count worse than incomplete: it overwrites a fuller
number with a smaller one, and the volume cap makes it more frequent by
design, because bounding memory means more, smaller windows per day.

The fix writes the day's own total, taken from ES, which is idempotent
under replace — it only grows as the day fills, so whichever cycle writes
last is also the one holding the most complete number.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from tpot2cti.parsers.base import AttackSession, ParsedEvent
from tpot2cti.stix_ids import attacker_ip_indicator_id

IP = "203.0.113.77"
SENSOR = "s1"
DAY = datetime(2026, 8, 26, 4, 0, tzinfo=timezone.utc)


def _session(at=DAY, sid="s-a"):
    ev = ParsedEvent(src_ip=IP, timestamp=at, sensor_hostname=SENSOR,
                     event_type="honeytrap", dst_port=445,
                     src_country_code="DE", src_asn=64512)
    s = AttackSession.from_event(ev)
    s.first_seen, s.last_seen = at, at + timedelta(minutes=5)
    s.session_id = sid
    return s


def _emit(builder, session, count=1):
    return builder.build_sighting(attacker_ip_indicator_id(session.src_ip),
                                  SENSOR, session, count=count)


def test_authoritative_day_total_overrides_the_cycle_slice(builder):
    builder.daily_event_counts = {(IP, SENSOR, "2026-08-26"): 22119}
    got = _emit(builder, _session(), count=3484)
    assert got["count"] == 22119, (
        f"the cycle's slice ({3484}) was published instead of the day's "
        f"total; a narrower later cycle would clobber the fuller one"
    )


def test_authoritative_counts_are_not_summed_across_sessions(builder):
    """Every session of the day carries the SAME day total.

    Summing them — which is correct for per-cycle counts — would multiply
    the day's total by the number of sessions in it.
    """
    builder.daily_event_counts = {(IP, SENSOR, "2026-08-26"): 500}
    kept = _emit(builder, _session(sid="s-a"), count=10)
    _emit(builder, _session(at=DAY + timedelta(hours=2), sid="s-b"), count=10)
    _emit(builder, _session(at=DAY + timedelta(hours=4), sid="s-c"), count=10)
    assert kept["count"] == 500, (
        f"expected the day total 500, got {kept['count']} — three sessions "
        "each carrying the day total were summed into 1500"
    )


def test_per_cycle_counts_still_sum_when_no_authoritative_value(builder):
    """The fallback path must keep its old, correct behaviour."""
    builder.daily_event_counts = {}
    kept = _emit(builder, _session(sid="s-a"), count=3)
    _emit(builder, _session(at=DAY + timedelta(hours=1), sid="s-b"), count=5)
    assert kept["count"] == 8


def test_a_missing_pair_falls_back_rather_than_zeroing(builder):
    """A partial map (page cap, agg failure) must not publish count=0."""
    builder.daily_event_counts = {("198.51.100.1", SENSOR, "2026-08-26"): 999}
    got = _emit(builder, _session(), count=42)
    assert got["count"] == 42, (
        "an address absent from the map must keep its per-cycle count, not "
        "inherit someone else's or collapse to zero"
    )


def test_the_upper_bound_is_the_window_not_the_clock():
    """The count must never claim events the connector has not imported."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(root, "tpot2cti", "main.py")).read()
    i = src.index("builder.daily_event_counts = es.daily_event_counts(")
    call = src[i:i + 200]
    assert "window_end" in call, (
        "the aggregation's upper bound must be window_end; using the wall "
        "clock would count events this cycle never read"
    )
    assert "now" not in call.split(")")[0]


def test_the_es_method_is_actually_a_method_on_the_client():
    """The producer, not just the consumer.

    Every other test in this file sets `builder.daily_event_counts` by hand,
    so they all passed while the ES method that POPULATES it was not a method
    at all: it had been appended to the end of es_client.py and landed inside
    `if __name__ == "__main__":` as a nested function. Valid syntax, imported
    cleanly, and silently absent from the class.

    Production degraded rather than broke -- the call is wrapped and logged
    "daily count aggregation failed (TpotESClient object has no attribute
    daily_event_counts)", then fell back to per-cycle counts. Which is the
    designed behaviour, and also exactly why nothing failed loudly enough to
    notice. A test that only exercises the consumer cannot see this.
    """
    from tpot2cti.es_client import TpotESClient

    assert hasattr(TpotESClient, "daily_event_counts"), (
        "daily_event_counts is not a method on TpotESClient — check it did "
        "not land inside the __main__ smoke-test block"
    )
    assert callable(TpotESClient.daily_event_counts)

    import inspect
    params = inspect.signature(TpotESClient.daily_event_counts).parameters
    assert "self" in params, "must be an instance method, not a bare function"
    for expected in ("day_start", "upper", "ignore_types"):
        assert expected in params, f"missing parameter {expected}"
