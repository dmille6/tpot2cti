"""A cycle must be bounded by VOLUME, and must never advance past unread data.

The existing 24h time cap does not bound memory: density is not constant, so
a 16.3h window -- comfortably under the cap -- was 2.24M events and 13 GiB
RSS. The whole window is materialised (parsed events, then sessions, then
STIX objects, all live at once), and the predecessor system hit this exact
wall and exhausted a 4 GB limit.

The dangerous half is not the cap, it is where the cursor stops. This
pipeline's worst recorded failure was a window computation that jumped to
the present instead of walking forward, leaving 80,260,536 documents
permanently unread in the 2026-07-19 outage -- and a manual cursor rewind
could not recover them, because the rewind re-triggered the same jump.

So the invariant these tests hold is asymmetric, and deliberately so:

    RE-READING a window is free   -- ids are deterministic UUID5 and the
                                     publisher keeps max(score) with label
                                     union, so replay converges.
    SKIPPING a window is fatal    -- nothing downstream can tell it happened.

Every choice below resolves in favour of overlap.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone

MAIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "tpot2cti", "main.py")


def _src() -> str:
    return open(MAIN).read()


def test_doc_timestamp_returns_aware_utc_or_none():
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tpot2cti.main import _doc_timestamp

    assert _doc_timestamp({"@timestamp": "2026-08-11T03:32:57.184Z"}) == \
        datetime(2026, 8, 11, 3, 32, 57, 184000, tzinfo=timezone.utc)
    # naive input is read as UTC, matching the rest of the pipeline
    assert _doc_timestamp({"@timestamp": "2026-08-11T03:32:57"}).tzinfo is not None
    # offset-bearing input is normalised, not left to sort lexicographically
    assert _doc_timestamp({"@timestamp": "2026-08-11T05:32:57+02:00"}) == \
        datetime(2026, 8, 11, 3, 32, 57, tzinfo=timezone.utc)


def test_unparseable_timestamp_never_moves_the_cursor():
    """A guess here is how 80M documents went unread."""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tpot2cti.main import _doc_timestamp

    for bad in ({}, {"@timestamp": ""}, {"@timestamp": "not-a-date"},
                {"@timestamp": None}):
        assert _doc_timestamp(bad) is None, f"{bad!r} must not yield a timestamp"

    src = _src()
    i = src.index("if _max_events and events_read >= _max_events:")
    body = src[i:i + 1400]
    assert "if _ts is None:" in body and "pass" in body, (
        "an unparseable timestamp must fall through to 'keep reading', never "
        "to a cursor advance"
    )


def test_the_cap_excludes_its_boundary_rather_than_draining_it():
    """The rule both models named: never ADVANCE past a split timestamp.

    The ES range is half-open [start, end) (`gte`/`lt`), so setting
    window_end to the tripping event's own timestamp excludes that entire
    instant from this cycle. The next cycle re-covers it from `gte`. Events
    sharing that millisecond therefore cannot be skipped, whether we read
    some of them or none.
    """
    src = _src()
    i = src.index("if _max_events and events_read >= _max_events:")
    body = src[i:i + 1800]
    assert "_capped_end = _ts" in body, (
        "the truncated window must end at the TRIPPING event's timestamp, "
        "not at the clock and not at ts+1"
    )
    assert not re.search(r"_capped_end\s*=\s*_ts\s*\+", body), (
        "advancing past the boundary would skip the rest of that instant"
    )


def test_a_zero_width_window_is_impossible():
    """The flood case: more events in one instant than the cap allows.

    Stopping at the tripping timestamp would make window_end == window_start,
    the cycle would cover nothing, and the cursor would never move again --
    a silent, permanent stall. Overshooting the cap is survivable; that is
    the trade taken.
    """
    src = _src()
    i = src.index("if _max_events and events_read >= _max_events:")
    body = src[i:i + 1800]
    assert "elif _ts <= window_start:" in body, (
        "no guard against the cap tripping inside the window's first instant"
    )
    j = body.index("elif _ts <= window_start:")
    branch = body[j:j + 700]
    assert "logger.error" in branch, "a flood-sized instant must be loud"
    assert "_capped_end" not in branch, (
        "the degenerate branch must NOT set a capped end — that is the "
        "zero-width window it exists to prevent"
    )


def test_the_capped_end_actually_reaches_the_cursor():
    """A cap that truncates the read but not the cursor is worse than none.

    It would mean the cursor advanced over events the cycle never read —
    precisely the 2026-07-19 failure, reintroduced by a memory fix.
    """
    src = _src()
    assert "if _capped_end is not None:" in src
    i = src.index("if _capped_end is not None:")
    assert "window_end = _capped_end" in src[i:i + 200]
    # and it must happen BEFORE the cursor is written. rindex, not index:
    # the module docstring also lists "7. state.set_last_run(window_end)",
    # and matching that instead of the real call made this test pass on
    # ordering it had never actually checked.
    assert i < src.rindex("state.set_last_run(window_end)"), (
        "window_end is reassigned after the cursor is written — the cap "
        "would have no effect on what gets marked as read"
    )


def test_cap_is_configurable_and_disablable():
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tpot2cti.config import CycleConfig

    assert CycleConfig().max_events_per_cycle == 400_000
    src = open(os.path.join(os.path.dirname(MAIN), "config.py")).read()
    assert "TPOT2CTI_MAX_EVENTS_PER_CYCLE" in src
    # `0 disables` must be honoured by the guard, not just documented
    assert "if _max_events and events_read >= _max_events:" in _src(), (
        "a falsy cap must skip the check entirely"
    )
