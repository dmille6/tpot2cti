"""A gap must be walked, not skipped.

`_compute_window` capped over-long windows by returning `[now-24h, now)`.
That is not a catch-up — it jumps to the present, and because the cursor
advances to `window_end` on success, everything between `last_run` and
`now-24h` is skipped permanently and silently.

Measured cost of the live instance of this: the 2026-07-19 outage left
80,260,536 documents unread across 17 daily indices, and the recovery the
CHANGELOG documents ("manual cursor rewind") could not work either, because
rewinding `last_run` re-triggered the same jump on the very next cycle.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tpot2cti.main import _compute_window


class _State:
    """Minimal CycleState stand-in — _compute_window only reads last_run."""

    def __init__(self, last_run):
        self._last_run = last_run

    def get_last_run(self):
        return self._last_run


class _Cycle:
    initial_lookback_hours = 0


class _Cfg:
    cycle = _Cycle()


NOW = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)


def test_a_long_gap_is_walked_from_the_cursor_not_from_now():
    """The regression lock. A 16.5-day-old cursor must produce a window that
    STARTS at the cursor, so the gap is covered rather than jumped."""
    last_run = NOW - timedelta(days=16, hours=12)
    start, end = _compute_window(_State(last_run), _Cfg(), NOW)

    assert start == last_run, (
        "the window no longer starts at the cursor — the gap is being "
        "skipped, which is how 80.2M documents went unread"
    )
    assert end == last_run + timedelta(hours=24)
    assert end < NOW, "a catch-up window must land in the past"


def test_the_cap_still_bounds_the_pull():
    """The cap exists so a week-long outage does not pull a week of events
    into one cycle. Walking the gap must not remove that protection."""
    last_run = NOW - timedelta(days=30)
    start, end = _compute_window(_State(last_run), _Cfg(), NOW)
    assert end - start == timedelta(hours=24)


def test_repeated_cycles_converge_on_now():
    """Catch-up must actually terminate. Simulate the cursor advancing to
    window_end each cycle, as run_cycle does on publish success."""
    cursor = NOW - timedelta(days=5)
    steps = 0
    while True:
        start, end = _compute_window(_State(cursor), _Cfg(), NOW)
        assert start == cursor
        cursor = end                     # what set_last_run(window_end) does
        steps += 1
        if end == NOW:
            break
        assert steps < 20, "catch-up is not converging"
    # Exactly 5 × 24h lands on NOW: the 5th call sees `now - last_run == cap`,
    # which is not `> cap`, so it returns the final [last_run, now) window.
    assert steps == 5, f"5 days should take 5 steps of 24h, got {steps}"


def test_no_window_is_ever_skipped_while_catching_up():
    """The property that matters: consecutive windows must abut exactly, so
    no interval is left uncovered."""
    cursor = NOW - timedelta(days=4)
    windows = []
    while True:
        start, end = _compute_window(_State(cursor), _Cfg(), NOW)
        windows.append((start, end))
        cursor = end
        if end == NOW:
            break
    for (_, prev_end), (next_start, _) in zip(windows, windows[1:]):
        assert prev_end == next_start, f"gap between {prev_end} and {next_start}"
    assert windows[0][0] == NOW - timedelta(days=4)
    assert windows[-1][1] == NOW


def test_a_normal_window_is_untouched():
    """The common path — cursor inside the cap — must keep running to now."""
    last_run = NOW - timedelta(hours=2)
    assert _compute_window(_State(last_run), _Cfg(), NOW) == (last_run, NOW)


def test_a_naive_cursor_is_treated_as_utc():
    naive = (NOW - timedelta(days=3)).replace(tzinfo=None)
    start, end = _compute_window(_State(naive), _Cfg(), NOW)
    assert start.tzinfo is not None and end.tzinfo is not None
    assert end - start == timedelta(hours=24)
