"""A health check that can never be green is as useless as one never red.

The no-success ceiling exists for a real failure: between 2026-07-19 and
08-04, every cycle STARTED (bumping the heartbeat) and failed at publish,
so a plain `cycle_fresh OR heartbeat_fresh` rule stayed green for 16 days.
The ceiling closed that.

But it was derived from the POLL INTERVAL alone, which condemns any
connector whose cycle legitimately runs longer than its own interval. The
backfill instance polls at PT1M -- deliberately, so it starts the next 24h
day-step immediately -- while a day-step measures ~2,895s. Its ceiling was
180s. It reported `cycling-no-success` continuously while succeeding every
48 minutes.

That matters beyond tidiness: this project has already lost a whole-site
power event to alert fatigue, because a nightly reboot paged red every
night and everyone stopped looking.

The fix anchors the ceiling to the last SUCCESSFUL cycle's duration, which
is what keeps it from becoming an excuse: a hung cycle never completes, so
it can never raise the ceiling it would need to hide behind.
"""
from __future__ import annotations

from tpot2cti.health import (
    NO_SUCCESS_CEILING_MULTIPLIER,
    OBSERVED_DURATION_CEILING_MULTIPLIER,
)


def _ceiling(interval_s: float, last_duration_s: float | None) -> float:
    """Mirror of the rule in HealthServer._payload."""
    ceiling = interval_s * NO_SUCCESS_CEILING_MULTIPLIER
    if last_duration_s:
        ceiling = max(ceiling, last_duration_s * OBSERVED_DURATION_CEILING_MULTIPLIER)
    return ceiling


def test_a_long_cycle_on_a_short_interval_can_be_healthy():
    """The measured backfill case: PT1M interval, 2,895s cycles."""
    assert _ceiling(60.0, 2895.0) >= 2895.0, (
        "a container that completes a 2,895s cycle must be able to read "
        "healthy; a ceiling of 180s makes green unreachable by construction"
    )


def test_the_interval_floor_still_applies_when_cycles_are_fast():
    """A fast connector must not have its ceiling shrunk to nothing."""
    assert _ceiling(900.0, 10.0) == 900.0 * NO_SUCCESS_CEILING_MULTIPLIER


def test_a_hung_cycle_cannot_raise_its_own_ceiling():
    """The property that keeps this from reopening the 16-day stall.

    The ceiling is anchored to the last SUCCESSFUL cycle. A cycle that hangs
    never completes, so it contributes no duration and cannot widen the
    window it would need to stay green inside.
    """
    # No successful cycle yet -> interval-derived ceiling only.
    assert _ceiling(60.0, None) == 60.0 * NO_SUCCESS_CEILING_MULTIPLIER
    # A previously-fast connector that now hangs keeps its small ceiling.
    assert _ceiling(60.0, 30.0) == 60.0 * NO_SUCCESS_CEILING_MULTIPLIER


def test_the_ceiling_is_not_unbounded():
    """Slack for a slow hive, not for a stall."""
    assert OBSERVED_DURATION_CEILING_MULTIPLIER <= 3.0, (
        "too much slack turns the ceiling back into the rubber stamp the "
        "16-day stall slipped through"
    )
    assert _ceiling(60.0, 100.0) == 200.0
