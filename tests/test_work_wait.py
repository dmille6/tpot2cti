"""wait_for_work must report what happened, not merely that it stopped.

pycti's own `wait_for_work_to_finish` cannot be used safely here, verified
against 7.260609.0:

  * returns "" on error and None on success -- BOTH FALSY. There is no
    correct truthiness test: `if not wait(...)` reads success as failure,
    `if wait(...)` reads failure as success, and a bare call throws the
    distinction away.
  * loops `while status != "complete"` with no timeout, so a work that
    never terminates blocks the cycle for ever.

And the contract test found the substantive part: a work reported
status="complete" while carrying two per-object errors. Completeness is
not success.
"""
from __future__ import annotations

from tpot2cti.work_wait import (STATUS_COMPLETE, STATUS_TIMEOUT, WorkOutcome,
                                wait_for_work)


class _Work:
    """Minimal stand-in for helper.api.work."""

    def __init__(self, states):
        self._states = list(states)

    def get_work(self, work_id):
        return self._states.pop(0) if self._states else self._states_last()

    def _states_last(self):
        return {}


def test_clean_work_is_clean():
    w = _Work([{"status": "complete", "errors": [],
                "tracking": {"import_expected_number": 10,
                             "import_processed_number": 10}}])
    out = wait_for_work(w, "w1", timeout_s=5, poll_s=0.01)
    assert out.status == STATUS_COMPLETE
    assert out.is_clean is True
    assert out.error_count == 0


def test_complete_with_errors_is_not_clean():
    """The exact shape the contract test observed."""
    w = _Work([{"status": "complete",
                "errors": [{"message": "FUNCTIONAL_ERROR"},
                           {"message": "MISSING_REFERENCE_ERROR"}],
                "tracking": {"import_expected_number": 4,
                             "import_processed_number": 4}}])
    out = wait_for_work(w, "w2", timeout_s=5, poll_s=0.01)
    assert out.status == STATUS_COMPLETE, "it did finish"
    assert out.is_clean is False, (
        "status=complete with 2 rejected objects must NOT read as success — "
        "this is the case that would advance a cursor over lost data"
    )
    assert out.error_count == 2
    assert "FUNCTIONAL_ERROR" in out.summary()


def test_timeout_fails_closed():
    w = _Work([{"status": "progress", "errors": []}] * 2)
    out = wait_for_work(w, "w3", timeout_s=0.05, poll_s=0.01)
    assert out.status == STATUS_TIMEOUT
    assert out.is_clean is False, "an unknown outcome must never advance a cursor"


def test_a_raising_api_does_not_escape():
    """We could not find out is the same answer as it failed, for the cursor."""

    class _Boom:
        def get_work(self, work_id):
            raise RuntimeError("transport gone")

    out = wait_for_work(_Boom(), "w4", timeout_s=0.05, poll_s=0.01)
    assert out.status == STATUS_TIMEOUT
    assert out.is_clean is False


def test_count_mismatch_blocks_but_equality_alone_does_not_pass():
    """Counts are diagnostic, not an acceptance signal.

    The contract test returned expected == processed == 4 for a bundle
    containing 2 rejects, so equality is guaranteed by construction and
    proves nothing. A MISMATCH is still a real problem worth blocking on.
    """
    mismatch = WorkOutcome("w", STATUS_COMPLETE, [], 10, 7)
    assert mismatch.is_clean is False

    equal_but_broken = WorkOutcome("w", STATUS_COMPLETE,
                                   [{"message": "FUNCTIONAL_ERROR"}], 4, 4)
    assert equal_but_broken.is_clean is False, (
        "equal counts must not rescue a work that reported errors"
    )

# ---------------------------------------------------------------------------
# Stall-vs-ceiling. Regression for cycle 205 (2026-08-30): a 900s wall-clock
# deadline killed the relationships pass at 6,896/11,760 with ZERO errors. The
# work finished cleanly on its own afterwards. A slow work was reported as a
# failed one, and a failed cycle holds the cursor -- so the connector would
# have re-read the same window for ever and never advanced.
# ---------------------------------------------------------------------------


class _Progressing:
    """A work that keeps importing, then finishes. Slow, never stuck."""

    def __init__(self, polls_before_complete, expected=11760):
        self.n = 0
        self.polls = polls_before_complete
        self.expected = expected

    def get_work(self, work_id=None):
        self.n += 1
        if self.n >= self.polls:
            return {"status": "complete", "errors": [],
                    "tracking": {"import_expected_number": self.expected,
                                 "import_processed_number": self.expected}}
        return {"status": "progress", "errors": [],
                "tracking": {"import_expected_number": self.expected,
                             "import_processed_number": self.n * 50}}


class _Stuck:
    """A work whose counter never moves. Genuinely wedged."""

    def get_work(self, work_id=None):
        return {"status": "progress", "errors": [],
                "tracking": {"import_expected_number": 11760,
                             "import_processed_number": 6896}}


class _Trickling:
    """Always advancing, never completing -- the case the ceiling exists for."""

    def __init__(self):
        self.n = 0

    def get_work(self, work_id=None):
        self.n += 1
        return {"status": "progress", "errors": [],
                "tracking": {"import_expected_number": 10**9,
                             "import_processed_number": self.n}}


def test_progress_extends_the_wait_well_past_the_stall_window():
    """The cycle-205 case: slow but healthy must come back CLEAN.

    Total elapsed here deliberately exceeds stall_s several times over. If
    the implementation ever reverts to a fixed deadline this fails.
    """
    w = _Progressing(polls_before_complete=60)
    out = wait_for_work(w, "slow", timeout_s=30, stall_s=0.05, poll_s=0.005)
    assert out.status == "complete"
    assert out.reason == "complete"
    assert out.is_clean is True
    assert out.waited_s > 0.05


def test_a_stuck_counter_trips_the_stall():
    w = _Stuck()
    out = wait_for_work(w, "stuck", timeout_s=30, stall_s=0.05, poll_s=0.005)
    assert out.status == "timeout"
    assert out.reason == "stalled"
    assert out.is_clean is False
    assert out.import_processed == 6896      # reports where it got stuck
    assert out.waited_s < 5                  # gave up on the stall, not the ceiling


def test_the_ceiling_still_bounds_a_work_that_never_finishes():
    w = _Trickling()
    out = wait_for_work(w, "trickle", timeout_s=0.15, stall_s=999, poll_s=0.005)
    assert out.status == "timeout"
    assert out.reason == "ceiling"
    assert out.is_clean is False


def test_a_polling_exception_does_not_count_as_a_stall():
    """Losing the ability to ask is not evidence the work stopped moving."""

    class _Flaky:
        def __init__(self):
            self.n = 0

        def get_work(self, work_id=None):
            self.n += 1
            if self.n < 8:
                raise RuntimeError("transport blip")
            return {"status": "complete", "errors": [],
                    "tracking": {"import_expected_number": 3,
                                 "import_processed_number": 3}}

    out = wait_for_work(_Flaky(), "flaky", timeout_s=30, stall_s=0.05,
                        poll_s=0.02)
    assert out.status == "complete"
    assert out.is_clean is True
