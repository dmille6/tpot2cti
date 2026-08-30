"""Waiting on an OpenCTI work, without believing what it tells you.

`pycti`'s own ``wait_for_work_to_finish`` cannot be used safely here for two
independent reasons, both verified against the installed 7.260609.0:

1. It returns ``""`` on error and ``None`` on success. BOTH ARE FALSY. A
   caller writing ``if not wait(...)`` reads success as failure; a caller
   writing ``if wait(...)`` reads failure as success; and a bare call
   discards the distinction entirely. There is no correct truthiness test.

2. It loops ``while status != "complete"`` with no timeout. A work that
   never reaches a terminal state blocks the cycle for ever.

And the contract test found the part that matters most: a work reported
``status: "complete"`` while carrying two per-object errors. "Complete"
means "OpenCTI stopped working on it", NOT "everything landed". Gating a
cursor on completeness alone would advance over rejected objects -- the
same class of mistake that once left 80,260,536 documents permanently
unread here.

So this module reports what actually happened and lets the caller decide,
and it FAILS CLOSED: anything it could not establish comes back as
``unknown``, which callers must treat as "do not advance".
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

#: Terminal states we can reason about. Anything else is `unknown`.
STATUS_COMPLETE = "complete"
STATUS_TIMEOUT = "timeout"
STATUS_UNKNOWN = "unknown"


@dataclass
class WorkOutcome:
    """What a work actually did, as opposed to whether it finished."""

    work_id: str
    status: str                      # complete | timeout | unknown
    errors: list = field(default_factory=list)
    import_expected: Optional[int] = None
    import_processed: Optional[int] = None
    waited_s: float = 0.0
    #: Why we stopped waiting: complete | stalled | ceiling. Appended
    #: LAST on purpose -- inserting it mid-dataclass re-bound every
    #: positional argument after it and broke three callers at once.
    reason: str = ""

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def is_clean(self) -> bool:
        """True only if the work finished AND nothing was rejected.

        Deliberately not the same question as "did it finish". The contract
        test observed status=complete alongside two rejected objects; a
        caller that conflates the two publishes a green signal over lost
        data.
        """
        if self.status != STATUS_COMPLETE:
            return False
        if self.errors:
            return False
        # Counts are advisory: `import_expected_number` came back as 4 for a
        # 4-object bundle that contained 2 rejects, so it counts SUBMITTED,
        # not ACCEPTED. A mismatch is still a real problem; a match proves
        # nothing on its own, which is why `errors` is checked first.
        if (self.import_expected is not None
                and self.import_processed is not None
                and self.import_processed != self.import_expected):
            return False
        return True

    def summary(self, limit: int = 400) -> str:
        if not self.errors:
            return ""
        return json.dumps(self.errors, default=str)[:limit]


def wait_for_work(api_work, work_id: str, *, timeout_s: float = 7200.0,
                  stall_s: float = 420.0, poll_s: float = 2.0) -> WorkOutcome:
    """Poll a work to a terminal state and report what it did.

    Two independent limits, because "slow" and "stuck" are different failures
    and only one of them is worth giving up on:

    * ``stall_s`` -- give up when ``import_processed`` STOPS ADVANCING. This
      is the real signal: a wedged work stops counting immediately, a slow
      one keeps counting.
    * ``timeout_s`` -- a hard ceiling, so a work that somehow trickles for
      ever still cannot pin a cycle open.

    A fixed wall-clock deadline alone was measurably wrong. On cycle 205 the
    relationships pass was killed at 900s having imported 6,896 of 11,760
    objects WITH ZERO ERRORS, and went on to import the rest perfectly well
    after we stopped watching. That marked a healthy cycle as failed, and a
    failed cycle holds the cursor -- so the connector would have re-read the
    same window for ever and never advanced. Timing out on elapsed time
    punishes volume; timing out on a stall punishes being stuck, which is
    what we actually mean.

    `api_work` is `helper.api.work`. Never raises for a work-level problem --
    a transport exception during polling is itself reported as `unknown`,
    because "we could not find out" and "it failed" must both stop the
    cursor, and only a caller can decide whether to retry.
    """
    started = time.monotonic()
    deadline = started + timeout_s
    last_state: dict[str, Any] = {}
    best_processed = -1
    last_progress = started

    def _tracking(key):
        return ((last_state.get("tracking") or {}) if last_state else {}).get(key)

    def _outcome(status: str, reason: str) -> WorkOutcome:
        return WorkOutcome(
            work_id=work_id,
            status=status,
            reason=reason,
            errors=list(last_state.get("errors") or []),
            import_expected=_tracking("import_expected_number"),
            import_processed=_tracking("import_processed_number"),
            waited_s=time.monotonic() - started,
        )

    while True:
        if time.monotonic() >= deadline:
            logger.error(
                "work %s hit the %.0fs HARD CEILING (last status=%r, %s/%s "
                "imported). Treating as NOT clean: an unknown outcome must "
                "never advance a cursor.",
                work_id, timeout_s, last_state.get("status"),
                _tracking("import_processed_number"),
                _tracking("import_expected_number"))
            return _outcome(STATUS_TIMEOUT, "ceiling")

        try:
            state = api_work.get_work(work_id=work_id) or {}
        except Exception as exc:  # noqa: BLE001
            # Deliberately NOT counted towards the stall. Losing the ability
            # to ask is not evidence the work stopped moving, and the hard
            # ceiling above still bounds the loop.
            logger.warning("work %s: get_work raised %s: %s",
                           work_id, type(exc).__name__, exc)
            time.sleep(poll_s)
            continue

        last_state = state
        if state.get("status") == STATUS_COMPLETE:
            tracking = state.get("tracking") or {}
            return WorkOutcome(
                work_id=work_id,
                status=STATUS_COMPLETE,
                reason="complete",
                errors=list(state.get("errors") or []),
                import_expected=tracking.get("import_expected_number"),
                import_processed=tracking.get("import_processed_number"),
                waited_s=time.monotonic() - started,
            )

        processed = (state.get("tracking") or {}).get("import_processed_number")
        if isinstance(processed, int) and processed > best_processed:
            best_processed = processed
            last_progress = time.monotonic()

        if time.monotonic() - last_progress > stall_s:
            logger.error(
                "work %s STALLED: no import progress for %.0fs (stuck at %s/%s, "
                "status=%r). Treating as NOT clean.",
                work_id, stall_s,
                best_processed if best_processed >= 0 else None,
                _tracking("import_expected_number"), state.get("status"))
            return _outcome(STATUS_TIMEOUT, "stalled")

        time.sleep(poll_s)
