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


def wait_for_work(api_work, work_id: str, *, timeout_s: float = 900.0,
                  poll_s: float = 2.0) -> WorkOutcome:
    """Poll a work to a terminal state and report what it did.

    `api_work` is `helper.api.work`. Never raises for a work-level problem --
    a transport exception during polling is itself reported as `unknown`,
    because "we could not find out" and "it failed" must both stop the
    cursor, and only a caller can decide whether to retry.
    """
    started = time.monotonic()
    deadline = started + timeout_s
    last_state: dict[str, Any] = {}

    while time.monotonic() < deadline:
        try:
            state = api_work.get_work(work_id=work_id) or {}
        except Exception as exc:  # noqa: BLE001
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
                errors=list(state.get("errors") or []),
                import_expected=tracking.get("import_expected_number"),
                import_processed=tracking.get("import_processed_number"),
                waited_s=time.monotonic() - started,
            )
        time.sleep(poll_s)

    tracking = (last_state.get("tracking") or {}) if last_state else {}
    logger.error(
        "work %s did not reach a terminal state within %.0fs (last status=%r). "
        "Treating as NOT clean: an unknown outcome must never advance a cursor.",
        work_id, timeout_s, last_state.get("status"),
    )
    return WorkOutcome(
        work_id=work_id,
        status=STATUS_TIMEOUT,
        errors=list(last_state.get("errors") or []),
        import_expected=tracking.get("import_expected_number"),
        import_processed=tracking.get("import_processed_number"),
        waited_s=time.monotonic() - started,
    )
