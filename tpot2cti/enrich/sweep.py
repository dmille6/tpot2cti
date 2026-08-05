"""Shared sweep machinery for ENRICH modules that walk CORE's telemetry.

Every Lane A/C module has the same problem: read CORE's `attacker_activity`
roll-up read-only, in bounded pages, covering **every** address rather than
whichever ones happen to be busiest, and never mistaking a broken read for a
quiet fleet.

This lives in one place because the predecessor platform reimplemented its
shared write path 21+ times, and each bug fix landed in one copy while the
other twenty kept the bug. The sweep has already produced four distinct silent
failure modes during review (see the constants and docstrings below); having
one copy means fixing each of them once.

Two rules encoded here, both learned the hard way:

1. **A failed read raises.** Returning an empty list makes a missing DB, a
   missing table, or schema drift indistinguishable from "nothing to do" —
   the module publishes nothing, records a successful cycle, and goes green.
   That is this project's signature failure.
2. **Coverage is a cursor sweep, not a top-N.** The SQL `LIMIT` runs *before*
   any skip-cache filters, so ordering by recency hands back the same page
   every cycle and the older majority of the window is never read at all.
   Measured on live data before this was fixed: ~12,700 of ~14,800 addresses
   were unreachable.
"""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class ActivityReadError(RuntimeError):
    """CORE's telemetry could not be read (missing DB, schema drift, bad query).

    Raised rather than returning an empty list so a broken module can never be
    mistaken for a genuinely quiet fleet.
    """


#: The columns every consumer gets. Aggregated per source IP across all
#: (parser, sensor) rows for that IP.
_SQL = """
    SELECT src_ip,
           COUNT(DISTINCT parser)          AS surfaces,
           COUNT(DISTINCT sensor)          AS sensors,
           SUM(sessions_count)             AS sessions,
           SUM(auth_success_count)         AS auth_success,
           SUM(commands_count)             AS commands,
           SUM(malware_drop_count)         AS malware_drops,
           GROUP_CONCAT(sample_dst_ports_json) AS ports_json
      FROM attacker_activity
     WHERE last_seen >= ? AND src_ip > ?
     GROUP BY src_ip
     ORDER BY src_ip ASC
     LIMIT ?
"""


def read_activity(
    core_db: str,
    *,
    window_hours: int,
    limit: int,
    after_ip: str = "",
) -> list[dict]:
    """Return one aggregated page of CORE's `attacker_activity`, per source IP.

    **What `window_hours` actually means.** It selects rows *last active*
    within N hours; it does NOT window the counters. CORE stores one row per
    `(src_ip, parser, sensor)` with **lifetime** cumulative counts, so the SUMs
    are that triple's totals since first contact, not totals for the last N
    hours. Read the knob as "how recently must this IP have been active for us
    to look at it", never as "activity in the last N hours".

    **Ordering is lexicographic**, because `src_ip` is TEXT — `'45.9.10.1'`
    sorts before `'45.9.9.1'`. That is safe only because this WHERE clause and
    ORDER BY share the same collation, so the sweep needs merely *a* total
    order, not a numerically sensible one. If they ever diverge, addresses
    vanish silently.

    `limit` and `window_hours` are required rather than defaulted, because a
    module-level constant used as a parameter default binds at import and then
    ignores the module global forever — a trap that already let one test assert
    a page size it never applied.

    Raises `ActivityReadError` on any DB or schema problem.
    """
    if limit < 1:
        # Belt and braces: consumers floor this too, but a non-positive limit
        # is catastrophic in two directions — 0 reads nothing and looks
        # successful, and SQLite reads a negative LIMIT as *unlimited*, which
        # parks a cursor at the highest src_ip and never resets.
        raise ValueError(f"limit must be >= 1, got {limit}")
    since = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
    uri = f"file:{core_db}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=10.0)
    except sqlite3.Error as exc:
        raise ActivityReadError(f"cannot open CORE state DB {core_db}: {exc}") from exc
    try:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(_SQL, (since, after_ip, limit))]
    except sqlite3.Error as exc:
        raise ActivityReadError(f"activity query failed: {exc}") from exc
    finally:
        conn.close()


class SweepCursor:
    """Resumable position in a full pass over the in-window address set.

    Owns the three pieces of state that keep coverage honest: where the pass
    resumes, whether publishing is stalled, and how long it has been stalled.
    Keys are namespaced per module so two ENRICH modules sharing a state DB
    would not collide (they should not share one, but the failure if they did
    should be nothing rather than silent interference).
    """

    def __init__(self, state, prefix: str, *, stuck_alert: int = 3) -> None:
        self._state = state
        self.cursor_key = f"{prefix}_sweep_cursor"
        self.stuck_count_key = f"{prefix}_stuck_count"
        self.stuck_at_key = f"{prefix}_stuck_at"
        self._stuck_alert = max(1, int(stuck_alert))

    def position(self) -> str:
        return self._state.get(self.cursor_key) or ""

    def advance(self, rows: list[dict], page_size: int) -> bool:
        """Move to the next page. Returns True if the pass just completed.

        Call only after the page's objects are confirmed published — advancing
        past data that never landed is the defect this project already shipped
        once. A short page proves the window is exhausted, so the pass restarts.
        """
        self._state.set(self.stuck_count_key, "0")
        if len(rows) < page_size:
            self._state.set(self.cursor_key, "")
            return True
        if rows:
            self._state.set(self.cursor_key, str(rows[-1]["src_ip"]))
        return False

    def hold(self, cursor: str) -> int:
        """Record a failed page. Returns the consecutive-failure count here.

        The page is deliberately NOT skipped, so a deterministically bad page
        stalls the sweep until an operator intervenes. That trade is accepted —
        the alternative walks past unpublished data — but it must not be
        silent, so the wedge gets named once the count crosses the threshold.
        """
        at = self._state.get(self.stuck_at_key)
        n = (int(self._state.get(self.stuck_count_key) or 0) + 1) if at == cursor else 1
        self._state.set(self.stuck_at_key, cursor)
        self._state.set(self.stuck_count_key, str(n))
        if n >= self._stuck_alert:
            logger.error(
                "SWEEP WEDGED — %d consecutive publish failures at cursor %r. "
                "The page is NOT skipped (advancing past unpublished data is "
                "worse), so coverage is stalled until this is resolved. "
                "Inspect the addresses after that cursor in CORE's "
                "attacker_activity, or clear %s to step past them deliberately.",
                n, cursor or "<start>", self.cursor_key,
            )
        return n
