"""tpot2cti — cycle state persistence.

Tracks the importer's `last_run` timestamp across container restarts.
Per V1_SPEC.md §3 (cycle behavior):

    5. Update state
       - last_run = end of cycle window
       - written to local state DB

Implementation: SQLite file at /opt/connector/data/state.db (bind-mount
of host's `data/tpot2cti/` per V1_SPEC §2.4 file layout).  SQLite was
chosen over a flat file for:

  - Atomic writes (no half-written state file on crash)
  - Future extensibility (per-cycle audit rows live alongside last_run)
  - Zero external dependencies (stdlib `sqlite3`)

The schema is intentionally tiny — one key/value table for cycle state,
one rolling-log table for cycle audit (used by the lightweight audit
jsonl per V1_SPEC §7 if we want a SQL view as well).

This module does NOT cover the cycles.jsonl rotating file — that's
its own module so audit can be appended without holding a DB write
lock.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cycle_log (
    cycle_id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at         TEXT NOT NULL,
    ended_at           TEXT,
    success            INTEGER,
    events_read        INTEGER,
    events_parsed      INTEGER,
    events_dropped     INTEGER,
    sdos_emitted       INTEGER,
    errors_count       INTEGER,
    duration_seconds   REAL
);

CREATE INDEX IF NOT EXISTS idx_cycle_log_started_at
    ON cycle_log(started_at);

-- Per V1_SPEC.md §6 (daily top-100 credentials Note): track which
-- (sensor, utc_date) pairs we've already emitted a Note for, so the
-- "missed midnight" catch-up scan in main.py can find missing days
-- in the configured lookback window without re-emitting (the Note id
-- is idempotent via UUID5, but skipping the ES aggregation when we
-- already published the day is a cheap win).
CREATE TABLE IF NOT EXISTS daily_creds_log (
    sensor      TEXT NOT NULL,
    utc_date    TEXT NOT NULL,
    emitted_at  TEXT NOT NULL,
    PRIMARY KEY (sensor, utc_date)
);

CREATE INDEX IF NOT EXISTS idx_daily_creds_log_utc_date
    ON daily_creds_log(utc_date);
"""


class CycleState:
    """SQLite-backed state for the importer cycle loop."""

    def __init__(self, db_path: str | Path = "/opt/connector/data/state.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as c:
            c.executescript(_SCHEMA)
        logger.debug(f"State DB initialized at {self.db_path}")

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        """SQLite connection context manager.  Auto-commits on success."""
        # Auto-commit isolation level is fine for our single-writer pattern.
        # SQLite default is "deferred" which buffers — we want each
        # set_last_run / record_cycle to be durable immediately.
        conn = sqlite3.connect(self.db_path, isolation_level=None,
                               timeout=10.0)
        # WAL improves concurrent read durability (the cycle.jsonl exporter
        # or external audit query won't block the importer's writes).
        conn.execute("PRAGMA journal_mode = WAL;")
        try:
            yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Key-value state (last_run, last_cycle_id, etc.)
    # ------------------------------------------------------------------

    def get_last_run(self) -> Optional[datetime]:
        """Return the last successful cycle's end time, or None if never run."""
        with self._conn() as c:
            row = c.execute(
                "SELECT value FROM state WHERE key = 'last_run'"
            ).fetchone()
        if not row:
            return None
        try:
            return datetime.fromisoformat(row[0])
        except (TypeError, ValueError) as e:
            logger.warning(f"Corrupt last_run value in state DB: {row[0]!r}; "
                           f"treating as never-run.  {e}")
            return None

    def set_last_run(self, when: datetime) -> None:
        """Update last_run to the given datetime (UTC recommended)."""
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        iso = when.isoformat()
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                "INSERT INTO state (key, value, updated_at) VALUES "
                "('last_run', ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                "updated_at=excluded.updated_at",
                (iso, now),
            )
        logger.debug(f"State updated: last_run = {iso}")

    def get(self, key: str) -> Optional[str]:
        """Generic key/value getter for future state needs."""
        with self._conn() as c:
            row = c.execute(
                "SELECT value FROM state WHERE key = ?", (key,)
            ).fetchone()
        return row[0] if row else None

    def set(self, key: str, value: str) -> None:
        """Generic key/value setter."""
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                "INSERT INTO state (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                "updated_at=excluded.updated_at",
                (key, value, now),
            )

    # ------------------------------------------------------------------
    # Cycle-log rows (used by audit, observability)
    # ------------------------------------------------------------------

    def start_cycle(self) -> int:
        """Begin a cycle row; return its cycle_id for later update."""
        started_at = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO cycle_log (started_at) VALUES (?)", (started_at,)
            )
            return cur.lastrowid

    def record_cycle(
        self,
        cycle_id: int,
        *,
        success: bool,
        events_read: int,
        events_parsed: int,
        events_dropped: int,
        sdos_emitted: int,
        errors_count: int,
        duration_seconds: float,
    ) -> None:
        """Finalize a cycle row with the cycle's outcomes."""
        ended_at = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                "UPDATE cycle_log SET "
                "ended_at = ?, success = ?, events_read = ?, "
                "events_parsed = ?, events_dropped = ?, sdos_emitted = ?, "
                "errors_count = ?, duration_seconds = ? "
                "WHERE cycle_id = ?",
                (ended_at, 1 if success else 0, events_read, events_parsed,
                 events_dropped, sdos_emitted, errors_count, duration_seconds,
                 cycle_id),
            )

    def record_cycle_failure(
        self, cycle_id: int, error_msg: str, duration_seconds: float = 0.0
    ) -> None:
        """Mark a cycle row as failed.  Convenience wrapper around
        `record_cycle()` for the exception path in `main.run_cycle`.

        Per V1_SPEC.md §7 (error handling): we never let a single bad
        cycle crash the loop — we log + record + continue.  The error
        message is truncated to 4 KB for the cycle_log row.
        """
        msg = (error_msg or "")[:4096]
        # Store error in the generic state table under a rolling key so
        # /health can surface "last failure" without a schema change.
        self.set("last_cycle_error", msg)
        ended_at = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                "UPDATE cycle_log SET "
                "ended_at = ?, success = 0, errors_count = 1, "
                "duration_seconds = ? "
                "WHERE cycle_id = ?",
                (ended_at, duration_seconds, cycle_id),
            )

    # ------------------------------------------------------------------
    # Daily top-100 credentials Note tracking (V1_SPEC.md §6)
    # ------------------------------------------------------------------

    def record_daily_creds_emitted(self, sensor: str, utc_date: date) -> None:
        """Mark a (sensor, utc_date) pair as having had its daily Note emitted.

        Called by `main.run_cycle` AFTER a successful publisher round, so
        a failed publish doesn't poison the log (the Note id is idempotent
        in OpenCTI, but we want the catch-up scan to retry next cycle).
        """
        d = utc_date.isoformat() if isinstance(utc_date, date) else str(utc_date)
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                "INSERT INTO daily_creds_log (sensor, utc_date, emitted_at) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(sensor, utc_date) DO UPDATE SET "
                "emitted_at = excluded.emitted_at",
                (sensor, d, now),
            )
        logger.debug(
            f"daily_creds_log: recorded sensor={sensor!r} utc_date={d}"
        )

    def get_missing_daily_creds_dates(
        self, sensor: str, lookback_days: int
    ) -> list[date]:
        """Return UTC dates in [today - lookback_days, yesterday] for `sensor`
        that don't yet have a row in `daily_creds_log`.

        We DELIBERATELY exclude today (the day isn't over yet — emitting a
        partial-day Note would be wrong and would not get re-emitted, since
        the (sensor, today) row would mark it done).

        Per V1_SPEC.md §6: "Once per UTC day (computed during the cycle
        that crosses midnight)".  This catches the case where the
        importer was down across midnight — on next start we walk back
        `lookback_days` (default 7) and fill in any gaps.
        """
        if lookback_days <= 0:
            return []
        today = datetime.now(timezone.utc).date()
        # Half-open window: yesterday inclusive, looking back lookback_days.
        # e.g. lookback_days=7 → yesterday + 6 prior days = 7 candidate dates.
        candidates: list[date] = [
            today - timedelta(days=n) for n in range(1, lookback_days + 1)
        ]
        with self._conn() as c:
            rows = c.execute(
                "SELECT utc_date FROM daily_creds_log WHERE sensor = ?",
                (sensor,),
            ).fetchall()
        emitted = {r[0] for r in rows}
        missing = [d for d in candidates if d.isoformat() not in emitted]
        # Return in ascending date order for stable / predictable processing.
        missing.sort()
        return missing

    def recent_cycles(self, limit: int = 10) -> list[dict]:
        """Return the last N cycle rows, newest first."""
        with self._conn() as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                "SELECT * FROM cycle_log "
                "ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def prune_cycles(self, keep_last: int = 1000) -> int:
        """Delete cycle_log rows beyond the last N.  Returns rows deleted."""
        with self._conn() as c:
            cur = c.execute(
                "DELETE FROM cycle_log "
                "WHERE cycle_id NOT IN ("
                "  SELECT cycle_id FROM cycle_log "
                "  ORDER BY started_at DESC LIMIT ?"
                ")",
                (keep_last,),
            )
            return cur.rowcount


if __name__ == "__main__":
    import tempfile

    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        s = CycleState(db_path=tmp)
        assert s.get_last_run() is None, "fresh DB should have no last_run"
        print("OK: fresh DB has no last_run")

        now = datetime.now(timezone.utc)
        s.set_last_run(now)
        got = s.get_last_run()
        assert got is not None
        # Allow up to 1 microsecond drift through ISO round-trip
        assert abs((got - now).total_seconds()) < 0.001
        print(f"OK: last_run round-trip: {got.isoformat()}")

        cid = s.start_cycle()
        print(f"OK: started cycle id={cid}")
        s.record_cycle(
            cid, success=True, events_read=12503, events_parsed=12489,
            events_dropped=14, sdos_emitted=47823, errors_count=0,
            duration_seconds=18.4,
        )
        rows = s.recent_cycles(5)
        print(f"OK: recent_cycles returned {len(rows)} row(s)")
        print(f"  cycle: {rows[0]}")

        s.set("custom_key", "custom_value")
        assert s.get("custom_key") == "custom_value"
        print("OK: generic key/value get/set works")

        # ── daily_creds_log smoke (V1_SPEC §6) ──
        from datetime import date as _date, timedelta as _td
        sensor = "tpot01"
        today = datetime.now(timezone.utc).date()
        yesterday = today - _td(days=1)
        two_days_ago = today - _td(days=2)

        # Fresh DB → every day in lookback window is missing.
        missing = s.get_missing_daily_creds_dates(sensor, lookback_days=7)
        assert len(missing) == 7, f"expected 7 missing dates, got {len(missing)}"
        assert today not in missing, "today should NOT be in the missing set"
        assert yesterday in missing, "yesterday should be missing on fresh DB"
        print(f"OK: get_missing_daily_creds_dates → {len(missing)} dates, "
              f"first={missing[0].isoformat()} last={missing[-1].isoformat()}")

        # Record yesterday + two_days_ago as emitted.
        s.record_daily_creds_emitted(sensor, yesterday)
        s.record_daily_creds_emitted(sensor, two_days_ago)
        missing2 = s.get_missing_daily_creds_dates(sensor, lookback_days=7)
        assert yesterday not in missing2
        assert two_days_ago not in missing2
        assert len(missing2) == 5, f"expected 5 after recording 2, got {len(missing2)}"
        print(f"OK: after recording 2 days, missing count = {len(missing2)}")

        # Idempotent re-record (ON CONFLICT update).
        s.record_daily_creds_emitted(sensor, yesterday)
        missing3 = s.get_missing_daily_creds_dates(sensor, lookback_days=7)
        assert len(missing3) == 5
        print("OK: record_daily_creds_emitted is idempotent")

        # Other sensor isolated.
        missing_other = s.get_missing_daily_creds_dates("tpot02", lookback_days=7)
        assert len(missing_other) == 7, "other sensor should be untouched"
        print("OK: daily_creds_log is per-sensor isolated")

        # record_cycle_failure stamps last_cycle_error and the row.
        cid2 = s.start_cycle()
        s.record_cycle_failure(cid2, "kaboom: test failure", duration_seconds=0.5)
        assert s.get("last_cycle_error") == "kaboom: test failure"
        rows = s.recent_cycles(2)
        # newest first — should include the failed row
        assert any(r["success"] == 0 for r in rows), "failure row not recorded"
        print("OK: record_cycle_failure stamps state + cycle_log row")

        print("\nSmoke test passed.")
    finally:
        Path(tmp).unlink(missing_ok=True)
        Path(tmp + "-wal").unlink(missing_ok=True)
        Path(tmp + "-shm").unlink(missing_ok=True)
