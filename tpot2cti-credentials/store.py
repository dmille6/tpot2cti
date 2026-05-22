"""DuckDB persistence for the credentials sidecar.

Implements the schema documented in V1_SPEC §8.1:

    CREATE TABLE credentials (
        username VARCHAR, password VARCHAR, sensor VARCHAR,
        first_seen TIMESTAMP, last_seen TIMESTAMP,
        attempt_count BIGINT, unique_src_ip_count BIGINT,
        PRIMARY KEY (username, password, sensor));

    CREATE TABLE credential_sources (
        username VARCHAR, password VARCHAR, sensor VARCHAR, src_ip VARCHAR,
        first_seen TIMESTAMP, last_seen TIMESTAMP, attempt_count BIGINT,
        PRIMARY KEY (username, password, sensor, src_ip));

    CREATE TABLE cycle_log (
        cycle_started_at TIMESTAMP, cycle_ended_at TIMESTAMP,
        events_processed BIGINT, creds_new BIGINT, creds_updated BIGINT);

DuckDB has ``INSERT ... ON CONFLICT (...) DO UPDATE SET ...`` syntax,
which is what we use for the upserts. State (last_run) lives in
``cycle_log``: the start of the next cycle is the max ``cycle_ended_at``
from any prior successful row.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator

import duckdb

logger = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
    username             VARCHAR,
    password             VARCHAR,
    sensor               VARCHAR,
    first_seen           TIMESTAMP,
    last_seen            TIMESTAMP,
    attempt_count        BIGINT,
    unique_src_ip_count  BIGINT,
    PRIMARY KEY (username, password, sensor)
);

CREATE TABLE IF NOT EXISTS credential_sources (
    username     VARCHAR,
    password     VARCHAR,
    sensor       VARCHAR,
    src_ip       VARCHAR,
    first_seen   TIMESTAMP,
    last_seen    TIMESTAMP,
    attempt_count BIGINT,
    PRIMARY KEY (username, password, sensor, src_ip)
);

CREATE TABLE IF NOT EXISTS cycle_log (
    cycle_started_at TIMESTAMP,
    cycle_ended_at   TIMESTAMP,
    events_processed BIGINT,
    creds_new        BIGINT,
    creds_updated    BIGINT
);
"""


@dataclass
class CycleCounts:
    """Aggregate counters returned by :meth:`CredentialsStore.cycle_done`."""
    events_processed: int = 0
    creds_new: int = 0
    creds_updated: int = 0


class CredentialsStore:
    """Thin wrapper around a DuckDB connection.

    DuckDB's file format is single-writer; we keep one connection open
    for the lifetime of the process. The wrapper is intentionally
    sync — sidecars are not asyncio (per LESSONS §2.4).
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".", exist_ok=True)
        self._conn = duckdb.connect(db_path)
        self._conn.execute(_SCHEMA)
        logger.info("DuckDB ready at %s", db_path)

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # pragma: no cover - defensive
            pass

    # ------------------------------------------------------------------ #
    # state cursor — derived from cycle_log
    # ------------------------------------------------------------------ #

    def last_run(self) -> datetime | None:
        """Return the latest ``cycle_ended_at`` recorded, or None."""
        row = self._conn.execute(
            "SELECT MAX(cycle_ended_at) FROM cycle_log"
        ).fetchone()
        if not row or row[0] is None:
            return None
        # DuckDB returns a Python datetime (naive); treat as UTC.
        val: datetime = row[0]
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        return val

    # ------------------------------------------------------------------ #
    # upserts
    # ------------------------------------------------------------------ #

    def upsert_credential(
        self,
        username: str,
        password: str,
        sensor: str,
        src_ip: str,
        event_ts: datetime,
    ) -> tuple[bool, bool]:
        """Insert or update one credential observation.

        Returns ``(is_new_cred, is_new_source)`` so the cycle loop can
        track aggregate counts. ``is_new_cred`` is True when this is
        the first time we've seen the (username, password, sensor)
        tuple. ``is_new_source`` is True when this is the first time
        we've seen the source IP for that tuple.
        """
        # Normalize timestamp to naive UTC for DuckDB TIMESTAMP storage.
        if event_ts.tzinfo is not None:
            event_ts = event_ts.astimezone(timezone.utc).replace(tzinfo=None)

        # --- credentials (per-tuple aggregate) ---
        # Probe first so we can report new vs updated. DuckDB doesn't
        # expose an "INSERTED" affected-rows count after ON CONFLICT.
        existing = self._conn.execute(
            "SELECT first_seen, attempt_count, unique_src_ip_count "
            "FROM credentials WHERE username=? AND password=? AND sensor=?",
            [username, password, sensor],
        ).fetchone()
        is_new_cred = existing is None

        # --- credential_sources (per-IP detail) ---
        existing_src = self._conn.execute(
            "SELECT first_seen, attempt_count FROM credential_sources "
            "WHERE username=? AND password=? AND sensor=? AND src_ip=?",
            [username, password, sensor, src_ip],
        ).fetchone()
        is_new_source = existing_src is None

        if is_new_cred:
            self._conn.execute(
                "INSERT INTO credentials VALUES (?, ?, ?, ?, ?, ?, ?)",
                [username, password, sensor, event_ts, event_ts, 1, 1],
            )
        else:
            # Update last_seen, attempt_count, unique_src_ip_count.
            new_unique = existing[2] + (1 if is_new_source else 0)
            self._conn.execute(
                "UPDATE credentials SET "
                "last_seen = GREATEST(last_seen, ?), "
                "attempt_count = attempt_count + 1, "
                "unique_src_ip_count = ? "
                "WHERE username=? AND password=? AND sensor=?",
                [event_ts, new_unique, username, password, sensor],
            )

        if is_new_source:
            self._conn.execute(
                "INSERT INTO credential_sources VALUES (?, ?, ?, ?, ?, ?, ?)",
                [username, password, sensor, src_ip, event_ts, event_ts, 1],
            )
        else:
            self._conn.execute(
                "UPDATE credential_sources SET "
                "last_seen = GREATEST(last_seen, ?), "
                "attempt_count = attempt_count + 1 "
                "WHERE username=? AND password=? AND sensor=? AND src_ip=?",
                [event_ts, username, password, sensor, src_ip],
            )

        return is_new_cred, is_new_source

    # ------------------------------------------------------------------ #
    # cycle bookkeeping
    # ------------------------------------------------------------------ #

    def record_cycle(
        self,
        started_at: datetime,
        ended_at: datetime,
        counts: CycleCounts,
    ) -> None:
        """Append one row to cycle_log."""
        def _naive_utc(ts: datetime) -> datetime:
            if ts.tzinfo is not None:
                return ts.astimezone(timezone.utc).replace(tzinfo=None)
            return ts

        self._conn.execute(
            "INSERT INTO cycle_log VALUES (?, ?, ?, ?, ?)",
            [
                _naive_utc(started_at),
                _naive_utc(ended_at),
                counts.events_processed,
                counts.creds_new,
                counts.creds_updated,
            ],
        )

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Context manager: BEGIN / COMMIT or ROLLBACK on exception."""
        self._conn.execute("BEGIN")
        try:
            yield
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise
