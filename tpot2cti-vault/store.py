"""SQLite persistence for the vault sidecar.

Implements V1_SPEC §8.2 schema:

    CREATE TABLE samples (
        sha256 TEXT PRIMARY KEY, first_seen_at TIMESTAMP, last_seen_at TIMESTAMP,
        capture_count INTEGER, first_sensor TEXT, first_honeypot TEXT,
        size_bytes INTEGER, file_type TEXT);

    CREATE TABLE seen_files (
        sensor TEXT, honeypot TEXT, filename TEXT, sha256 TEXT, seen_at TIMESTAMP,
        PRIMARY KEY (sensor, honeypot, filename));

SQLite (not DuckDB) was chosen for this sidecar because:
  - tiny dependency surface (stdlib)
  - the workload is write-mostly INSERT-OR-IGNORE, no analytics
  - matches the core importer's state.py pattern (see tpot2cti/state.py)
"""

from __future__ import annotations

import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    sha256          TEXT PRIMARY KEY,
    first_seen_at   TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    capture_count   INTEGER NOT NULL,
    first_sensor    TEXT NOT NULL,
    first_honeypot  TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    file_type       TEXT
);

CREATE TABLE IF NOT EXISTS seen_files (
    sensor    TEXT NOT NULL,
    honeypot  TEXT NOT NULL,
    filename  TEXT NOT NULL,
    sha256    TEXT NOT NULL,
    seen_at   TEXT NOT NULL,
    PRIMARY KEY (sensor, honeypot, filename)
);

CREATE INDEX IF NOT EXISTS idx_seen_sha256 ON seen_files(sha256);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class VaultStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".", exist_ok=True)
        self._conn = sqlite3.connect(db_path, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        logger.info("VaultStore ready at %s", db_path)

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # pragma: no cover
            pass

    # ------------------------------------------------------------------ #
    # seen_files — idempotency oracle
    # ------------------------------------------------------------------ #

    def have_seen(self, sensor: str, honeypot: str, filename: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM seen_files WHERE sensor=? AND honeypot=? AND filename=?",
            (sensor, honeypot, filename),
        ).fetchone()
        return row is not None

    def mark_seen(
        self,
        sensor: str,
        honeypot: str,
        filename: str,
        sha256: str,
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO seen_files (sensor, honeypot, filename, sha256, seen_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (sensor, honeypot, filename, sha256, _now_iso()),
        )

    # ------------------------------------------------------------------ #
    # samples — content-addressable index
    # ------------------------------------------------------------------ #

    def have_sample(self, sha256: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM samples WHERE sha256=?", (sha256,)
        ).fetchone()
        return row is not None

    def insert_sample(
        self,
        sha256: str,
        sensor: str,
        honeypot: str,
        size_bytes: int,
        file_type: Optional[str] = None,
    ) -> None:
        now = _now_iso()
        self._conn.execute(
            "INSERT OR IGNORE INTO samples "
            "(sha256, first_seen_at, last_seen_at, capture_count, "
            " first_sensor, first_honeypot, size_bytes, file_type) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (sha256, now, now, 1, sensor, honeypot, size_bytes, file_type),
        )

    def bump_sample(self, sha256: str) -> None:
        """Increment capture_count + bump last_seen_at for an existing sample."""
        self._conn.execute(
            "UPDATE samples SET capture_count = capture_count + 1, "
            "last_seen_at = ? WHERE sha256=?",
            (_now_iso(), sha256),
        )

    # ------------------------------------------------------------------ #
    # transactions
    # ------------------------------------------------------------------ #

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self._conn.execute("BEGIN")
        try:
            yield
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise
