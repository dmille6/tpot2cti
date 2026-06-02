"""tpot2cti — local credential store (keeps bruteforce pairs OUT of OpenCTI).

A single bruteforce run can be tens of thousands of (username, password)
attempts. Emitting those as OpenCTI objects would flood the platform — so
we record every attempt here instead, and the publisher emits only ONE
Note per attacker IP summarising the pairs tried and which (if any) was
accepted. See docs/credential-store.md.

This mirrors the production tsec-tpot-connectors DuckDB ``CredentialStore``
(``credential_pairs`` + ``credential_usage`` tables, UPSERT semantics), but
uses stdlib ``sqlite3`` — the same engine OSS already uses for state.db — to
avoid adding a dependency to the lean core.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CredentialStore:
    """SQLite-backed store of credential attempts, keyed for per-IP recall.

    Usage::

        store = CredentialStore("/data/credentials.db")
        store.record_attempt("root", "toor", attacker_ip="1.2.3.4",
                             honeypot_name="node1", honeypot_type="Cowrie",
                             service="ssh", port=22, success=True)
        rows = store.get_ip_credentials("1.2.3.4")   # -> for the Note
    """

    def __init__(self, db_path: str = "/data/credentials.db") -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._conn_obj = sqlite3.connect(db_path)
        self._conn_obj.execute("PRAGMA journal_mode=WAL;")
        # NORMAL is safe under WAL and avoids an fsync per commit — this
        # store takes one write per credential attempt (thousands/cycle).
        self._conn_obj.execute("PRAGMA synchronous=NORMAL;")
        self._conn_obj.row_factory = sqlite3.Row
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with self._conn_obj:  # commits on success, rolls back on exception
            yield self._conn_obj

    def _init_schema(self) -> None:
        with self._conn() as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS credential_pairs (
                    credential_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                    username        TEXT NOT NULL,
                    password        TEXT NOT NULL,
                    password_sha256 TEXT NOT NULL,
                    password_length INTEGER,
                    is_empty_pass   INTEGER DEFAULT 0,
                    first_seen      TEXT NOT NULL,
                    last_seen       TEXT NOT NULL,
                    total_attempts  INTEGER DEFAULT 0,
                    UNIQUE (username, password_sha256)
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS credential_usage (
                    usage_id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    credential_id    INTEGER NOT NULL,
                    attacker_ip      TEXT NOT NULL,
                    honeypot_name    TEXT NOT NULL,
                    honeypot_type    TEXT NOT NULL,
                    service          TEXT NOT NULL,
                    port             INTEGER NOT NULL,
                    first_seen       TEXT NOT NULL,
                    last_seen        TEXT NOT NULL,
                    attempt_count    INTEGER DEFAULT 0,
                    success_count    INTEGER DEFAULT 0,
                    attacker_country TEXT,
                    attacker_asn     INTEGER,
                    attacker_org     TEXT,
                    UNIQUE (credential_id, attacker_ip, honeypot_name, service, port)
                )
                """
            )
            c.execute(
                "CREATE INDEX IF NOT EXISTS idx_usage_ip ON credential_usage(attacker_ip)"
            )

    # ------------------------------------------------------------------
    # write path
    # ------------------------------------------------------------------

    def record_attempt(
        self,
        username: str,
        password: str,
        *,
        attacker_ip: str,
        honeypot_name: str,
        honeypot_type: str,
        service: str,
        port: int,
        when: Optional[datetime] = None,
        success: bool = False,
        country: Optional[str] = None,
        asn: Optional[int] = None,
        org: Optional[str] = None,
    ) -> int:
        """Record one credential attempt; UPSERT pair + usage. Returns credential_id.

        Tens of thousands of attempts collapse onto a bounded set of rows:
        repeat (username, password) pairs increment counters rather than
        inserting new rows, and per-(ip, honeypot, service, port) usage is
        aggregated the same way.
        """
        username = "" if username is None else str(username)
        password = "" if password is None else str(password)
        ph = _sha256(password)
        ts = (when or datetime.now(timezone.utc)).isoformat()
        with self._conn() as c:
            c.execute(
                """
                INSERT INTO credential_pairs
                    (username, password, password_sha256, password_length,
                     is_empty_pass, first_seen, last_seen, total_attempts)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(username, password_sha256) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    total_attempts = total_attempts + 1
                """,
                (username, password, ph, len(password),
                 1 if password == "" else 0, ts, ts),
            )
            cid = c.execute(
                "SELECT credential_id FROM credential_pairs "
                "WHERE username = ? AND password_sha256 = ?",
                (username, ph),
            ).fetchone()[0]
            c.execute(
                """
                INSERT INTO credential_usage
                    (credential_id, attacker_ip, honeypot_name, honeypot_type,
                     service, port, first_seen, last_seen, attempt_count,
                     success_count, attacker_country, attacker_asn, attacker_org)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                ON CONFLICT(credential_id, attacker_ip, honeypot_name, service, port)
                DO UPDATE SET
                    last_seen = excluded.last_seen,
                    attempt_count = attempt_count + 1,
                    success_count = success_count + excluded.success_count
                """,
                (cid, attacker_ip, honeypot_name, honeypot_type, service, port,
                 ts, ts, 1 if success else 0, country, asn, org),
            )
        return cid

    # ------------------------------------------------------------------
    # read path (for the per-IP Note)
    # ------------------------------------------------------------------

    def get_ip_credentials(self, attacker_ip: str) -> list[dict]:
        """Return the credential pairs an IP tried, newest-first, for the Note.

        Each row: ``username, password, attempts, succeeded (bool), service,
        port``. This is the summary the publisher renders into ONE Note on
        the attacker IP — the bulk detail stays here in the store.
        """
        with self._conn() as c:
            rows = c.execute(
                """
                SELECT p.username AS username,
                       p.password AS password,
                       SUM(u.attempt_count) AS attempts,
                       SUM(u.success_count) AS successes,
                       u.service AS service,
                       u.port AS port,
                       MAX(u.last_seen) AS last_seen
                FROM credential_usage u
                JOIN credential_pairs p ON p.credential_id = u.credential_id
                WHERE u.attacker_ip = ?
                GROUP BY p.credential_id, u.service, u.port
                ORDER BY last_seen DESC
                """,
                (attacker_ip,),
            ).fetchall()
        return [
            {
                "username": r["username"],
                "password": r["password"],
                "attempts": int(r["attempts"] or 0),
                "succeeded": bool(r["successes"] or 0),
                "service": r["service"],
                "port": r["port"],
            }
            for r in rows
        ]

    def close(self) -> None:
        try:
            self._conn_obj.close()
        except Exception as e:  # pragma: no cover - defensive
            logger.debug(f"credential_store close raised (ignored): {e}")
