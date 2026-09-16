"""The Lane B enrichment ledger — cache, budget, backlog and health in one table.

Deliberately a single component, per docs/ENRICHMENT.md §6: the same table
answers four questions, and splitting it would mean four things that can
disagree about whether a lookup happened.

THE RULE THAT MATTERS MOST
--------------------------
**Cache on confirmed, never on attempted.** A `found` / `not_found` row is
written only when the provider returned a valid response AND the caller
confirms the downstream write landed. Failures get ``status='error'`` with a
backoff and ``attempt_count += 1`` — never a clean verdict.

The predecessor cached a verdict when it merely *tried* to write, which masked
dropped writes for weeks. A cache that hides failure is worse than no cache.

Two supporting rules, also from §6:
  * store NORMALISED verdicts, never the raw vendor blob (a legacy store
    reached 6.4 GB for 949 samples);
  * the ledger is NOT OpenCTI labels. Labels are the *output* and carry no TTL;
    the ledger is the *cache*.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS enrichment_cache (
  source        TEXT NOT NULL,
  obs_type      TEXT NOT NULL,
  value         TEXT NOT NULL,
  status        TEXT NOT NULL,
  verdict_json  TEXT,
  fetched_at    TEXT NOT NULL,
  expires_at    TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  last_error    TEXT,
  PRIMARY KEY (source, obs_type, value)
);
CREATE INDEX IF NOT EXISTS idx_cache_expiry  ON enrichment_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_cache_fetched ON enrichment_cache(source, fetched_at);
"""

#: Statuses that count as a confirmed answer we may reuse.
_TERMINAL = ("found", "not_found")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


@dataclass(frozen=True)
class CacheHit:
    status: str
    verdict: dict
    fetched_at: str


class EnrichmentLedger:
    """SQLite-backed cache + budget + backlog for Lane B."""

    def __init__(self, path: str) -> None:
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._db = sqlite3.connect(path, timeout=30, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(SCHEMA)

    # ── reads ────────────────────────────────────────────────────────────

    def lookup(self, source: str, obs_type: str, value: str) -> Optional[CacheHit]:
        """Return a live cached answer, or None if absent/expired/erroring.

        An expired row is treated as a miss rather than deleted: the row still
        carries attempt_count and last_error, which the backoff needs.
        """
        row = self._db.execute(
            "SELECT status, verdict_json, fetched_at, expires_at "
            "FROM enrichment_cache WHERE source=? AND obs_type=? AND value=?",
            (source, obs_type, value)).fetchone()
        if not row:
            return None
        status, vj, fetched_at, expires_at = row
        if status not in _TERMINAL:
            return None
        if expires_at and expires_at <= _iso(_now()):
            return None
        try:
            verdict = json.loads(vj) if vj else {}
        except (TypeError, ValueError):
            verdict = {}
        return CacheHit(status=status, verdict=verdict, fetched_at=fetched_at)

    def in_backoff(self, source: str, obs_type: str, value: str,
                   *, base_seconds: int = 300, max_seconds: int = 86400) -> bool:
        """True while an errored entry is still inside its exponential backoff.

        Without this, a source that is down gets hammered once per cycle per
        object for as long as it stays down.
        """
        row = self._db.execute(
            "SELECT status, fetched_at, attempt_count FROM enrichment_cache "
            "WHERE source=? AND obs_type=? AND value=?",
            (source, obs_type, value)).fetchone()
        if not row or row[0] != "error":
            return False
        _, fetched_at, attempts = row
        wait = min(base_seconds * (2 ** max(0, int(attempts) - 1)), max_seconds)
        try:
            when = datetime.fromisoformat(fetched_at)
        except ValueError:
            return False
        return _now() < when + timedelta(seconds=wait)

    def spent_since(self, source: str, since: datetime) -> int:
        """Confirmed provider calls for `source` since `since` — the budget read.

        Counts errors too: a failed call still consumed quota with the provider.
        """
        row = self._db.execute(
            "SELECT COUNT(*) FROM enrichment_cache WHERE source=? AND fetched_at>=?",
            (source, _iso(since))).fetchone()
        return int(row[0]) if row else 0

    def spent_today(self, source: str) -> int:
        midnight = _now().replace(hour=0, minute=0, second=0, microsecond=0)
        return self.spent_since(source, midnight)

    def stats(self) -> dict:
        out: dict[str, Any] = {}
        for status, n in self._db.execute(
                "SELECT status, COUNT(*) FROM enrichment_cache GROUP BY status"):
            out[str(status)] = int(n)
        return out

    # ── writes ───────────────────────────────────────────────────────────

    def record_result(self, source: str, obs_type: str, value: str, *,
                      status: str, verdict: Optional[dict], ttl_seconds: int) -> None:
        """Write a CONFIRMED answer. Callers must not call this speculatively.

        `verdict` is the normalised minimal dict, never the raw vendor blob.
        """
        if status not in _TERMINAL:
            raise ValueError(f"record_result is for confirmed answers, got {status!r}")
        now = _now()
        self._db.execute(
            "INSERT INTO enrichment_cache "
            "(source, obs_type, value, status, verdict_json, fetched_at, "
            " expires_at, attempt_count, last_error) "
            "VALUES (?,?,?,?,?,?,?,0,NULL) "
            "ON CONFLICT(source, obs_type, value) DO UPDATE SET "
            "  status=excluded.status, verdict_json=excluded.verdict_json, "
            "  fetched_at=excluded.fetched_at, expires_at=excluded.expires_at, "
            "  attempt_count=0, last_error=NULL",
            (source, obs_type, value, status,
             json.dumps(verdict or {}, separators=(",", ":")),
             _iso(now), _iso(now + timedelta(seconds=ttl_seconds))))

    def record_error(self, source: str, obs_type: str, value: str,
                     error: str) -> None:
        """Record a failed attempt — never a clean verdict."""
        self._db.execute(
            "INSERT INTO enrichment_cache "
            "(source, obs_type, value, status, verdict_json, fetched_at, "
            " expires_at, attempt_count, last_error) "
            "VALUES (?,?,?, 'error', NULL, ?, NULL, 1, ?) "
            "ON CONFLICT(source, obs_type, value) DO UPDATE SET "
            "  status='error', fetched_at=excluded.fetched_at, expires_at=NULL, "
            "  attempt_count=enrichment_cache.attempt_count+1, "
            "  last_error=excluded.last_error",
            (source, obs_type, value, _iso(_now()), str(error)[:300]))

    def close(self) -> None:
        try:
            self._db.close()
        except Exception:  # noqa: BLE001
            pass
