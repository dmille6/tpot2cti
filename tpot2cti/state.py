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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Optional

from tpot2cti.stix_ids import canonical_ip

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

-- Cross-cycle label/score preservation per the V0 finding on pycti UPSERT overwriting scalar fields + the
-- 2026-05-21 live-find: pycti's UPSERT silently overwrites scalar
-- fields on Indicators/SCOs across cycles. A high-signal Cowrie
-- indicator (score 100, labels [cowrie, honeypot, ssh-telnet]) could
-- be overwritten by a lower-signal emission for the same IP (e.g.
-- a P0f fallback at score 50) in a later cycle.
--
-- This table is the connector-side "what's the highest-signal version
-- of this object we've ever shipped" memory. Publisher reads from it
-- before sending; merges labels (union), keeps max score, and
-- preserves the higher-score emission's name/description.
--
-- One row per STIX id. Same UUID5 = same row → idempotent across
-- cycles. The labels_json column is a JSON-encoded sorted list.
CREATE TABLE IF NOT EXISTS object_max_state (
    stix_id       TEXT PRIMARY KEY,
    max_score     INTEGER,
    labels_json   TEXT,
    name          TEXT,
    description   TEXT,
    updated_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_object_max_state_score
    ON object_max_state(max_score);

-- Indexed for prune_object_max_state's "WHERE updated_at < cutoff" scan.
CREATE INDEX IF NOT EXISTS idx_object_max_state_updated_at
    ON object_max_state(updated_at);

-- Per-attacker rolling aggregates feeding the attacker-profile Notes.
-- One row per (src_ip, parser, sensor). Updated every cycle that has
-- activity from this attacker via that parser on that sensor.
-- See tpot2cti/attacker_profile.py for the consumer + V1_SPEC §6 (the
-- daily-creds Note has a similar pattern; this is the more-general
-- multi-parser sibling).
CREATE TABLE IF NOT EXISTS attacker_activity (
    src_ip                  TEXT NOT NULL,
    parser                  TEXT NOT NULL,       -- "Cowrie", "Suricata", etc.
    sensor                  TEXT NOT NULL,
    sessions_count          INTEGER NOT NULL DEFAULT 0,
    events_count            INTEGER NOT NULL DEFAULT 0,
    auth_success_count      INTEGER NOT NULL DEFAULT 0,
    credentials_count       INTEGER NOT NULL DEFAULT 0,
    commands_count          INTEGER NOT NULL DEFAULT 0,
    malware_drop_count      INTEGER NOT NULL DEFAULT 0,
    first_seen              TEXT NOT NULL,
    last_seen               TEXT NOT NULL,
    sample_credentials_json TEXT,                -- top-N (user,pass,count) JSON list
    sample_commands_json    TEXT,                -- top-N (command,count) JSON list
    sample_hashes_json      TEXT,                -- malware sha256 JSON list
    sample_urls_json        TEXT,                -- URLs JSON list
    sample_domains_json     TEXT,                -- Domains JSON list
    sample_signatures_json  TEXT,                -- Suricata sig names JSON list
    sample_mitre_json       TEXT,                -- MITRE technique ids JSON list
    sample_dst_ports_json   TEXT,                -- Honeytrap dst_ports JSON list
    geoip_country           TEXT,
    geoip_asn               INTEGER,
    geoip_as_org            TEXT,
    hassh                   TEXT,                -- if known (Cowrie)
    ssh_version             TEXT,                -- if known (Cowrie)
    PRIMARY KEY (src_ip, parser, sensor)
);

CREATE INDEX IF NOT EXISTS idx_attacker_activity_src_ip
    ON attacker_activity(src_ip);
CREATE INDEX IF NOT EXISTS idx_attacker_activity_last_seen
    ON attacker_activity(last_seen);

-- Tracks the per-cadence emission point for attacker-profile Notes, so
-- the per-cycle emitter can skip IPs that haven't accumulated new activity
-- since the last emission. Idempotent UUID5 keeps OpenCTI from creating
-- duplicates regardless, but this saves bundle bytes.
CREATE TABLE IF NOT EXISTS attacker_profile_emit_log (
    src_ip         TEXT NOT NULL,
    cadence        TEXT NOT NULL,                -- "live" / "daily" / "weekly"
    last_seen_seen TEXT NOT NULL,                -- the activity row's last_seen at emit time
    emitted_at     TEXT NOT NULL,
    PRIMARY KEY (src_ip, cadence)
);

CREATE INDEX IF NOT EXISTS idx_attacker_profile_emit_log_emitted_at
    ON attacker_profile_emit_log(emitted_at);

-- Cross-cycle ledger of which attacker IPs have presented which concrete
-- IoC (shared malware hash, planted SSH key, HASSH / JA3 client fingerprint).
-- A Campaign only materialises once an artifact_key is shared by >= 2 distinct
-- IPs (see tpot2cti/campaigns.py) — the "same actor/toolkit" signal. The
-- second IP arrives in a LATER cycle than the first, so this state is what
-- lets the importer detect the sharing at all. `emitted` flips to 1 once an
-- IP's indicates-edge has been published, so popular artifacts don't re-emit
-- every member edge every cycle.
CREATE TABLE IF NOT EXISTS campaign_artifacts (
    artifact_key   TEXT NOT NULL,                -- "malware:<sha256>", "hassh:<h>", ...
    src_ip         TEXT NOT NULL,
    artifact_type  TEXT NOT NULL,                -- "malware" / "ssh-key" / "hassh" / "ja3"
    artifact_value TEXT NOT NULL,                -- the raw sha256 / fingerprint / hash
    display        TEXT NOT NULL,                -- short human label
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    emitted        INTEGER NOT NULL DEFAULT 0,   -- 1 once this IP's edge is published
    PRIMARY KEY (artifact_key, src_ip)
);

CREATE INDEX IF NOT EXISTS idx_campaign_artifacts_key
    ON campaign_artifacts(artifact_key);
CREATE INDEX IF NOT EXISTS idx_campaign_artifacts_last_seen
    ON campaign_artifacts(last_seen);
"""


class CycleState:
    """SQLite-backed state for the importer cycle loop."""

    # Max STIX ids per ``WHERE ... IN (...)`` batch. Kept well under
    # SQLite's oldest ``SQLITE_MAX_VARIABLE_NUMBER`` (999) so bulk lookups
    # never raise "too many SQL variables" regardless of bundle size.
    _SQL_VAR_CHUNK = 500

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

    def heartbeat(self) -> None:
        """Record a liveness heartbeat for the /health endpoint.

        Called from the cycle loop at start and at each long-running step
        (ES stream complete, after every publisher pass) so /health can
        tell a healthy long-running cycle apart from a hung/dead process.
        A heavy cycle at hive scale can run longer than the staleness
        window between *completed* cycles; without a heartbeat /health
        would flip to 503 (and the container to "unhealthy") mid-cycle
        even though work is actively progressing. See health.py.

        Stored in the generic ``state`` KV table so no schema change is
        needed; the value is an ISO-8601 UTC timestamp.
        """
        self.set("last_heartbeat_ts", datetime.now(timezone.utc).isoformat())

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

    def recent_cycles(self, limit: int = 10) -> list[dict]:
        """Return the last N cycle rows, newest first."""
        with self._conn() as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                "SELECT * FROM cycle_log "
                "ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def prune_cycles(self, keep_last: int = 10_000) -> int:
        """Delete cycle_log rows beyond the last N.  Returns rows deleted.

        Default of 10k rows ≈ 104 days at 15-min cycle. Calling it once
        per cycle is cheap (SQLite ``DELETE … NOT IN (SELECT … LIMIT N)``
        on a small indexed table is microseconds).
        """
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

    # ----------------------------------------------------------------------
    # Pruning — keep the SQLite footprint bounded.
    #
    # Per the 2026-05-22 audit: ``attacker_activity``, ``object_max_state``,
    # and ``attacker_profile_emit_log`` had no pruning at all.  Without
    # bounds, the DB grows monotonically at honeypot-hive rates (~50k new
    # IPs/day) and SQLite query time degrades within months.
    #
    # Pruning semantics:
    #   - ``attacker_activity``: drop rows whose last_seen is older than
    #     ``cutoff_days`` (default 90).  Same attacker reappearing after
    #     pruning starts fresh — acceptable: they'll get a new "first_seen"
    #     and a fresh attacker-profile Note cadence.
    #   - ``attacker_profile_emit_log``: drop rows whose ``emitted_at`` is
    #     older than ``profile_log_cutoff_days`` (default 100, > activity
    #     cutoff so the emit gate stays intact for any IP whose activity
    #     row is still present).
    #   - ``object_max_state``: drop rows not touched in
    #     ``max_state_cutoff_days`` (default 180).  Worst case after prune:
    #     a re-emission of that object UPSERTs without cross-cycle merge;
    #     publisher will re-establish the row on first re-emit.  6 months
    #     of inactivity is a strong signal we won't see it again.
    # ----------------------------------------------------------------------

    def prune_attacker_activity(self, cutoff_days: int = 90) -> int:
        """Drop attacker_activity rows whose last_seen is older than cutoff."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=cutoff_days)).isoformat()
        with self._conn() as c:
            cur = c.execute(
                "DELETE FROM attacker_activity WHERE last_seen < ?",
                (cutoff,),
            )
            return cur.rowcount

    def prune_malformed_attacker_activity(self) -> int:
        """Drop attacker_activity rows whose src_ip is not an address.

        Cleanup for rows written before the source-address gate existed:
        h0neytr4p reports the attacker-controlled X-Forwarded-For header
        as the client address, so Log4Shell scanners deposited obfuscated
        JNDI payloads in this table's key column (30 rows on the live
        hive). They produce no observables, they are counted as
        ``malformed`` by the noisefloor enricher every pass, and they can
        never match a real attacker.

        Self-healing rather than a one-shot migration: it runs each cycle
        as part of :meth:`prune_all`, costs one indexed scan, and returns
        0 forever once the table is clean. Filtering is done in Python
        because SQLite has no address type.
        """
        with self._conn() as c:
            bad = [
                row[0] for row in c.execute(
                    "SELECT DISTINCT src_ip FROM attacker_activity"
                )
                if canonical_ip(str(row[0])) is None
            ]
            if not bad:
                return 0
            deleted = 0
            # Chunked so a large cleanup can't overflow SQLite's
            # bind-variable limit — the exact failure mode behind the
            # 2026-07-19 ingestion outage.
            for i in range(0, len(bad), 500):
                chunk = bad[i:i + 500]
                cur = c.execute(
                    "DELETE FROM attacker_activity WHERE src_ip IN "
                    f"({','.join('?' * len(chunk))})",
                    chunk,
                )
                deleted += cur.rowcount
            logger.info(
                f"attacker_activity: removed {deleted} row(s) with a "
                f"non-address src_ip ({len(bad)} distinct value(s))"
            )
            return deleted

    def prune_attacker_profile_emit_log(self, cutoff_days: int = 100) -> int:
        """Drop attacker_profile_emit_log rows older than cutoff (default 100d).

        Cutoff intentionally exceeds ``prune_attacker_activity``'s default
        so the per-IP emission gate stays present for any IP whose activity
        row is still present (prevents Note storm on re-emit after activity
        prune lag).
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=cutoff_days)).isoformat()
        with self._conn() as c:
            cur = c.execute(
                "DELETE FROM attacker_profile_emit_log WHERE emitted_at < ?",
                (cutoff,),
            )
            return cur.rowcount

    def prune_campaign_artifacts(self, cutoff_days: int = 180) -> int:
        """Drop campaign_artifacts rows whose last_seen is older than cutoff.

        Cutoff is generous (180d) — a shared-IoC campaign can resurface after
        a long dormancy, and the row is what lets us re-attribute a returning
        IP. Idempotent Campaign UUID5 means a re-emit after prune simply
        re-establishes the node.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=cutoff_days)).isoformat()
        with self._conn() as c:
            cur = c.execute(
                "DELETE FROM campaign_artifacts WHERE last_seen < ?",
                (cutoff,),
            )
            return cur.rowcount

    def prune_object_max_state(self, cutoff_days: int = 180) -> int:
        """Drop object_max_state rows not updated in cutoff days (default 180d).

        Idempotent UUID5 means a re-emission re-establishes the row from
        the current cycle's signal; the worst case is loss of cross-cycle
        label-union for one cycle if a long-dormant object suddenly
        reappears.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=cutoff_days)).isoformat()
        with self._conn() as c:
            cur = c.execute(
                "DELETE FROM object_max_state WHERE updated_at < ?",
                (cutoff,),
            )
            return cur.rowcount

    def db_size_bytes(self) -> int:
        """Return the SQLite file size in bytes (0 if missing).

        Surfaced in cycle log so operators can watch growth / verify
        that pruning is keeping pace with ingest.
        """
        try:
            return self.db_path.stat().st_size
        except (FileNotFoundError, OSError):
            return 0

    def maybe_vacuum(self, min_age_days: int = 30) -> bool:
        """VACUUM the DB if it hasn't been vacuumed in ``min_age_days``.

        VACUUM rewrites the file in place, reclaiming space freed by
        DELETEs and defragmenting B-trees.  Cheap on a small DB but
        holds an exclusive write lock — only do it occasionally.
        Tracks last run via the ``state`` k/v table.
        """
        last = self.get("last_vacuum_at")
        now = datetime.now(timezone.utc)
        if last:
            try:
                last_dt = datetime.fromisoformat(last)
                if (now - last_dt).total_seconds() < min_age_days * 86400:
                    return False
            except ValueError:
                pass  # corrupted value — vacuum anyway
        with self._conn() as c:
            c.execute("VACUUM")
        self.set("last_vacuum_at", now.isoformat())
        return True

    def prune_all(
        self,
        *,
        cycles_keep_last: int = 10_000,
        activity_cutoff_days: int = 90,
        profile_log_cutoff_days: int = 100,
        max_state_cutoff_days: int = 180,
    ) -> dict[str, int]:
        """Run all per-cycle prune passes.  Returns rows-deleted per table.

        Caller (``main.run_cycle``) invokes this once per cycle.  All four
        DELETEs together take low-millisecond time on a healthy DB.
        VACUUM runs separately via :meth:`maybe_vacuum` (heavier — gated
        by age).
        """
        return {
            "cycles": self.prune_cycles(keep_last=cycles_keep_last),
            "attacker_activity": self.prune_attacker_activity(cutoff_days=activity_cutoff_days),
            "attacker_activity_malformed": self.prune_malformed_attacker_activity(),
            "profile_emit_log": self.prune_attacker_profile_emit_log(cutoff_days=profile_log_cutoff_days),
            "object_max_state": self.prune_object_max_state(cutoff_days=max_state_cutoff_days),
            "campaign_artifacts": self.prune_campaign_artifacts(cutoff_days=max_state_cutoff_days),
        }

    # ----------------------------------------------------------------------
    # Cross-cycle label/score preservation (the V0 finding on pycti UPSERT overwriting scalar fields + the
    # 2026-05-21 live-find: pycti UPSERT silently overwrites scalar fields
    # across cycles; need connector-side memory of the highest-signal
    # emission to preserve it through low-signal re-emissions).
    # ----------------------------------------------------------------------

    def get_max_state_bulk(
        self,
        stix_ids: list[str],
    ) -> dict[str, dict]:
        """Look up the persisted max-signal state for a batch of STIX ids.

        Returns ``{stix_id: {max_score, labels, name, description}}`` for
        every id that has an existing row. Missing ids are absent from
        the result dict (caller treats as "no previous state").

        Bulk-fetches with ``WHERE stix_id IN (...)`` to avoid N+1
        roundtrips. The id list is chunked at ``_SQL_VAR_CHUNK`` so a
        large bundle can never exceed SQLite's bound-variable limit
        (the default ``SQLITE_MAX_VARIABLE_NUMBER`` is 999 on older
        builds, 32,766 on newer). An unchunked ``IN (...)`` over a
        runaway bundle raised ``OperationalError: too many SQL variables``
        every cycle and stalled ingestion (2026-07-19 → 08-04 outage).
        """
        import json
        if not stix_ids:
            return {}
        out: dict[str, dict] = {}
        with self._conn() as c:
            for i in range(0, len(stix_ids), self._SQL_VAR_CHUNK):
                chunk = stix_ids[i:i + self._SQL_VAR_CHUNK]
                placeholders = ",".join("?" for _ in chunk)
                cur = c.execute(
                    f"SELECT stix_id, max_score, labels_json, name, description "
                    f"FROM object_max_state WHERE stix_id IN ({placeholders})",
                    chunk,
                )
                for row in cur:
                    stix_id, max_score, labels_json, name, description = row
                    try:
                        labels = json.loads(labels_json) if labels_json else []
                    except Exception:
                        labels = []
                    out[stix_id] = {
                        "max_score": max_score,
                        "labels": labels,
                        "name": name,
                        "description": description,
                    }
        return out

    def upsert_max_state_bulk(
        self,
        updates: list[tuple[str, Optional[int], list[str], Optional[str], Optional[str]]],
    ) -> None:
        """Persist post-merge state for a batch of STIX ids.

        Each update tuple is
        ``(stix_id, max_score, labels_list, name, description)``.
        Uses a single transaction + ``INSERT OR REPLACE`` so the whole
        cycle's worth of updates lands or none of it does.
        """
        import json
        if not updates:
            return
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (stix_id, max_score, json.dumps(sorted(set(labels))), name, description, now)
            for (stix_id, max_score, labels, name, description) in updates
        ]
        with self._conn() as c:
            c.executemany(
                "INSERT OR REPLACE INTO object_max_state "
                "(stix_id, max_score, labels_json, name, description, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                rows,
            )

    # ----------------------------------------------------------------------
    # Attacker-profile rolling aggregates (see tpot2cti/attacker_profile.py).
    # ----------------------------------------------------------------------

    # Cap on each "sample_*_json" array length. Per the spec hard rules:
    # "Cap sample-list growth to 25 entries each by sorting by frequency
    # in the merge and trimming." Bigger lists become "and N more" markers
    # in the rendered Note body.
    _ATTACKER_SAMPLE_CAP = 25

    @staticmethod
    def _decode_json_list(blob: Optional[str]) -> list:
        import json
        if not blob:
            return []
        try:
            v = json.loads(blob)
            return v if isinstance(v, list) else []
        except Exception:
            return []

    @classmethod
    def _merge_counted_pairs(
        cls, existing: list, additions: list
    ) -> list:
        """Merge two lists of [key, count] (or [user, pass, count]) entries.

        Keys are matched by everything-except-the-trailing-count. Counts
        are summed. The result is sorted by count descending and trimmed
        to ``_ATTACKER_SAMPLE_CAP`` items. ``additions`` entries may be
        bare keys (no count) — in which case they contribute 1.
        """
        bucket: dict[tuple, int] = {}

        def _split(entry):
            if isinstance(entry, list) and entry and isinstance(entry[-1], int):
                return tuple(entry[:-1]), int(entry[-1])
            if isinstance(entry, list):
                return tuple(entry), 1
            return (str(entry),), 1

        for e in (existing or []):
            k, c = _split(e)
            bucket[k] = bucket.get(k, 0) + c
        for e in (additions or []):
            k, c = _split(e)
            bucket[k] = bucket.get(k, 0) + c

        items = sorted(bucket.items(), key=lambda kv: (-kv[1], kv[0]))
        items = items[:cls._ATTACKER_SAMPLE_CAP]
        # Re-encode as [key_parts..., count]
        return [list(k) + [c] for k, c in items]

    @classmethod
    def _merge_unique_list(
        cls, existing: list, additions: list
    ) -> list:
        """Union two flat lists, preserving order, capped at the sample cap."""
        out: list = []
        seen: set = set()
        for v in (existing or []) + list(additions or []):
            if v is None:
                continue
            key = v if isinstance(v, (str, int, float, bool)) else json_dumps_stable(v)
            if key in seen:
                continue
            seen.add(key)
            out.append(v)
            if len(out) >= cls._ATTACKER_SAMPLE_CAP:
                break
        return out

    def upsert_attacker_activity(self, session) -> None:
        """Merge one session's activity signals into the per-(ip, parser,
        sensor) row of ``attacker_activity``.

        Increments the counters, merges the sample collections (union /
        frequency-merged, both capped at ``_ATTACKER_SAMPLE_CAP``), and
        updates first_seen (min) / last_seen (max). Pulls geo / fingerprint
        fields off the first event when available.

        Called from ``main.run_cycle`` for every session in the cycle
        (see ``attacker_profile.update_activity_from_session`` which
        wraps this).
        """
        import json
        from datetime import datetime as _dt, timezone as _tz

        src_ip = getattr(session, "src_ip", None)
        parser_name = getattr(session, "event_type", None) or "Unknown"
        sensor = getattr(session, "sensor_hostname", None) or "unknown"
        if not src_ip:
            return
        # Defence in depth: this table is keyed on src_ip and is read back
        # as an address by attacker_profile, campaigns, the noisefloor
        # enricher and the credential Notes. A non-address key poisons all
        # of them silently. main.run_cycle rejects these before a session
        # is ever built (drop reason `src_ip_rejected`); this guard means a
        # future caller that skips that gate cannot re-introduce the rows.
        # 30 such rows — obfuscated Log4Shell payloads that h0neytr4p
        # reported as client addresses — accumulated here before the gate
        # existed. Canonicalize too, so 1.2.3.4 and ::ffff:1.2.3.4 don't
        # split one attacker across two rows GOING FORWARD. This does not
        # migrate rows already written in a non-canonical form: they are
        # valid addresses, so prune_malformed leaves them, and merging
        # would mean summing counters and unioning sample sets. Measured
        # on the live DB 2026-08-04: zero such rows, so there is nothing
        # to migrate. Revisit only if that count stops being zero.
        canon = canonical_ip(str(src_ip))
        if canon is None:
            logger.debug(
                f"attacker_activity: skipping non-address src_ip "
                f"{str(src_ip)[:80]!r} from parser={parser_name!r}"
            )
            return
        src_ip = canon[1]

        first_seen = session.first_seen.isoformat()
        last_seen = session.last_seen.isoformat()

        # Pull session counters
        auth_success_inc = 1 if getattr(session, "auth_success", False) else 0
        creds_list = list(getattr(session, "credentials_tried", []) or [])
        cmds_list = list(getattr(session, "commands", []) or [])
        hashes_list = list(getattr(session, "malware_hashes", []) or [])
        urls_list = list(getattr(session, "urls", []) or [])
        domains_list = list(getattr(session, "domains", []) or [])

        # Parser-specific extras from session.meta + first event
        meta = getattr(session, "meta", {}) or {}
        signatures_add: list = []
        if sig := meta.get("signature"):
            signatures_add.append(str(sig))
        mitre_add: list = list(meta.get("mitre_techniques") or [])
        dst_ports_add: list = sorted(int(p) for p in (getattr(session, "dst_ports", set()) or set()) if p is not None)

        # Geo + fingerprints from the first event (parsers populate these
        # consistently per BaseParser._populate_geoip).
        first_event = (getattr(session, "events", []) or [None])[0]
        geo_country = getattr(first_event, "src_country_code", None) if first_event else None
        geo_asn = getattr(first_event, "src_asn", None) if first_event else None
        geo_as_org = getattr(first_event, "src_as_org", None) if first_event else None
        hassh_val = getattr(session, "hassh", None)
        ssh_ver_val = getattr(session, "ssh_version", None)

        # Render credential / command additions as count-bearing entries.
        # credentials: [[user, pass, count], ...] ; commands: [[cmd, count], ...]
        creds_add: list = []
        creds_bucket: dict[tuple, int] = {}
        for u, p in creds_list:
            key = (str(u), str(p))
            creds_bucket[key] = creds_bucket.get(key, 0) + 1
        for (u, p), c in creds_bucket.items():
            creds_add.append([u, p, c])

        cmds_add: list = []
        cmd_bucket: dict[str, int] = {}
        for cmd in cmds_list:
            cs = str(cmd)
            cmd_bucket[cs] = cmd_bucket.get(cs, 0) + 1
        for cs, c in cmd_bucket.items():
            cmds_add.append([cs, c])

        with self._conn() as c:
            row = c.execute(
                "SELECT sessions_count, events_count, auth_success_count, "
                "credentials_count, commands_count, malware_drop_count, "
                "first_seen, last_seen, sample_credentials_json, "
                "sample_commands_json, sample_hashes_json, sample_urls_json, "
                "sample_domains_json, sample_signatures_json, "
                "sample_mitre_json, sample_dst_ports_json, "
                "geoip_country, geoip_asn, geoip_as_org, hassh, ssh_version "
                "FROM attacker_activity WHERE src_ip = ? AND parser = ? AND sensor = ?",
                (src_ip, parser_name, sensor),
            ).fetchone()

            if row is None:
                merged_creds = self._merge_counted_pairs([], creds_add)
                merged_cmds = self._merge_counted_pairs([], cmds_add)
                merged_hashes = self._merge_unique_list([], hashes_list)
                merged_urls = self._merge_unique_list([], urls_list)
                merged_domains = self._merge_unique_list([], domains_list)
                merged_sigs = self._merge_unique_list([], signatures_add)
                merged_mitre = self._merge_unique_list([], mitre_add)
                merged_ports = self._merge_unique_list([], dst_ports_add)
                c.execute(
                    "INSERT INTO attacker_activity ("
                    "src_ip, parser, sensor, sessions_count, events_count, "
                    "auth_success_count, credentials_count, commands_count, "
                    "malware_drop_count, first_seen, last_seen, "
                    "sample_credentials_json, sample_commands_json, "
                    "sample_hashes_json, sample_urls_json, sample_domains_json, "
                    "sample_signatures_json, sample_mitre_json, "
                    "sample_dst_ports_json, geoip_country, geoip_asn, "
                    "geoip_as_org, hassh, ssh_version"
                    ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        src_ip, parser_name, sensor,
                        1,
                        int(getattr(session, "event_count", len(getattr(session, "events", []) or []))),
                        auth_success_inc,
                        len(creds_list),
                        len(cmds_list),
                        len(hashes_list),
                        first_seen, last_seen,
                        json.dumps(merged_creds),
                        json.dumps(merged_cmds),
                        json.dumps(merged_hashes),
                        json.dumps(merged_urls),
                        json.dumps(merged_domains),
                        json.dumps(merged_sigs),
                        json.dumps(merged_mitre),
                        json.dumps(merged_ports),
                        geo_country,
                        int(geo_asn) if geo_asn is not None else None,
                        geo_as_org,
                        hassh_val,
                        ssh_ver_val,
                    ),
                )
                return

            (
                sessions_count, events_count, auth_success_count,
                credentials_count, commands_count, malware_drop_count,
                old_first_seen, old_last_seen, old_creds, old_cmds,
                old_hashes, old_urls, old_domains, old_sigs, old_mitre,
                old_ports, old_country, old_asn, old_as_org,
                old_hassh, old_ssh_ver,
            ) = row

            merged_creds = self._merge_counted_pairs(
                self._decode_json_list(old_creds), creds_add,
            )
            merged_cmds = self._merge_counted_pairs(
                self._decode_json_list(old_cmds), cmds_add,
            )
            merged_hashes = self._merge_unique_list(
                self._decode_json_list(old_hashes), hashes_list,
            )
            merged_urls = self._merge_unique_list(
                self._decode_json_list(old_urls), urls_list,
            )
            merged_domains = self._merge_unique_list(
                self._decode_json_list(old_domains), domains_list,
            )
            merged_sigs = self._merge_unique_list(
                self._decode_json_list(old_sigs), signatures_add,
            )
            merged_mitre = self._merge_unique_list(
                self._decode_json_list(old_mitre), mitre_add,
            )
            merged_ports = self._merge_unique_list(
                self._decode_json_list(old_ports), dst_ports_add,
            )

            new_first = old_first_seen if old_first_seen <= first_seen else first_seen
            new_last = old_last_seen if old_last_seen >= last_seen else last_seen

            c.execute(
                "UPDATE attacker_activity SET "
                "sessions_count = ?, events_count = ?, auth_success_count = ?, "
                "credentials_count = ?, commands_count = ?, malware_drop_count = ?, "
                "first_seen = ?, last_seen = ?, "
                "sample_credentials_json = ?, sample_commands_json = ?, "
                "sample_hashes_json = ?, sample_urls_json = ?, sample_domains_json = ?, "
                "sample_signatures_json = ?, sample_mitre_json = ?, "
                "sample_dst_ports_json = ?, geoip_country = ?, geoip_asn = ?, "
                "geoip_as_org = ?, hassh = ?, ssh_version = ? "
                "WHERE src_ip = ? AND parser = ? AND sensor = ?",
                (
                    sessions_count + 1,
                    events_count + int(getattr(session, "event_count", len(getattr(session, "events", []) or []))),
                    auth_success_count + auth_success_inc,
                    credentials_count + len(creds_list),
                    commands_count + len(cmds_list),
                    malware_drop_count + len(hashes_list),
                    new_first, new_last,
                    json.dumps(merged_creds),
                    json.dumps(merged_cmds),
                    json.dumps(merged_hashes),
                    json.dumps(merged_urls),
                    json.dumps(merged_domains),
                    json.dumps(merged_sigs),
                    json.dumps(merged_mitre),
                    json.dumps(merged_ports),
                    geo_country or old_country,
                    int(geo_asn) if geo_asn is not None else old_asn,
                    geo_as_org or old_as_org,
                    hassh_val or old_hassh,
                    ssh_ver_val or old_ssh_ver,
                    src_ip, parser_name, sensor,
                ),
            )

    @staticmethod
    def _row_to_attacker_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        # Decode the JSON columns into Python lists for callers.
        for k in (
            "sample_credentials_json", "sample_commands_json",
            "sample_hashes_json", "sample_urls_json",
            "sample_domains_json", "sample_signatures_json",
            "sample_mitre_json", "sample_dst_ports_json",
        ):
            try:
                import json
                d[k] = json.loads(d.get(k) or "[]")
            except Exception:
                d[k] = []
        return d

    def get_attacker_activity(self, src_ip: str) -> list[dict]:
        """Return all per-(parser, sensor) rows for one attacker IP.

        Used by the profile renderer to aggregate across parsers and
        sensors. Empty list when the IP is unknown.
        """
        with self._conn() as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                "SELECT * FROM attacker_activity WHERE src_ip = ? "
                "ORDER BY parser, sensor",
                (src_ip,),
            ).fetchall()
        return [self._row_to_attacker_dict(r) for r in rows]

    def get_attacker_activity_window(
        self, start_iso: str, end_iso: str
    ) -> dict[str, list[dict]]:
        """Return ``{src_ip: [rows]}`` for every IP with activity in
        ``[start_iso, end_iso]``.

        The window predicate is ``last_seen >= start AND first_seen <= end``,
        i.e. the IP had at least one row whose lifespan overlapped the
        window. Used by the daily/weekly aggregators in attacker_profile.
        """
        with self._conn() as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                "SELECT * FROM attacker_activity "
                "WHERE last_seen >= ? AND first_seen <= ? "
                "ORDER BY src_ip, parser, sensor",
                (start_iso, end_iso),
            ).fetchall()
        out: dict[str, list[dict]] = {}
        for r in rows:
            d = self._row_to_attacker_dict(r)
            out.setdefault(d["src_ip"], []).append(d)
        return out

    def get_active_attackers_since(self, since_iso: str) -> list[str]:
        """Return the distinct src_ip set with activity since ``since_iso``.

        Used by the per-cycle attacker-profile emitter to find which IPs
        warrant a live-profile refresh this cycle.
        """
        with self._conn() as c:
            rows = c.execute(
                "SELECT DISTINCT src_ip FROM attacker_activity "
                "WHERE last_seen >= ? ORDER BY src_ip",
                (since_iso,),
            ).fetchall()
        return [r[0] for r in rows]

    # ──────────────────────────────────────────────────────────────────
    # Campaign artifacts (shared-IoC grouping — see tpot2cti/campaigns.py)
    # ──────────────────────────────────────────────────────────────────

    def record_campaign_artifact(
        self,
        *,
        artifact_key: str,
        src_ip: str,
        artifact_type: str,
        artifact_value: str,
        display: str,
        seen_iso: str,
    ) -> None:
        """Upsert one (artifact_key, src_ip) observation.

        first_seen is preserved on conflict; last_seen advances; ``emitted``
        is left untouched so an already-published member stays published.
        """
        with self._conn() as c:
            c.execute(
                "INSERT INTO campaign_artifacts ("
                "  artifact_key, src_ip, artifact_type, artifact_value, "
                "  display, first_seen, last_seen, emitted"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, 0) "
                "ON CONFLICT(artifact_key, src_ip) DO UPDATE SET "
                "  last_seen = excluded.last_seen, "
                "  display   = excluded.display",
                (
                    artifact_key, src_ip, artifact_type, artifact_value,
                    display, seen_iso, seen_iso,
                ),
            )

    def get_campaign_artifact_rows(self, artifact_key: str) -> list[dict]:
        """Return all member rows for one artifact_key (dicts), IP-sorted."""
        with self._conn() as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                "SELECT * FROM campaign_artifacts WHERE artifact_key = ? "
                "ORDER BY first_seen, src_ip",
                (artifact_key,),
            ).fetchall()
        return [dict(r) for r in rows]

    def mark_campaign_members_emitted(
        self, artifact_key: str, src_ips: list[str]
    ) -> None:
        """Flip ``emitted=1`` for the given (artifact_key, src_ip) rows."""
        if not src_ips:
            return
        with self._conn() as c:
            c.executemany(
                "UPDATE campaign_artifacts SET emitted = 1 "
                "WHERE artifact_key = ? AND src_ip = ?",
                [(artifact_key, ip) for ip in src_ips],
            )

    def record_attacker_profile_emitted(
        self, src_ip: str, cadence: str, last_seen_seen: str
    ) -> None:
        """Record that we emitted an attacker-profile Note for this IP /
        cadence with the given activity ``last_seen`` value.

        Subsequent emissions of the same cadence can compare against this
        to skip IPs that haven't accumulated new activity.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                "INSERT INTO attacker_profile_emit_log "
                "(src_ip, cadence, last_seen_seen, emitted_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(src_ip, cadence) DO UPDATE SET "
                "last_seen_seen = excluded.last_seen_seen, "
                "emitted_at = excluded.emitted_at",
                (src_ip, cadence, last_seen_seen, now),
            )

    def get_last_attacker_profile_emit(
        self, src_ip: str, cadence: str
    ) -> Optional[str]:
        """Return the last-emitted ``last_seen_seen`` for (IP, cadence),
        or None if we've never emitted this combination.
        """
        with self._conn() as c:
            row = c.execute(
                "SELECT last_seen_seen FROM attacker_profile_emit_log "
                "WHERE src_ip = ? AND cadence = ?",
                (src_ip, cadence),
            ).fetchone()
        return row[0] if row else None


def json_dumps_stable(v) -> str:
    """Stable JSON serialization for use as a dict-set key."""
    import json
    try:
        return json.dumps(v, sort_keys=True, default=str)
    except Exception:
        return repr(v)


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

        # record_cycle_failure stamps last_cycle_error and the row.
        cid2 = s.start_cycle()
        s.record_cycle_failure(cid2, "kaboom: test failure", duration_seconds=0.5)
        assert s.get("last_cycle_error") == "kaboom: test failure"
        rows = s.recent_cycles(2)
        # newest first — should include the failed row
        assert any(r["success"] == 0 for r in rows), "failure row not recorded"
        print("OK: record_cycle_failure stamps state + cycle_log row")

        # ── attacker_activity smoke ──
        # Build minimal session-like stub. We avoid importing AttackSession
        # here to keep the state module dependency-free of parsers.
        from datetime import datetime as _dt2, timezone as _tz2, timedelta as _td3

        class _SS:
            def __init__(self, src_ip, parser, sensor, first, last,
                         events_n=1, auth=False, creds=None, cmds=None,
                         hashes=None, urls=None, domains=None,
                         country="US", asn=64500, as_org="ExampleNet",
                         hassh=None, ssh_version=None, dst_ports=None,
                         signature=None, mitre=None):
                self.src_ip = src_ip
                self.event_type = parser
                self.sensor_hostname = sensor
                self.first_seen = first
                self.last_seen = last
                self.event_count = events_n
                self.auth_success = auth
                self.credentials_tried = creds or []
                self.commands = cmds or []
                self.malware_hashes = hashes or []
                self.urls = urls or []
                self.domains = domains or []
                self.hassh = hassh
                self.ssh_version = ssh_version
                self.dst_ports = set(dst_ports or [])
                self.meta = {}
                if signature:
                    self.meta["signature"] = signature
                if mitre:
                    self.meta["mitre_techniques"] = list(mitre)
                # Fake event[0] with geo fields
                class _E:
                    src_country_code = country
                    src_asn = asn
                    src_as_org = as_org
                self.events = [_E()]

        t0 = _dt2.now(_tz2.utc) - _td3(hours=2)
        t1 = t0 + _td3(minutes=10)
        t2 = t0 + _td3(minutes=30)

        # First session — Cowrie, with creds + commands.
        s.upsert_attacker_activity(_SS(
            "203.0.113.7", "Cowrie", "tpot01", t0, t1, events_n=5,
            auth=True, creds=[("root", "root"), ("admin", "admin")],
            cmds=["uname -a", "cat /etc/passwd"],
            hashes=["a" * 64], urls=["http://evil/x.sh"], domains=["evil"],
            hassh="hassh1", ssh_version="SSH-2.0-Foo", dst_ports=[22],
        ))
        # Second session same IP / parser / sensor — incremental merge.
        s.upsert_attacker_activity(_SS(
            "203.0.113.7", "Cowrie", "tpot01", t1, t2, events_n=3,
            auth=False, creds=[("root", "root"), ("oracle", "oracle")],
            cmds=["uname -a"], hassh="hassh1", dst_ports=[22],
        ))
        # Third session different parser, same IP.
        s.upsert_attacker_activity(_SS(
            "203.0.113.7", "Suricata", "tpot01", t1, t2, events_n=1,
            signature="ET SCAN Nmap", mitre=["T1046"],
        ))
        # Different IP, just to verify isolation.
        s.upsert_attacker_activity(_SS(
            "198.51.100.9", "Honeytrap", "tpot01", t0, t1, events_n=1,
            dst_ports=[23, 2323],
        ))

        rows = s.get_attacker_activity("203.0.113.7")
        assert len(rows) == 2, f"expected 2 parser/sensor rows, got {len(rows)}"
        cowrie_row = next(r for r in rows if r["parser"] == "Cowrie")
        assert cowrie_row["sessions_count"] == 2
        assert cowrie_row["events_count"] == 8
        assert cowrie_row["auth_success_count"] == 1
        assert cowrie_row["credentials_count"] == 4
        assert cowrie_row["commands_count"] == 3
        # ("root","root") seen twice, ("admin","admin") once, ("oracle","oracle") once
        creds = cowrie_row["sample_credentials_json"]
        # First entry is the most frequent
        assert creds[0][:2] == ["root", "root"] and creds[0][2] == 2, creds
        assert any(e[:2] == ["admin", "admin"] for e in creds), creds
        cmds = cowrie_row["sample_commands_json"]
        assert cmds[0] == ["uname -a", 2], cmds
        assert cowrie_row["geoip_country"] == "US"
        assert cowrie_row["hassh"] == "hassh1"
        print(f"OK: attacker_activity rows merged: cowrie sessions={cowrie_row['sessions_count']} "
              f"events={cowrie_row['events_count']} creds_sample={creds[:2]}")

        # Window query
        window_start = (t0 - _td3(minutes=1)).isoformat()
        window_end = (t2 + _td3(minutes=1)).isoformat()
        win = s.get_attacker_activity_window(window_start, window_end)
        assert "203.0.113.7" in win and "198.51.100.9" in win, list(win.keys())
        print(f"OK: window query returned {len(win)} attacker IP(s)")

        # active_since
        active = s.get_active_attackers_since((t0 - _td3(seconds=1)).isoformat())
        assert "203.0.113.7" in active and "198.51.100.9" in active
        print(f"OK: get_active_attackers_since → {sorted(active)}")

        # emit log idempotency
        ls = cowrie_row["last_seen"]
        assert s.get_last_attacker_profile_emit("203.0.113.7", "live") is None
        s.record_attacker_profile_emitted("203.0.113.7", "live", ls)
        assert s.get_last_attacker_profile_emit("203.0.113.7", "live") == ls
        # second call updates rather than duplicates
        s.record_attacker_profile_emitted("203.0.113.7", "live", ls)
        print("OK: attacker_profile_emit_log records + upserts")

        print("\nSmoke test passed.")
    finally:
        Path(tmp).unlink(missing_ok=True)
        Path(tmp + "-wal").unlink(missing_ok=True)
        Path(tmp + "-shm").unlink(missing_ok=True)
