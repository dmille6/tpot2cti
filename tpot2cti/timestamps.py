"""Stored-timestamp comparison and the one-time migration that makes it valid.

WHY THIS MODULE EXISTS

Timestamps are persisted as TEXT, and the comparisons that decide what an
analyst sees happen in SQL, which compares TEXT and cannot call a Python
helper:

    WHERE last_seen >= ? AND first_seen <= ?     state: window query
    SELECT MIN(first_seen), MAX(last_seen)       state: campaign bounds
    MAX(u.last_seen) ... ORDER BY last_seen DESC credentials: newest-first

Lexicographic order only equals chronological order when every value carries
the same UTC offset. Rows written before `BaseParser._parse_timestamp`
normalised keep their source offset, so a stored "10:30+02:00" (= 08:30Z)
sorts AFTER "09:00+00:00" while being half an hour earlier.

The fix is to normalise the DATA, once, rather than to rewrite every
comparison — there are more comparisons than there are columns, several are
in SQL, and the ones that get it wrong do so silently.

This lives in its own module because BOTH `state.py` and `credential_store.py`
need it against SEPARATE databases. A copy in each is how the two drift, and a
drifted comparison is invisible until it returns the wrong row.
"""
from __future__ import annotations

import datetime
import logging
import sqlite3
from typing import Mapping, Optional, Sequence

logger = logging.getLogger(__name__)


def as_instant(value) -> Optional[datetime.datetime]:
    """Parse a stored timestamp for COMPARISON, or None if unusable.

    Always returns an aware UTC datetime, never a naive one: Python raises
    TypeError comparing naive to aware, and a mix is exactly what a
    part-migrated database contains.

    Every failure returns None rather than raising. This runs inside a
    migration that runs inside `__init__`, so an exception here does not fail
    one row — it stops the process from starting, on every retry, forever.
    OverflowError is the live example: "0001-01-01T00:00:00+01:00" converts to
    a year-zero instant and raises.
    """
    if not value:
        return None
    try:
        raw = str(value)
        if raw.endswith(("Z", "z")):
            raw = raw[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(raw)
        return (dt.replace(tzinfo=datetime.timezone.utc) if dt.tzinfo is None
                else dt.astimezone(datetime.timezone.utc))
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def earlier(a, b):
    """The earlier of two stored timestamps, preserving the original string.

    A value that will not parse never WINS. Junk taking a min()/max() pins the
    bound to a string with no chronological meaning, and every later
    comparison against it is arbitrary. Raw string comparison is reserved for
    when BOTH values are unusable, where no chronological answer exists and
    the only requirement is to be stable.
    """
    if not a:
        return b
    if not b:
        return a
    ia, ib = as_instant(a), as_instant(b)
    if ia is None and ib is None:
        return a if str(a) <= str(b) else b
    if ia is None:
        return b
    if ib is None:
        return a
    return a if ia <= ib else b


def later(a, b):
    """The later of two stored timestamps. Same null/unparseable rule."""
    if not a:
        return b
    if not b:
        return a
    ia, ib = as_instant(a), as_instant(b)
    if ia is None and ib is None:
        return a if str(a) >= str(b) else b
    if ia is None:
        return b
    if ib is None:
        return a
    return a if ia >= ib else b


def normalise_timestamp_columns(
    c: sqlite3.Connection,
    tables: Mapping[str, Sequence[str]],
    schema_version: int,
    *,
    label: str = "db",
) -> int:
    """Rewrite persisted timestamps to UTC, ONCE, under an exclusive lock.

    CONCURRENCY is the whole reason this is not three lines. Several processes
    open these files. An earlier version read the table and then wrote row by
    row on an autocommit connection, so a writer committing in between had its
    newer value overwritten by this migration's stale snapshot — silent data
    loss caused by the fix for a data-correctness bug.

    BEGIN IMMEDIATE takes the write lock BEFORE the read, the version check
    happens under that lock, and the rewrite plus the version bump commit
    together. A second process either waits and then sees the new version, or
    is excluded and leaves the rows alone.

    Unparseable values are SKIPPED, not rewritten: a migration must not
    destroy data it cannot interpret.
    """
    if c.execute("PRAGMA user_version").fetchone()[0] >= schema_version:
        return 0
    changed = 0
    c.execute("BEGIN IMMEDIATE")
    try:
        # Re-check under the lock: another process may have migrated while we
        # were waiting for it.
        if c.execute("PRAGMA user_version").fetchone()[0] >= schema_version:
            if c.in_transaction:
                c.execute("ROLLBACK")
            return 0
        for table, cols in tables.items():
            try:
                rows = c.execute(
                    f"SELECT rowid, {', '.join(cols)} FROM {table}").fetchall()
            except sqlite3.OperationalError:
                # Only "no such table" is an expected miss. Treating any
                # sqlite error as an absent table would let an operational
                # failure count as a successful migration.
                continue
            for row in rows:
                rowid, values = row[0], row[1:]
                fixed = []
                for v in values:
                    dt = as_instant(v)
                    fixed.append(dt.isoformat() if dt is not None else v)
                if list(fixed) != list(values):
                    c.execute(
                        f"UPDATE {table} SET "
                        + ", ".join(f"{col} = ?" for col in cols)
                        + " WHERE rowid = ?",
                        (*fixed, rowid),
                    )
                    changed += 1
        c.execute(f"PRAGMA user_version = {schema_version}")
        c.execute("COMMIT")
    except Exception:
        # SQLite may already have rolled back on the error; an unconditional
        # ROLLBACK then raises "cannot rollback - no transaction is active",
        # REPLACING the real failure as the exception that propagates.
        if c.in_transaction:
            try:
                c.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        raise
    if changed:
        logger.info(
            f"{label}: normalised persisted timestamps to UTC on {changed} "
            f"row(s) — legacy offset-bearing values sort wrongly under the "
            f"TEXT comparisons used in SQL"
        )
    return changed
