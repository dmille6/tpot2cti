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


def _normalised_like(value):
    """UTC-normalise `value`, KEEPING its date/time separator.

    Not cosmetic. sqlite3's datetime adapter stores "2026-09-16 08:30:00+00:00"
    with a SPACE; `datetime.isoformat()` emits "T". Space is chr(32) and "T" is
    chr(84), so under the TEXT comparison these columns are sorted by, EVERY
    space-separated value sorts before EVERY T-separated one, whatever the
    actual instants are.

    Rewriting a legacy row with "T" while its neighbours keep a space
    therefore corrupts exactly the ordering this migration exists to repair.
    Caught by running the credential store's own writer rather than a
    hand-built fixture — the convention is the adapter's, not the code's.

    Unparseable values come back unchanged.
    """
    dt = as_instant(value)
    if dt is None:
        return value
    raw = str(value)
    sep = " " if (len(raw) > 10 and raw[10] == " ") else "T"
    return dt.isoformat(sep=sep)


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
        incomplete = False
        for table, cols in tables.items():
            try:
                # Only CANDIDATE rows, and streamed rather than materialised.
                #
                # Measured on the live host 2026-09-16: credential_usage has
                # 4,495,337 rows and credential_pairs 3,230,280, and ZERO of
                # them are legacy — every value is already "+00:00". A
                # fetchall() over 7.7M rows to discover there is nothing to do
                # means GBs of Python tuples built while holding the write
                # lock that the credentials writer needs.
                #
                # A value already ending in "+00:00" is already normalised, so
                # anything else is the candidate set. That is sound rather
                # than merely fast: a "Z" suffix, a non-UTC offset and a naive
                # value all fail the test and get selected; and among values
                # that all end in "+00:00", lexicographic order already equals
                # chronological order, which is the property being restored.
                where = " OR ".join(f"{col} NOT LIKE '%+00:00'" for col in cols)
                # fetchall() on the CANDIDATE set, which is bounded and
                # usually empty — not on the table. Iterating the cursor
                # instead would be worse, not better: the loop below UPDATEs
                # the same table it is reading, and SQLite does not define
                # what an open SELECT cursor sees when its table is modified
                # underneath it. Tried that first; it silently skipped the
                # row it was supposed to fix.
                rows = c.execute(
                    f"SELECT rowid, {', '.join(cols)} FROM {table} "
                    f"WHERE {where}").fetchall()
            except sqlite3.OperationalError as e:
                # "no such table" is an expected miss — a schema version that
                # simply lacks it. ANY OTHER operational failure means this
                # table was not migrated, and stamping the version anyway
                # would mark an incomplete migration permanently complete:
                # the rows stay wrong and nothing ever retries them. Skip the
                # table, remember, and leave the version alone so the next
                # open tries again.
                if "no such table" not in str(e).lower():
                    logger.warning(
                        f"{label}: could not read {table} during timestamp "
                        f"normalisation ({e}); leaving schema version "
                        f"unstamped so this retries on next open"
                    )
                    incomplete = True
                continue
            for row in rows:
                rowid, values = row[0], row[1:]
                fixed = []
                for v in values:
                    fixed.append(_normalised_like(v))
                if list(fixed) != list(values):
                    c.execute(
                        f"UPDATE {table} SET "
                        + ", ".join(f"{col} = ?" for col in cols)
                        + " WHERE rowid = ?",
                        (*fixed, rowid),
                    )
                    changed += 1
        if not incomplete:
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
