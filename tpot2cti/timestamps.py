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

#: Rows held in memory at once while migrating. The live tables run to
#: millions of rows; this is what keeps a one-time migration from
#: allocating GBs of tuples under the write lock.
_BATCH = 10_000


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


def canonical(value):
    """The one spelling every writer in this codebase produces: isoformat().

    All four producers of these columns call `.isoformat()` — credential_store
    (both public entry points), state's activity bounds, campaigns' artifact
    bounds, profile emission. So the canonical form is T-separated, UTC,
    "+00:00". Normalising TO that matches what the next write will look like,
    which is the point: TEXT ordering is only meaningful when migrated rows
    and future rows agree.

    An earlier version of this preserved whatever separator the input had.
    That was a weaker fix arrived at from a bad measurement -- a test that
    bypassed the public API and handed a datetime to the private _upsert, so
    sqlite3's adapter wrote a SPACE separator that no production path
    produces. Preserving it would have frozen legacy rows in a spelling that
    sorts before every future write (space is chr(32), "T" is chr(84)),
    forever.

    Unparseable values come back unchanged.
    """
    dt = as_instant(value)
    return value if dt is None else dt.isoformat()


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
                # EXHAUSTIVE, in bounded batches.
                #
                # A WHERE filter selecting "obviously wrong" spellings lived
                # here and UNDER-SELECTED: "09:00:00.1+00:00",
                # "09:00:00,9+00:00" and "095900+00:00" all end "+00:00" with
                # a "T" at position 11, pass any such heuristic, and are still
                # not canonical — and "…,9+00:00" sorts BEFORE "….100000+00:00"
                # while being later. A filter that misses a row is worse than
                # no filter: the version gets stamped and nothing revisits it.
                # Canonicality is decided by canonical(), which cannot be
                # expressed in SQL, so every row must be offered to it.
                #
                # What actually mattered was MEMORY: 7.7M credential rows
                # measured live, fetchall()'d into Python tuples while holding
                # the write lock. Paging by rowid bounds that to _BATCH rows.
                # rowid is stable under UPDATE, so paging and updating cannot
                # interfere — which iterating one open cursor while updating
                # its own table would.
                # last_rowid starts as None, not -1: SQLite rowids may be
                # NEGATIVE (they can be assigned explicitly), and a -1
                # sentinel silently skips every such row while the migration
                # goes on to stamp itself complete — so nothing ever revisits
                # them. The first page is therefore unbounded.
                last_rowid = None
                select = f"SELECT rowid, {', '.join(cols)} FROM {table} "
                while True:
                    if last_rowid is None:
                        batch = c.execute(
                            select + f"ORDER BY rowid LIMIT {_BATCH}").fetchall()
                    else:
                        batch = c.execute(
                            select + f"WHERE rowid > ? ORDER BY rowid LIMIT {_BATCH}",
                            (last_rowid,),
                        ).fetchall()
                    if not batch:
                        break
                    last_rowid = batch[-1][0]
                    for row in batch:
                        rowid, values = row[0], row[1:]
                        fixed = [canonical(v) for v in values]
                        if list(fixed) != list(values):
                            c.execute(
                                f"UPDATE {table} SET "
                                + ", ".join(f"{col} = ?" for col in cols)
                                + " WHERE rowid = ?",
                                (*fixed, rowid),
                            )
                            changed += 1
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
