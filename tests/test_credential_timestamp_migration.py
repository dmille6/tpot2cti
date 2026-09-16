"""CredentialStore has its OWN database, so CycleState's migration can't reach it.

`get_ip_credentials` does `MAX(u.last_seen)` and `ORDER BY last_seen DESC` — both
lexicographic. A row written before `_parse_timestamp` normalised keeps its
source offset, so a legacy "10:30+02:00" (= 08:30Z) sorts ahead of a genuinely
newer "09:00+00:00" and the "most recent credentials" an analyst reads are the
wrong ones.

Found by codex reviewing #45, which fixed the same class of bug in state.py
and left this database untouched.
"""
from __future__ import annotations

from datetime import datetime, timezone

from tpot2cti.credential_store import CredentialStore


def _seed(store, user, ts):
    with store._conn() as c:
        store._upsert(
            c, username=user, password="pw", attacker_ip="203.0.113.44",
            honeypot_name="s1", honeypot_type="Cowrie", service="ssh",
            port=22, ts=ts, success=False, country="DE", asn=64512, org="x",
        )


def test_newest_first_ordering_survives_a_legacy_offset_row(tmp_path):
    db = str(tmp_path / "creds.db")
    store = CredentialStore(db_path=db)

    _seed(store, "older", datetime(2026, 9, 16, 8, 30, tzinfo=timezone.utc))
    _seed(store, "newer", datetime(2026, 9, 16, 9, 0, tzinfo=timezone.utc))

    # Rewrite the OLDER row to its pre-normalisation spelling and reset the
    # version, i.e. a database from before this migration existed.
    with store._conn() as c:
        c.execute("UPDATE credential_usage SET first_seen = ?, last_seen = ? "
                  "WHERE credential_id IN (SELECT credential_id FROM "
                  "credential_pairs WHERE username = 'older')",
                  ("2026-09-16 10:30:00+02:00", "2026-09-16 10:30:00+02:00"))
        c.execute("PRAGMA user_version = 0")
    store.close()

    reopened = CredentialStore(db_path=db)
    rows = reopened.get_ip_credentials("203.0.113.44")
    assert rows, "guard: the fixture must return credentials at all"
    assert rows[0]["username"] == "newer", (
        f"newest-first returned {rows[0]['username']!r} — the legacy "
        f"'+02:00' row (08:30Z) outsorted a genuinely newer 09:00Z row"
    )


def test_the_credential_migration_is_one_time_and_spares_junk(tmp_path):
    db = str(tmp_path / "creds.db")
    store = CredentialStore(db_path=db)
    _seed(store, "u", datetime(2026, 9, 16, 8, tzinfo=timezone.utc))
    with store._conn() as c:
        c.execute("UPDATE credential_usage SET first_seen = ?", ("not-a-date",))
        c.execute("PRAGMA user_version = 0")
    store.close()

    a = CredentialStore(db_path=db)
    first_a = a._conn_obj.execute(
        "SELECT first_seen, last_seen FROM credential_usage").fetchone()
    ver = a._conn_obj.execute("PRAGMA user_version").fetchone()[0]
    a.close()

    b = CredentialStore(db_path=db)
    first_b = b._conn_obj.execute(
        "SELECT first_seen, last_seen FROM credential_usage").fetchone()
    b.close()

    assert tuple(first_a) == tuple(first_b), "migration is not idempotent"
    assert first_a[0] == "not-a-date", "an unparseable value was destroyed"
    assert first_a[1].endswith("+00:00"), "the parseable column was not fixed"
    assert ver == CredentialStore._SCHEMA_VERSION


def test_the_pairs_table_is_migrated_too(tmp_path):
    """credential_pairs carries the same columns and had NO coverage.

    codex removed that table from the migration and both existing tests still
    passed — they only ever looked at credential_usage.
    """
    from datetime import datetime, timezone
    db = str(tmp_path / "creds.db")
    store = CredentialStore(db_path=db)
    _seed(store, "u", datetime(2026, 9, 16, 8, 30, tzinfo=timezone.utc))
    with store._conn() as c:
        c.execute("UPDATE credential_pairs SET first_seen = ?, last_seen = ?",
                  ("2026-09-16 10:30:00+02:00", "2026-09-16 10:30:00+02:00"))
        c.execute("PRAGMA user_version = 0")
    store.close()

    reopened = CredentialStore(db_path=db)
    first, last = reopened._conn_obj.execute(
        "SELECT first_seen, last_seen FROM credential_pairs").fetchone()
    reopened.close()
    assert first.endswith("+00:00"), f"credential_pairs.first_seen not migrated: {first}"
    assert last.endswith("+00:00"), f"credential_pairs.last_seen not migrated: {last}"
    assert datetime.fromisoformat(first) == datetime(
        2026, 9, 16, 8, 30, tzinfo=timezone.utc), "normalisation moved the instant"


def test_an_unreadable_table_leaves_the_version_unstamped(tmp_path):
    """A migration that could not finish must not mark itself finished.

    Skipping a table on an operational error and stamping the version anyway
    makes an incomplete migration permanently complete: the rows stay wrong
    and nothing ever retries. Only "no such table" is an expected miss.
    """
    import sqlite3
    from tpot2cti.timestamps import normalise_timestamp_columns

    db = tmp_path / "x.db"
    c = sqlite3.connect(db, isolation_level=None)
    c.execute("CREATE TABLE present (first_seen TEXT, last_seen TEXT)")
    c.execute("INSERT INTO present VALUES (?, ?)",
              ("2026-09-16 10:30:00+02:00", "2026-09-16 10:30:00+02:00"))

    # The table must EXIST for this to be a genuine operational failure —
    # a missing table raises "no such table", which is an expected miss and
    # correctly does NOT block stamping. My first version of this fixture got
    # that backwards and the test failed for the wrong reason.
    c.execute("CREATE TABLE present2 (other TEXT)")
    normalise_timestamp_columns(
        c, {"present": ("first_seen", "last_seen"),
            "present2": ("nope",)},          # no such COLUMN, not table
        1, label="t")
    assert c.execute("PRAGMA user_version").fetchone()[0] == 0, (
        "version was stamped despite a table that could not be read — the "
        "migration can now never retry"
    )
    # The readable table is still fixed — a skipped table must not abandon
    # the work already done.
    got = c.execute("SELECT first_seen FROM present").fetchone()[0]
    assert got.endswith("+00:00"), f"readable table not migrated: {got}"

    # ...and a clean re-run stamps it.
    normalise_timestamp_columns(c, {"present": ("first_seen", "last_seen")}, 1, label="t")
    assert c.execute("PRAGMA user_version").fetchone()[0] == 1

    # A genuinely ABSENT table is an expected miss and must NOT block stamping.
    d = sqlite3.connect(tmp_path / "y.db", isolation_level=None)
    d.execute("CREATE TABLE present (first_seen TEXT, last_seen TEXT)")
    normalise_timestamp_columns(
        d, {"present": ("first_seen", "last_seen"),
            "never_created": ("first_seen",)}, 1, label="t")
    assert d.execute("PRAGMA user_version").fetchone()[0] == 1, (
        "an absent table blocked stamping — every fresh database would "
        "re-scan forever"
    )
    d.close()
    c.close()


def test_the_migration_never_holds_more_than_a_batch_in_memory(tmp_path):
    """Bounded memory, not fewer rows.

    This asserted the opposite until 2026-09-16: that a WHERE filter kept the
    migration from reading already-correct rows. That filter UNDER-SELECTED
    (see the canonicalisation test below), and a migration that misses a row
    then stamps itself complete is worse than one that reads everything. The
    real requirement was never "read less" — it was "do not materialise 7.7M
    rows at once under the write lock".
    """
    import sqlite3
    from tpot2cti import timestamps as T

    db = tmp_path / "big.db"
    real = sqlite3.connect(db, isolation_level=None)
    real.execute("CREATE TABLE t (first_seen TEXT, last_seen TEXT)")
    real.executemany("INSERT INTO t VALUES (?, ?)",
                     [("2026-09-16T09:00:00+00:00", "2026-09-16T09:00:00+00:00")] * 250)
    real.execute("INSERT INTO t VALUES (?, ?)",
                 ("2026-09-16 10:30:00+02:00", "2026-09-16 10:30:00+02:00"))

    seen = {"max_batch": 0, "total": 0}

    class Counting:
        def __init__(self, conn): self._c = conn
        def execute(self, sql, *a):
            cur = self._c.execute(sql, *a)
            if sql.lstrip().upper().startswith("SELECT ROWID"):
                rows = cur.fetchall()
                seen["max_batch"] = max(seen["max_batch"], len(rows))
                seen["total"] += len(rows)

                class _Done:
                    def fetchall(self_inner): return rows
                return _Done()
            return cur
        @property
        def in_transaction(self): return self._c.in_transaction

    orig, T._BATCH = T._BATCH, 100
    try:
        changed = T.normalise_timestamp_columns(
            Counting(real), {"t": ("first_seen", "last_seen")}, 1, label="t")
    finally:
        T._BATCH = orig

    assert changed == 1, f"the one legacy row should have been fixed, got {changed}"
    assert seen["total"] == 251, (
        f"read {seen['total']} of 251 rows — the scan is not exhaustive"
    )
    assert seen["max_batch"] <= 100, (
        f"a single read pulled {seen['max_batch']} rows with _BATCH=100 — "
        "memory is not bounded"
    )
    real.close()


def test_migration_canonicalises_the_separator(tmp_path):
    """Everything ends up in the spelling future writes will use.

    All production writers call isoformat() (T-separated). A space-separated
    row — which sqlite3's adapter produces if anything ever bypasses those
    writers — must be rewritten to "T", not preserved: space is chr(32) and
    "T" is chr(84), so a preserved space sorts before every future write
    regardless of instant.

    An earlier version of this test asserted the opposite, from a fixture that
    bypassed the public API and so measured the adapter rather than the code.
    """
    import sqlite3
    from tpot2cti.timestamps import normalise_timestamp_columns

    db = tmp_path / "sep.db"
    c = sqlite3.connect(db, isolation_level=None)
    c.execute("CREATE TABLE t (first_seen TEXT, last_seen TEXT)")
    c.execute("INSERT INTO t VALUES (?, ?)",            # canonical already
              ("2026-09-16T09:00:00+00:00", "2026-09-16T09:00:00+00:00"))
    c.execute("INSERT INTO t VALUES (?, ?)",            # space + legacy offset
              ("2026-09-16 10:30:00+02:00", "2026-09-16 10:30:00+02:00"))
    c.execute("INSERT INTO t VALUES (?, ?)",            # space, already UTC
              ("2026-09-16 07:00:00+00:00", "2026-09-16 07:00:00+00:00"))

    normalise_timestamp_columns(c, {"t": ("first_seen", "last_seen")}, 1, label="t")

    rows = [r[0] for r in c.execute("SELECT last_seen FROM t ORDER BY last_seen")]
    assert all(r[10] == "T" for r in rows), f"not canonicalised: {rows}"
    assert rows == sorted(rows), "guard"
    assert rows[0].startswith("2026-09-16T07:00:00"), rows
    assert rows[-1].startswith("2026-09-16T09:00:00"), (
        f"ordering is wrong after migration: {rows}"
    )
    c.close()


def test_the_filter_never_under_selects(tmp_path):
    """The SQL filter is an optimisation; missing a row that needs work would
    stamp the version and leave it permanently wrong."""
    import sqlite3
    from tpot2cti.timestamps import normalise_timestamp_columns, canonical

    db = tmp_path / "f.db"
    c = sqlite3.connect(db, isolation_level=None)
    c.execute("CREATE TABLE t (first_seen TEXT, last_seen TEXT)")
    cases = [
        "2026-09-16 09:00:00+00:00",     # space separator, UTC
        "2026-09-16T09:00:00+02:00",     # T, non-UTC
        "2026-09-16 09:00:00+02:00",     # space, non-UTC
        "2026-09-16T09:00:00Z",          # Z suffix
        "2026-09-16T09:00:00z",          # lowercase z
        "2026-09-16T09:00:00",           # naive
        # The five codex reproduced as slipping past the old WHERE filter:
        # each ends "+00:00" with a "T" at position 11 and is still not
        # canonical. "…,9+00:00" even sorts BEFORE "….100000+00:00" while
        # being later.
        "2026-09-16T09:00:00.1+00:00",
        "2026-09-16T09:00:00.000000+00:00",
        "2026-09-16T09:00:00,9+00:00",
        "2026-09-16T095900+00:00",
        "2026-09-16T09:00+00:00",
    ]
    for v in cases:
        c.execute("INSERT INTO t VALUES (?, ?)", (v, v))

    normalise_timestamp_columns(c, {"t": ("first_seen", "last_seen")}, 1, label="t")

    for stored, original in zip(
        [r[0] for r in c.execute("SELECT first_seen FROM t")], cases
    ):
        assert stored == canonical(original), (
            f"{original!r} was left as {stored!r} — the filter under-selected"
        )
    c.close()


def test_negative_rowids_are_migrated(tmp_path):
    """SQLite rowids can be negative, and a -1 paging sentinel skipped them
    while the migration stamped itself complete — so nothing ever revisited
    them. Found by codex on the third review of #47."""
    import sqlite3
    from tpot2cti.timestamps import normalise_timestamp_columns

    db = tmp_path / "neg.db"
    c = sqlite3.connect(db, isolation_level=None)
    c.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, first_seen TEXT, last_seen TEXT)")
    for rid in (-500, -1, 0, 7):
        c.execute("INSERT INTO t (id, first_seen, last_seen) VALUES (?, ?, ?)",
                  (rid, "2026-09-16 10:30:00+02:00", "2026-09-16 10:30:00+02:00"))

    changed = normalise_timestamp_columns(c, {"t": ("first_seen", "last_seen")}, 1, label="t")
    assert changed == 4, f"only {changed} of 4 rows migrated — negative rowids skipped"

    left = c.execute(
        "SELECT COUNT(*) FROM t WHERE first_seen NOT LIKE '%+00:00'").fetchone()[0]
    assert left == 0, f"{left} row(s) still legacy after a 'complete' migration"
    assert c.execute("PRAGMA user_version").fetchone()[0] == 1
    c.close()
