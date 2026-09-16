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


def test_the_migration_only_reads_rows_that_need_changing(tmp_path):
    """It must not materialise the whole table to find nothing to do.

    Live measurement 2026-09-16: 7.7M credential rows, ZERO of them legacy.
    A fetchall() over all of them builds GBs of tuples while holding the write
    lock the credentials writer needs.

    Asserted by counting what the SELECT actually returns, not by timing.
    """
    import sqlite3
    from tpot2cti.timestamps import normalise_timestamp_columns

    db = tmp_path / "big.db"
    real = sqlite3.connect(db, isolation_level=None)
    real.execute("CREATE TABLE t (first_seen TEXT, last_seen TEXT)")
    real.executemany("INSERT INTO t VALUES (?, ?)",
                     [("2026-09-16T09:00:00+00:00", "2026-09-16T09:00:00+00:00")] * 500)
    real.execute("INSERT INTO t VALUES (?, ?)",
                 ("2026-09-16 10:30:00+02:00", "2026-09-16 10:30:00+02:00"))

    seen = {"rows": 0}

    class Counting:
        """Forwards to the real connection, counting rows the migration reads."""
        def __init__(self, conn): self._c = conn
        def execute(self, sql, *a):
            cur = self._c.execute(sql, *a)
            if sql.lstrip().upper().startswith("SELECT ROWID"):
                rows = cur.fetchall()
                seen["rows"] += len(rows)

                class _Done:            # the migration calls .fetchall() on it
                    def fetchall(self_inner): return rows
                return _Done()
            return cur
        @property
        def in_transaction(self): return self._c.in_transaction

    changed = normalise_timestamp_columns(
        Counting(real), {"t": ("first_seen", "last_seen")}, 1, label="t")

    assert changed == 1, f"the one legacy row should have been fixed, got {changed}"
    assert seen["rows"] == 1, (
        f"the migration read {seen['rows']} rows to fix 1 — it is scanning "
        "every already-normalised row into memory"
    )
    fixed = real.execute(
        "SELECT COUNT(*) FROM t WHERE first_seen LIKE '%+00:00'").fetchone()[0]
    assert fixed == 501, "the legacy row was not normalised"
    real.close()


def test_migration_keeps_the_stored_date_time_separator(tmp_path):
    """sqlite3's adapter writes "2026-09-16 08:30:00+00:00" with a SPACE;
    isoformat() emits "T". Space is chr(32), "T" is chr(84), so under the TEXT
    comparison these columns are sorted by, every space-separated value sorts
    before every T-separated one regardless of instant.

    A migration that rewrites one row with "T" while its neighbours keep a
    space corrupts the ordering it exists to fix. Found by seeding through
    CredentialStore's own writer instead of a hand-built fixture.
    """
    import sqlite3
    from tpot2cti.timestamps import normalise_timestamp_columns

    db = tmp_path / "sep.db"
    c = sqlite3.connect(db, isolation_level=None)
    c.execute("CREATE TABLE t (first_seen TEXT, last_seen TEXT)")
    # space-separated, already UTC (what the adapter writes)
    c.execute("INSERT INTO t VALUES (?, ?)",
              ("2026-09-16 09:00:00+00:00", "2026-09-16 09:00:00+00:00"))
    # space-separated but a legacy offset — the row that gets rewritten
    c.execute("INSERT INTO t VALUES (?, ?)",
              ("2026-09-16 10:30:00+02:00", "2026-09-16 10:30:00+02:00"))

    normalise_timestamp_columns(c, {"t": ("first_seen", "last_seen")}, 1, label="t")

    rows = [r[0] for r in c.execute("SELECT last_seen FROM t ORDER BY last_seen DESC")]
    assert all(" " in r[:11] for r in rows), (
        f"separator changed during migration: {rows} — mixed 'T' and ' ' "
        "makes TEXT ordering meaningless"
    )
    assert rows[0].startswith("2026-09-16 09:00:00"), (
        f"newest-first returned {rows[0]} — 08:30Z outsorted 09:00Z"
    )
    c.close()
