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
                  ("2026-09-16T10:30:00+02:00", "2026-09-16T10:30:00+02:00"))
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
