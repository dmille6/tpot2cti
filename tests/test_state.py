"""CycleState SQLite-backed state — pruning + vacuum + size.

Per the 2026-05-22 audit #2: ``attacker_activity`` and friends had no
pruning at all and grew monotonically.  Tests below pin the pruning
semantics (cutoff respected, vacuum idempotent within window).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


def test_set_and_get_last_run(state_db):
    """Round-trip a last_run timestamp through SQLite."""
    when = datetime(2026, 5, 22, 12, 0, tzinfo=timezone.utc)
    state_db.set_last_run(when)
    got = state_db.get_last_run()
    assert got == when


def test_get_last_run_missing_returns_none(state_db):
    """No row → None, not an exception."""
    assert state_db.get_last_run() is None


def test_heartbeat_writes_parseable_utc_timestamp(state_db):
    """heartbeat() records a fresh ISO-8601 UTC timestamp under the KV key
    /health reads. Round-trips through SQLite and parses back to ~now."""
    assert state_db.get("last_heartbeat_ts") is None
    before = datetime.now(timezone.utc)
    state_db.heartbeat()
    raw = state_db.get("last_heartbeat_ts")
    assert raw is not None
    parsed = datetime.fromisoformat(raw)
    assert parsed.tzinfo is not None  # tz-aware
    # Within a few seconds of "now" on either side (clock + write latency).
    assert abs((parsed - before).total_seconds()) < 5.0


def test_heartbeat_advances_on_each_call(state_db):
    """A later heartbeat() overwrites the earlier timestamp (monotonic)."""
    state_db.heartbeat()
    first = state_db.get("last_heartbeat_ts")
    state_db.heartbeat()
    second = state_db.get("last_heartbeat_ts")
    assert second >= first


def test_prune_all_returns_dict(state_db):
    """prune_all returns a dict keyed by table name."""
    result = state_db.prune_all()
    assert isinstance(result, dict)
    assert {"cycles", "attacker_activity", "profile_emit_log", "object_max_state"} <= set(result)
    assert all(isinstance(v, int) for v in result.values())


def test_prune_attacker_activity_respects_cutoff(state_db):
    """A row newer than cutoff stays; a row older than cutoff is dropped."""
    now = datetime.now(timezone.utc)
    fresh = (now - timedelta(days=1)).isoformat()
    stale = (now - timedelta(days=200)).isoformat()
    with state_db._conn() as c:
        c.execute(
            "INSERT INTO attacker_activity (src_ip, parser, sensor, first_seen, last_seen) "
            "VALUES ('1.1.1.1', 'Cowrie', 'n1', ?, ?)", (fresh, fresh))
        c.execute(
            "INSERT INTO attacker_activity (src_ip, parser, sensor, first_seen, last_seen) "
            "VALUES ('2.2.2.2', 'Cowrie', 'n1', ?, ?)", (stale, stale))
    n = state_db.prune_attacker_activity(cutoff_days=90)
    assert n == 1
    with state_db._conn() as c:
        rows = c.execute("SELECT src_ip FROM attacker_activity").fetchall()
    assert [r[0] for r in rows] == ["1.1.1.1"]


def test_maybe_vacuum_idempotent_within_window(state_db):
    """A second vacuum within the min-age window MUST NOT re-run."""
    assert state_db.maybe_vacuum(min_age_days=30) is True
    assert state_db.maybe_vacuum(min_age_days=30) is False


def test_db_size_bytes_positive(state_db):
    """An initialized DB has a non-zero file size."""
    assert state_db.db_size_bytes() > 0


def test_prune_cycles_keeps_last_n(state_db):
    """prune_cycles preserves the most recent N rows."""
    for _ in range(5):
        state_db.start_cycle()
    n = state_db.prune_cycles(keep_last=2)
    assert n == 3
    assert len(state_db.recent_cycles(limit=10)) == 2


def test_get_max_state_bulk_chunks_large_id_list(state_db):
    """Regression for the 2026-07-19 ingestion outage.

    A large bundle produced a stix_id list far exceeding SQLite's
    ``SQLITE_MAX_VARIABLE_NUMBER`` (999 on older builds), and the
    single ``WHERE stix_id IN (...)`` raised
    ``OperationalError: too many SQL variables`` every publish cycle,
    stalling ingestion. get_max_state_bulk must chunk the lookup so it
    succeeds regardless of list size, and still return the persisted
    rows it does have.
    """
    # Persist a couple of known rows...
    known = [
        ("attack-pattern--" + "0" * 36, 80, ["a"], "n0", "d0"),
        ("attack-pattern--" + "1" * 36, 55, ["b"], "n1", "d1"),
    ]
    state_db.upsert_max_state_bulk(known)

    # ...then look them up inside a list of 5000 ids (well past the 999
    # limit and past our 500-per-chunk batch size).
    big = [f"attack-pattern--{i:036d}-x" for i in range(5000)]
    big[10] = known[0][0]
    big[4000] = known[1][0]

    out = state_db.get_max_state_bulk(big)  # must NOT raise

    assert set(out) == {known[0][0], known[1][0]}
    assert out[known[0][0]]["max_score"] == 80
    assert out[known[1][0]]["labels"] == ["b"]
