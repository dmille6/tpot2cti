"""HealthServer.compute_status — staleness + in-progress heartbeat.

These pin the /health contract that the docker-compose healthcheck and
operators depend on:

  * 200 when the last completed cycle is fresh ("fresh-cycle"), OR when a
    cycle is actively progressing via the heartbeat ("in-progress").
  * 503 when neither holds ("stale" / never-run / failed).

The heartbeat arm is the 2026-06-01 fix: a heavy hive-scale cycle (or the
first big catch-up cycle after a restart) can run longer than the window
between *completed* cycles, which used to flap the container to
"unhealthy" mid-cycle even though it was working. We call
``compute_status()`` directly (no socket bind needed) and backdate
timestamps explicitly so the assertions never race the wall clock.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tpot2cti.health import HealthServer


def _server(state, interval_s=900.0):
    # opencti=None is fine — compute_status never calls it (deliberate:
    # our liveness must not depend on OpenCTI's). No start_in_background()
    # so nothing binds a port.
    return HealthServer(
        state, opencti=None, bind="127.0.0.1:0",
        cycle_interval_seconds=interval_s,
    )


def _record_success(state, duration_seconds=12.5):
    cid = state.start_cycle()
    state.record_cycle(
        cid, success=True, events_read=100, events_parsed=100,
        events_dropped=0, sdos_emitted=42, errors_count=0,
        duration_seconds=duration_seconds,
    )
    return cid


def _backdate_cycle(state, cycle_id, seconds_ago):
    """Force a cycle's ended_at into the past, deterministically."""
    old = (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()
    with state._conn() as c:
        c.execute(
            "UPDATE cycle_log SET ended_at = ? WHERE cycle_id = ?",
            (old, cycle_id),
        )


def test_never_run_is_stale(state_db):
    payload, code = _server(state_db).compute_status()
    assert code == 503
    assert payload["status"] == "stale"
    assert payload["last_cycle_ts"] is None
    assert payload["heartbeat_age_s"] is None
    assert "last_cycle_error" in payload  # surfaced for debugging


def test_fresh_success_is_ok(state_db):
    _record_success(state_db)
    payload, code = _server(state_db).compute_status()
    assert code == 200
    assert payload["status"] == "ok"
    assert payload["liveness"] == "fresh-cycle"
    assert payload["last_cycle_duration_s"] == 12.5
    assert payload["age_s"] is not None and payload["age_s"] < 5.0


def test_stale_success_without_heartbeat_is_stale(state_db):
    """A completed cycle older than the window, with no heartbeat → 503."""
    cid = _record_success(state_db)
    _backdate_cycle(state_db, cid, seconds_ago=7200)  # 2h ago
    payload, code = _server(state_db, interval_s=900.0).compute_status()  # 30m window
    assert code == 503
    assert payload["status"] == "stale"
    assert payload["age_s"] > payload["stale_after_s"]
    assert payload["heartbeat_age_s"] is None


def test_in_progress_heartbeat_keeps_it_healthy(state_db):
    """A completed cycle older than the staleness window, but still within
    the no-success ceiling and with a fresh heartbeat (a long cycle actively
    progressing), keeps /health at 200 / 'in-progress'.

    interval=900s → window=1800s (stale beyond this), ceiling=2700s.
    2000s ago is stale-but-within-ceiling, so the heartbeat still rescues.
    """
    cid = _record_success(state_db)
    _backdate_cycle(state_db, cid, seconds_ago=2000)  # stale, but < 2700s ceiling
    state_db.heartbeat()                              # ...and we're working now
    payload, code = _server(state_db, interval_s=900.0).compute_status()
    assert code == 200
    assert payload["status"] == "ok"
    assert payload["liveness"] == "in-progress"
    assert payload["age_s"] > payload["stale_after_s"]        # cycle itself IS stale
    assert payload["no_success_age_s"] <= payload["max_no_success_s"]
    assert payload["heartbeat_age_s"] is not None
    assert payload["heartbeat_age_s"] < 5.0


def test_cycling_but_never_succeeding_goes_stale(state_db):
    """Regression for the 2026-07-19 → 08-04 stall.

    A process that keeps *starting* cycles (fresh heartbeat) but never
    *completes* one must NOT stay green forever. Once the last success is
    older than the no-success ceiling (3× interval), /health goes 503 with
    liveness 'cycling-no-success' even though the heartbeat is fresh.
    """
    cid = _record_success(state_db)
    _backdate_cycle(state_db, cid, seconds_ago=5000)  # > 2700s ceiling
    state_db.heartbeat()                              # process still looping
    payload, code = _server(state_db, interval_s=900.0).compute_status()
    assert code == 503
    assert payload["status"] == "stale"
    assert payload["liveness"] == "cycling-no-success"
    assert payload["heartbeat_age_s"] is not None and payload["heartbeat_age_s"] < 5.0
    assert payload["no_success_age_s"] > payload["max_no_success_s"]


def test_never_succeeded_past_ceiling_goes_stale(state_db):
    """A fresh deploy that has never landed a successful cycle goes 503
    once uptime passes the ceiling, even while heartbeating — measured from
    process start, not from a (nonexistent) last success."""
    srv = _server(state_db, interval_s=900.0)
    srv._started_at -= 5000  # pretend the process has been up > ceiling
    state_db.heartbeat()
    payload, code = srv.compute_status()
    assert code == 503
    assert payload["liveness"] == "cycling-no-success"
    assert payload["no_success_age_s"] > payload["max_no_success_s"]


def test_stale_heartbeat_is_stale(state_db):
    """A heartbeat older than the window does NOT keep it healthy."""
    old = (datetime.now(timezone.utc) - timedelta(seconds=7200)).isoformat()
    state_db.set("last_heartbeat_ts", old)
    payload, code = _server(state_db, interval_s=900.0).compute_status()
    assert code == 503
    assert payload["status"] == "stale"
    assert payload["liveness"] == "stale"
    assert payload["heartbeat_age_s"] > payload["stale_after_s"]
