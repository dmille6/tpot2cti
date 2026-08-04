"""tpot2cti — /health HTTP endpoint.

Implements V1_SPEC.md §3 (Health endpoint):

    The container exposes `/health` on internal port 8080 returning:
        - HTTP 200 if last cycle completed successfully
        - HTTP 503 if no cycle has succeeded in the last
          2× cycle interval

    Docker compose healthcheck uses this.

Implementation notes:

  - Stdlib `http.server` only — no Flask/FastAPI.  Per V1_SPEC §2 the
    container image stays minimal, and a one-route JSON endpoint
    doesn't justify a framework.

  - Runs in a daemon thread so the main cycle loop owns the lifetime
    of the process.  `start_in_background()` returns immediately;
    `stop()` shuts down cleanly.

  - "Last cycle is fresh" is computed from `state.recent_cycles(1)` —
    the most recent successful cycle's `ended_at`.  We compare
    `now - ended_at` against `2 × cycle.interval_iso` in seconds.

  - We ALSO treat an in-progress cycle as healthy via a heartbeat
    (`state.heartbeat()`), updated at cycle start and after each
    long-running step. A heavy hive-scale cycle (or the first big
    catch-up cycle after a restart) can run longer than the window
    between completed cycles; the heartbeat keeps `/health` at 200
    while it works, instead of flapping the container to "unhealthy".
    A truly hung process stops beating and still goes stale.

  - We DO NOT call `opencti.health_check()` on every /health hit —
    that would make our liveness probe transitively depend on
    OpenCTI's liveness, which is the wrong dependency direction
    (per LESSONS §11: "container restart loop because the
    health probe blocked on a downstream platform that itself relied
    on this container being up").  We only call it on startup, log
    the result, and surface it as a `last_opencti_check` field.

Per LESSONS_LEARNED_FROM_V0.md §1: stdlib `http.server` is sync —
fits our sync-only HTTP rule.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Default bind ":8080" per V1_SPEC §3 ("internal port 8080").
DEFAULT_BIND: str = ":8080"

# Stale threshold: 2× the cycle interval (V1_SPEC §3).  Multiplier kept
# as a constant so a future spec revision can tune it without touching
# the request handler.
STALENESS_MULTIPLIER: float = 2.0

# Hard ceiling on the heartbeat arm: the heartbeat keeps /health green
# while a cycle is actively working, but it may NOT do so indefinitely.
# If NO cycle has *completed successfully* within this many intervals,
# /health goes 503 even though the process is still cycling — because
# "cycling forever but never succeeding" is a failure, not health.
#
# This is the direct fix for the 2026-07-19 → 08-04 stall, where every
# cycle started (bumping the heartbeat) but failed at publish, so the
# old `cycle_fresh OR heartbeat_fresh` rule stayed green for 16 days.
# Set larger than STALENESS_MULTIPLIER so one genuinely long cycle
# (a big first catch-up) still won't flap the container.
NO_SUCCESS_CEILING_MULTIPLIER: float = 3.0


# ---------------------------------------------------------------------------
# ISO 8601 duration parsing — we accept the subset T-Pot/V1_SPEC uses
# (PTnH, PTnM, PTnS, and combos thereof).  Per V1_SPEC §10 the value is
# always a PT* duration.
# ---------------------------------------------------------------------------

_ISO_DURATION_RE = re.compile(
    r"^PT"
    r"(?:(?P<h>\d+(?:\.\d+)?)H)?"
    r"(?:(?P<m>\d+(?:\.\d+)?)M)?"
    r"(?:(?P<s>\d+(?:\.\d+)?)S)?"
    r"$"
)


def parse_iso_duration_seconds(iso: str, default_seconds: float = 900.0) -> float:
    """Parse a `PTnH...nM...nS` ISO 8601 duration into seconds.

    `default_seconds` is returned on any parse failure — we never let a
    bad config string crash the health endpoint.  The default of 900s
    matches V1_SPEC §3's default of PT15M.
    """
    if not iso:
        return default_seconds
    m = _ISO_DURATION_RE.match(iso.strip())
    if not m:
        logger.warning(
            f"parse_iso_duration_seconds: unrecognized value {iso!r}, "
            f"using default {default_seconds}s"
        )
        return default_seconds
    h = float(m.group("h") or 0)
    mi = float(m.group("m") or 0)
    s = float(m.group("s") or 0)
    total = h * 3600 + mi * 60 + s
    if total <= 0:
        return default_seconds
    return total


# ---------------------------------------------------------------------------
# Health request handler
# ---------------------------------------------------------------------------

class _HealthHandler(BaseHTTPRequestHandler):
    """Single-route handler — `/health` returns JSON.

    The server instance owns the references to `state`, `opencti`, and
    the cycle interval; we read them off the server in `do_GET`.  This
    is the canonical way to share state with stdlib `BaseHTTPRequestHandler`
    instances (each request gets a fresh handler).
    """

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Override ``BaseHTTPRequestHandler.log_message`` to silence the
        default stderr access log (we ship JSON logs via the module
        logger instead). Access logs are emitted at DEBUG so operators
        can opt in with ``LOG_LEVEL=DEBUG``.
        """
        logger.debug("health: %s - - %s" % (self.address_string(), format % args))

    def do_GET(self) -> None:  # noqa: N802 — stdlib API
        """Serve ``GET /health`` with the JSON status from
        :meth:`HealthServer.compute_status` (200 on healthy / 503 on
        stale). Any other path returns 404. The healthcheck contract
        per V1_SPEC §3 is intentionally narrow: one endpoint, two states.
        """
        if self.path != "/health":
            self._write_json(404, {"status": "not found", "path": self.path})
            return

        server: HealthServer = self.server  # type: ignore[assignment]
        payload, code = server.compute_status()
        self._write_json(code, payload)

    def _write_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Don't cache liveness probes.
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            # Probe disconnected mid-write.  Common for k8s/docker
            # health checks that don't wait for the body.  Not an error.
            pass


# ---------------------------------------------------------------------------
# HealthServer — the threaded wrapper the main loop uses
# ---------------------------------------------------------------------------

class HealthStatus:
    """Pure ``/health`` status computation over :class:`CycleState`.

    Split out from :class:`HealthServer` (which binds a socket in its
    constructor) so the status logic is unit-testable without opening a
    port. ``HealthServer`` owns one of these and delegates to it.
    """

    def __init__(
        self,
        state,
        cycle_interval_seconds: float = 900.0,
        pycti_version: Optional[str] = None,
        started_at_monotonic: Optional[float] = None,
    ) -> None:
        self._state = state
        self._cycle_interval_seconds = float(cycle_interval_seconds)
        self._pycti_version = pycti_version or _detect_pycti_version()
        self._started_at = (
            started_at_monotonic
            if started_at_monotonic is not None
            else time.monotonic()
        )

    def compute_status(self) -> tuple[dict, int]:
        """Return (payload, http_status_code) for the /health response.

        Healthy (200) if EITHER:

          * the last *completed* cycle succeeded within
            ``STALENESS_MULTIPLIER × interval`` seconds (``liveness:
            "fresh-cycle"``), OR
          * a cycle is actively in progress — the cycle loop's heartbeat
            (``state.heartbeat()``, bumped at cycle start, after the ES
            stream, and after every publisher pass) is within that window
            **and** we are not past the no-success ceiling
            (``liveness: "in-progress"``).

        Otherwise stale (503). The heartbeat arm keeps a heavy
        long-running cycle from flapping the container to "unhealthy"
        while it is demonstrably working — but only until the no-success
        ceiling (``NO_SUCCESS_CEILING_MULTIPLIER × interval``). Past that,
        a process that keeps *starting* cycles but never *completes* one
        (the 2026-07-19 stall) correctly reads unhealthy (``liveness:
        "cycling-no-success"``). A genuinely hung/dead process stops
        beating, so it still goes stale on schedule.

        The ceiling is measured against the last *successful* cycle. The
        one subtlety is a fresh install that has never succeeded: a big
        first cycle can legitimately run longer than the ceiling, so as
        long as **no cycle has finished yet** we treat it as in-progress
        (give the first cycle time). Only once a cycle has *completed*
        without success does the ceiling start from process start — that
        is the "failing loop" case.
        """
        now = datetime.now(timezone.utc)
        uptime_s = time.monotonic() - self._started_at
        stale_after_s = self._cycle_interval_seconds * STALENESS_MULTIPLIER
        max_no_success_s = (
            self._cycle_interval_seconds * NO_SUCCESS_CEILING_MULTIPLIER
        )

        last_ts_iso, last_duration_s, last_success, any_completed = \
            self._cycle_summary()
        heartbeat_iso, heartbeat_age_s = self._heartbeat_age(now)
        heartbeat_fresh = (
            heartbeat_age_s is not None and heartbeat_age_s <= stale_after_s
        )

        cycle_age_s = _age_seconds(last_ts_iso, now) if last_ts_iso else None

        # Time since a cycle last SUCCEEDED — the signal the heartbeat arm
        # may not mask past the ceiling:
        #   * prior success exists      -> age of that success (catches the
        #     16-day stall: old success + now failing -> past ceiling -> 503)
        #   * never succeeded, and no cycle has even *finished* yet -> a
        #     first cycle is still running; give it time (age 0) so a big
        #     first catch-up on a fresh install doesn't false-alarm
        #   * never succeeded but cycles have *completed* without success
        #     -> a failing loop; measure from process start (uptime)
        if last_success is True and cycle_age_s is not None:
            no_success_age_s = cycle_age_s
        elif not any_completed:
            no_success_age_s = 0.0
        else:
            no_success_age_s = uptime_s
        within_success_ceiling = no_success_age_s <= max_no_success_s

        base: dict[str, Any] = {
            "uptime_s": round(uptime_s, 3),
            "stale_after_s": stale_after_s,
            "max_no_success_s": max_no_success_s,
            "no_success_age_s": round(no_success_age_s, 3),
            "cycle_interval_s": self._cycle_interval_seconds,
            "pycti_version": self._pycti_version,
            # Last cycle's drop breakdown (unparsed / dispatch_error /
            # self_or_internal / benign_scanner) so an operator can see WHY
            # events aren't landing without grepping logs. Best-effort.
            "last_cycle_drops": self._last_cycle_drops(),
        }

        # Freshness of the most recent *completed* successful cycle.
        cycle_fresh = (
            last_success is True
            and cycle_age_s is not None
            and cycle_age_s <= stale_after_s
        )
        heartbeat_rescues = heartbeat_fresh and within_success_ceiling

        if cycle_fresh or heartbeat_rescues:
            payload = {
                "status": "ok",
                "liveness": "fresh-cycle" if cycle_fresh else "in-progress",
                "last_cycle_ts": last_ts_iso,
                "last_cycle_duration_s": last_duration_s,
                "age_s": cycle_age_s,
                "heartbeat_age_s": heartbeat_age_s,
                **base,
            }
            return payload, 200

        # Stale (503). Distinguish the "cycling but never completing"
        # failure — heartbeat is fresh, so the process is alive and
        # looping, but no cycle has succeeded within the ceiling — from a
        # plain dead/hung process, because the remedy differs.
        cycling_no_success = heartbeat_fresh and not within_success_ceiling
        payload = {
            "status": "stale",
            "liveness": "cycling-no-success" if cycling_no_success else "stale",
            "last_cycle_ts": last_ts_iso,
            "last_cycle_duration_s": last_duration_s,
            "age_s": cycle_age_s,
            "heartbeat_age_s": heartbeat_age_s,
            **base,
        }
        if last_ts_iso is None or last_success is not True:
            # Never run a successful cycle, OR the most recent cycle
            # failed — surface the last error to aid debugging.
            payload["last_cycle_error"] = self._state.get("last_cycle_error")
        return payload, 503

    def _cycle_summary(
        self,
    ) -> tuple[Optional[str], Optional[float], Optional[bool], bool]:
        """One ``recent_cycles`` read → (ts, duration, success, any_completed).

        The first three describe the most recent *successful* cycle (so a
        freshly-failed cycle doesn't flip /health to 503 while a prior
        success is still inside the staleness window). ``any_completed`` is
        True if ANY recent cycle has finished (``ended_at`` set) — used to
        tell "first cycle still running" from "looping without success".
        Any field may be None / False if state is empty or unreadable;
        health is best-effort and never raises.
        """
        try:
            rows = self._state.recent_cycles(limit=10)
        except Exception as e:
            logger.warning(f"health: state.recent_cycles failed: {e}")
            return None, None, None, False
        any_completed = any(row.get("ended_at") for row in rows)
        for row in rows:
            if row.get("success") == 1 and row.get("ended_at"):
                return (
                    row.get("ended_at"),
                    row.get("duration_seconds"),
                    True,
                    any_completed,
                )
        if rows:
            # Topmost row exists but isn't a success — report failure shape.
            return (
                rows[0].get("ended_at"),
                rows[0].get("duration_seconds"),
                False,
                any_completed,
            )
        return None, None, None, any_completed

    def _last_cycle_drops(self) -> Optional[dict]:
        """Return the last cycle's drop-reason breakdown from the state KV.

        ``None`` if none recorded yet or the read/parse fails — health is
        best-effort and never raises.
        """
        try:
            raw = self._state.get("last_cycle_drops")
            return json.loads(raw) if raw else None
        except Exception as e:  # pragma: no cover - defensive
            logger.debug(f"health: last_cycle_drops read failed: {e}")
            return None

    def _heartbeat_age(
        self, now: datetime
    ) -> tuple[Optional[str], Optional[float]]:
        """Return ``(heartbeat_iso, age_seconds)`` from the state KV.

        Both fields are None if no heartbeat has been recorded yet or the
        state read fails — health is best-effort and never raises.
        """
        try:
            iso = self._state.get("last_heartbeat_ts")
        except Exception as e:  # pragma: no cover - defensive
            logger.debug(f"health: heartbeat read failed: {e}")
            return None, None
        if not iso:
            return None, None
        return iso, _age_seconds(iso, now)


class HealthServer(ThreadingHTTPServer):
    """HTTP server wrapping stdlib `ThreadingHTTPServer`.

    Subclassing the server (rather than composing it) keeps the
    `state` / `opencti` references on the same object the handler
    receives via `self.server`, which is the stdlib idiom. The status
    computation itself lives in :class:`HealthStatus` (socket-free and
    unit-testable); this server just owns one and serves it over HTTP.

    Usage::

        srv = HealthServer(state, opencti, bind=":8080",
                           cycle_interval_seconds=900)
        srv.start_in_background()
        ...
        srv.stop()
    """

    # Tame the kernel's TIME_WAIT behaviour so a container restart can
    # immediately rebind 0.0.0.0:8080 without hitting "address in use".
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        state,
        opencti,
        bind: str = DEFAULT_BIND,
        cycle_interval_seconds: float = 900.0,
        pycti_version: Optional[str] = None,
    ) -> None:
        host, port = _split_bind(bind)
        super().__init__((host, port), _HealthHandler)
        self._state = state
        self._opencti = opencti
        self._cycle_interval_seconds = float(cycle_interval_seconds)
        self._thread: Optional[threading.Thread] = None
        self._pycti_version = pycti_version or _detect_pycti_version()
        # The status logic lives here (socket-free); the server just serves it.
        self._status = HealthStatus(
            state,
            cycle_interval_seconds=self._cycle_interval_seconds,
            pycti_version=self._pycti_version,
            started_at_monotonic=time.monotonic(),
        )

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def start_in_background(self) -> None:
        """Spawn a daemon thread running `serve_forever`."""
        if self._thread is not None:
            logger.warning("HealthServer.start_in_background called twice")
            return
        t = threading.Thread(
            target=self.serve_forever,
            name="tpot2cti-health",
            daemon=True,
        )
        t.start()
        self._thread = t
        logger.info(
            f"health: serving /health on {self.server_address[0]}:"
            f"{self.server_address[1]} "
            f"(stale_after={self._cycle_interval_seconds * STALENESS_MULTIPLIER:.0f}s)"
        )

    def stop(self) -> None:
        """Shut down the server and join the background thread."""
        try:
            self.shutdown()
        except Exception as e:  # pragma: no cover - defensive
            logger.debug(f"health: shutdown raised (ignored): {e}")
        try:
            self.server_close()
        except Exception as e:  # pragma: no cover
            logger.debug(f"health: server_close raised (ignored): {e}")
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        logger.info("health: stopped")

    # ------------------------------------------------------------------
    # status computation — delegated to the socket-free HealthStatus
    # ------------------------------------------------------------------

    def compute_status(self) -> tuple[dict, int]:
        """Delegate to :class:`HealthStatus` (see there for the contract)."""
        return self._status.compute_status()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _split_bind(bind: str) -> tuple[str, int]:
    """Parse a bind string like `":8080"` or `"127.0.0.1:8080"`.

    Empty host = bind to all interfaces (`""`, which stdlib treats as
    the wildcard).
    """
    if ":" not in bind:
        raise ValueError(
            f"HealthServer bind {bind!r} must contain a port (e.g. ':8080')"
        )
    host, _, port_s = bind.rpartition(":")
    try:
        port = int(port_s)
    except ValueError as e:
        raise ValueError(f"HealthServer bind {bind!r} has bad port") from e
    return host, port


def _age_seconds(iso: str, now: datetime) -> Optional[float]:
    """Return `(now - iso)` in seconds, or None on parse error."""
    try:
        when = datetime.fromisoformat(iso)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return (now - when).total_seconds()
    except (TypeError, ValueError) as e:
        logger.debug(f"health: unparseable cycle timestamp {iso!r}: {e}")
        return None


def _detect_pycti_version() -> str:
    """Return the installed pycti version, or 'unknown' if not importable.

    We don't WANT to import pycti at health-init time (it's heavy), so
    we use `importlib.metadata` which only reads the package's
    METADATA file.
    """
    try:
        import importlib.metadata as md
        return md.version("pycti")
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile
    import urllib.request
    import urllib.error
    from pathlib import Path

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    from tpot2cti.state import CycleState

    # ---- helpers ----
    def get_health(port: int) -> tuple[int, dict]:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/health", timeout=3.0
            ) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return resp.status, body
        except urllib.error.HTTPError as e:
            # 503 is expected for "stale"; capture body.
            body = json.loads(e.read().decode("utf-8"))
            return e.code, body

    # ---- 1) Fresh state DB: never-run → 503 stale ----
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    cleanup = [db_path, db_path + "-wal", db_path + "-shm"]
    try:
        state = CycleState(db_path=db_path)
        srv = HealthServer(
            state, opencti=None, bind="127.0.0.1:18080",
            cycle_interval_seconds=900,
        )
        srv.start_in_background()
        try:
            code, body = get_health(18080)
            assert code == 503, f"fresh DB should be stale; got {code}: {body}"
            assert body["status"] == "stale"
            assert body["last_cycle_ts"] is None
            assert "pycti_version" in body
            assert "uptime_s" in body
            print(f"OK: fresh DB → 503 stale (uptime_s={body['uptime_s']})")

            # ---- 2) Record a fresh successful cycle → 200 ok ----
            cid = state.start_cycle()
            state.record_cycle(
                cid, success=True, events_read=100, events_parsed=100,
                events_dropped=0, sdos_emitted=42, errors_count=0,
                duration_seconds=12.5,
            )
            code, body = get_health(18080)
            assert code == 200, f"after success should be ok; got {code}: {body}"
            assert body["status"] == "ok"
            assert body["last_cycle_ts"] is not None
            assert body["last_cycle_duration_s"] == 12.5
            assert body["age_s"] is not None and body["age_s"] < 5.0
            print(f"OK: after success → 200 ok (age_s={body['age_s']:.3f}, "
                  f"duration_s={body['last_cycle_duration_s']})")

            # ---- 3) Force staleness via a tiny interval → 503 ----
            srv.stop()
            srv2 = HealthServer(
                state, opencti=None, bind="127.0.0.1:18081",
                cycle_interval_seconds=0.001,   # 2x = 0.002s window
            )
            srv2.start_in_background()
            try:
                time.sleep(0.05)  # well past the 2x window
                code, body = get_health(18081)
                assert code == 503, f"tight window should be stale; got {code}: {body}"
                assert body["status"] == "stale"
                assert body["age_s"] is not None and body["age_s"] > body["stale_after_s"]
                print(f"OK: tiny interval → 503 stale "
                      f"(age_s={body['age_s']:.3f} > stale_after_s={body['stale_after_s']})")
            finally:
                srv2.stop()

            # ---- 4) Unknown path → 404 ----
            srv3 = HealthServer(
                state, opencti=None, bind="127.0.0.1:18082",
                cycle_interval_seconds=900,
            )
            srv3.start_in_background()
            try:
                code, body = get_health(18082)
                assert code == 200, f"sanity check failed: {code}"
                # /metrics or anything else → 404
                try:
                    with urllib.request.urlopen(
                        "http://127.0.0.1:18082/metrics", timeout=3.0
                    ) as resp:
                        raise AssertionError(
                            f"expected 404, got {resp.status}"
                        )
                except urllib.error.HTTPError as e:
                    assert e.code == 404, f"expected 404; got {e.code}"
                    body = json.loads(e.read().decode("utf-8"))
                    assert body["status"] == "not found"
                print("OK: unknown path → 404")
            finally:
                srv3.stop()
        finally:
            try:
                srv.stop()
            except Exception:
                pass

        # ---- 5) parse_iso_duration_seconds basics ----
        assert parse_iso_duration_seconds("PT15M") == 900.0
        assert parse_iso_duration_seconds("PT1H") == 3600.0
        assert parse_iso_duration_seconds("PT1H30M") == 5400.0
        assert parse_iso_duration_seconds("PT30S") == 30.0
        assert parse_iso_duration_seconds("garbage", default_seconds=42.0) == 42.0
        assert parse_iso_duration_seconds("") == 900.0
        print("OK: parse_iso_duration_seconds handles PT15M / PT1H / PT1H30M / PT30S / bad input")

        print("\nOK")
    finally:
        for p in cleanup:
            Path(p).unlink(missing_ok=True)
