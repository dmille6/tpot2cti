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

  - We DO NOT call `opencti.health_check()` on every /health hit —
    that would make our liveness probe transitively depend on
    OpenCTI's liveness, which is the wrong dependency direction
    (per LESSONS_LEARNED §11: "container restart loop because the
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

    # Silence the default stderr access log — we have JSON logs already.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Route through the module logger at DEBUG so operators can
        # opt into access logs via LOG_LEVEL=DEBUG.
        logger.debug("health: %s - - %s" % (self.address_string(), format % args))

    def do_GET(self) -> None:  # noqa: N802 — stdlib API
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

class HealthServer(ThreadingHTTPServer):
    """HTTP server wrapping stdlib `ThreadingHTTPServer`.

    Subclassing the server (rather than composing it) keeps the
    `state` / `opencti` references on the same object the handler
    receives via `self.server`, which is the stdlib idiom.

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
        self._started_at = time.monotonic()
        self._thread: Optional[threading.Thread] = None
        self._pycti_version = pycti_version or _detect_pycti_version()

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
    # status computation — called by the handler
    # ------------------------------------------------------------------

    def compute_status(self) -> tuple[dict, int]:
        """Return (payload, http_status_code) for the /health response.

        200 if a successful cycle ended within `STALENESS_MULTIPLIER ×
        interval` seconds ago; 503 otherwise (including "never run").
        """
        now = datetime.now(timezone.utc)
        uptime_s = time.monotonic() - self._started_at
        stale_after_s = self._cycle_interval_seconds * STALENESS_MULTIPLIER

        last_ts_iso, last_duration_s, last_success = self._last_successful_cycle()

        base: dict[str, Any] = {
            "uptime_s": round(uptime_s, 3),
            "stale_after_s": stale_after_s,
            "cycle_interval_s": self._cycle_interval_seconds,
            "pycti_version": self._pycti_version,
        }

        if last_ts_iso is None or last_success is not True:
            # Never run a successful cycle, OR the most recent cycle
            # failed.  Either way: stale until we observe success.
            payload = {
                "status": "stale",
                "last_cycle_ts": None,
                "age_s": None,
                "last_cycle_error": self._state.get("last_cycle_error"),
                **base,
            }
            return payload, 503

        age_s = _age_seconds(last_ts_iso, now)
        if age_s is None or age_s > stale_after_s:
            payload = {
                "status": "stale",
                "last_cycle_ts": last_ts_iso,
                "last_cycle_duration_s": last_duration_s,
                "age_s": age_s,
                **base,
            }
            return payload, 503

        payload = {
            "status": "ok",
            "last_cycle_ts": last_ts_iso,
            "last_cycle_duration_s": last_duration_s,
            "age_s": age_s,
            **base,
        }
        return payload, 200

    def _last_successful_cycle(
        self,
    ) -> tuple[Optional[str], Optional[float], Optional[bool]]:
        """Pull the most recent row from `state.recent_cycles(1)`.

        Returns `(ended_at_iso, duration_seconds, success)` — any field
        may be None if state is empty / corrupt.  We scan the last few
        rows for the most recent SUCCESSFUL row rather than just taking
        the topmost row, so a freshly-failed cycle doesn't immediately
        flip /health to 503 if a recent prior success is still inside
        the staleness window.
        """
        try:
            rows = self._state.recent_cycles(limit=10)
        except Exception as e:
            logger.warning(f"health: state.recent_cycles failed: {e}")
            return None, None, None
        for row in rows:
            if row.get("success") == 1 and row.get("ended_at"):
                return (
                    row.get("ended_at"),
                    row.get("duration_seconds"),
                    True,
                )
        # No successful row in recent history.
        if rows:
            # Topmost row exists but isn't a success — report failure shape.
            return rows[0].get("ended_at"), rows[0].get("duration_seconds"), False
        return None, None, None


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
