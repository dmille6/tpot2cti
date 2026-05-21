"""tpot2cti — main importer entrypoint and cycle loop.

This module wires together every Phase 1-5 piece:

  - `config.load_config()`        — load env / yaml
  - `log.setup_logging()`         — JSON logs to stdout + rotated file
  - `state.CycleState`            — SQLite-backed cycle bookkeeping
  - `es_client.TpotESClient`      — read T-Pot's ES via SSH tunnel
  - `parsers.dispatch()`          — type → parser dispatch
  - `parsers.<P>.correlate()`     — events → sessions
  - `parsers.<P>.build()`         — sessions → STIX (substance-filtered)
  - `daily_creds.maybe_emit_pending()` — V1_SPEC §6 daily Note
  - `publisher.Publisher.publish()` (Phase 5)  — three-pass send to OpenCTI
  - `opencti_client.OpenCTIClient` (Phase 5)
  - `health.HealthServer`         — /health endpoint

Per V1_SPEC.md §3 (cycle behavior) the loop is:

    every TPOT2CTI_INTERVAL (default PT15M):
        1. ES query for events since last_run
        2. dispatch each doc → ParsedEvent
        3. group by parser type_name → correlate → AttackSessions
        4. parser.build(session, builder) → STIX objects
        5. daily_creds.maybe_emit_pending() → +Notes
        6. publisher.publish(objects)
        7. state.set_last_run(window_end)
        8. log + record cycle summary

Per V1_SPEC.md §7: catch + log + continue at the cycle boundary;
never let a single bad session crash the loop.  SIGTERM/SIGINT
finishes the current cycle then exits cleanly.

Per docs/LESSONS_LEARNED_FROM_V0.md §1: sync HTTP only (`requests`,
stdlib `http.server`).  No asyncio anywhere.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
import traceback
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from tpot2cti import daily_creds
from tpot2cti.config import Config, load_config
from tpot2cti.es_client import TpotESClient
from tpot2cti.health import HealthServer, parse_iso_duration_seconds
from tpot2cti.log import restore_logging, setup_logging
from tpot2cti.parsers import dispatch, get_parser
from tpot2cti.parsers.base import AttackSession, ParsedEvent
from tpot2cti.state import CycleState
from tpot2cti.stix.builder import STIXBuilder

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Phase 5 imports — defensive stubs so this module is importable even when
# Phase 5 hasn't landed yet (sibling agent is writing it in parallel).
# The stubs are NEVER used in production — `main()` will fail loudly at
# startup if pycti / publisher.py is missing.  But `from tpot2cti.main
# import run_cycle` works in unit tests on a clean tree.
# ---------------------------------------------------------------------------

try:
    from tpot2cti.publisher import Publisher  # type: ignore[import-not-found]
    from tpot2cti.publisher import PublishResult  # type: ignore[import-not-found]
    _HAVE_PUBLISHER = True
except Exception:  # pragma: no cover — Phase 5 not landed yet
    _HAVE_PUBLISHER = False

    class PublishResult:  # type: ignore[no-redef]
        """Stub PublishResult; replaced by Phase 5's real class on import."""

        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)

        def __repr__(self) -> str:
            return f"PublishResult({self.__dict__})"

    class Publisher:  # type: ignore[no-redef]
        """Stub Publisher — Phase 5 hasn't landed.  Logs and drops the bundle."""

        def __init__(self, opencti_client: Any, *, state: Any = None) -> None:
            self.opencti_client = opencti_client
            self.state = state
            logger.warning(
                "Publisher stub in use — Phase 5 hasn't landed yet. "
                "STIX objects will be logged and discarded."
            )

        def publish(
            self, objects: list[dict], cycle_id: Optional[str] = None
        ) -> PublishResult:
            logger.info(
                f"[stub publisher] would publish {len(objects)} STIX objects "
                f"(cycle_id={cycle_id})"
            )
            return PublishResult(
                ok=True, total=len(objects), foundation=0, entities=0,
                relationships=0, errors=[], duration_seconds=0.0,
            )

try:
    from tpot2cti.opencti_client import OpenCTIClient  # type: ignore[import-not-found]
    _HAVE_OPENCTI_CLIENT = True
except Exception:  # pragma: no cover
    _HAVE_OPENCTI_CLIENT = False

    class OpenCTIClient:  # type: ignore[no-redef]
        """Stub OpenCTIClient — Phase 5 hasn't landed."""

        def __init__(self, cfg: Any, connector_id: str = "") -> None:
            self.cfg = cfg
            self.connector_id = connector_id
            logger.warning(
                "OpenCTIClient stub in use — Phase 5 hasn't landed yet."
            )

        def send_bundle(self, objects: list[dict], update: bool = False) -> dict:
            return {"ok": True, "stub": True, "count": len(objects)}

        def health_check(self) -> bool:
            return False


# ---------------------------------------------------------------------------
# Signal handling — shared between main() and the cycle loop
# ---------------------------------------------------------------------------

class _Shutdown:
    """Bag of shutdown coordination state.

    `requested` is set True by signal handlers; the main loop reads it
    between cycles and exits cleanly.  Never set in the middle of a
    publish — the cycle finishes whatever it's doing first.
    """

    def __init__(self) -> None:
        self.requested = False
        self._event = threading.Event()

    def request(self, signum: int, *_: Any) -> None:
        if self.requested:
            # Second signal — operator is impatient.  Still don't kill the
            # current cycle (a partial publish corrupts OpenCTI's state),
            # but log loudly so they know we heard them.
            logger.warning(
                f"shutdown signal {signum} received again; "
                f"still finishing current cycle"
            )
            return
        self.requested = True
        self._event.set()
        logger.info(
            f"shutdown signal {signum} received; will exit after current cycle"
        )

    def wait(self, timeout: float) -> bool:
        """Sleep up to `timeout` seconds.  Returns True if a signal arrived."""
        return self._event.wait(timeout=timeout)


# ---------------------------------------------------------------------------
# Cycle window computation
# ---------------------------------------------------------------------------

def _compute_window(
    state: CycleState, cfg: Config, now: datetime
) -> tuple[datetime, datetime]:
    """Return [start, end) for the current ES query window.

    Per V1_SPEC.md §3 (Initial run):
      - If state.last_run is set, use [last_run, now).
      - Else if cfg.cycle.initial_lookback_hours > 0,
        use [now - lookback, now).
      - Else (default v1.0), use [now - 1s, now) — i.e. start fresh
        from "now" with a tiny window.  Next cycle gets the real range.
    """
    last_run = state.get_last_run()
    if last_run is not None:
        if last_run.tzinfo is None:
            last_run = last_run.replace(tzinfo=timezone.utc)
        # Cap pathologically-long windows — if the importer was down for
        # a week, we don't want to pull a week of events in one cycle.
        # 24h is the cap; the catch-up will happen across multiple cycles.
        max_window = timedelta(hours=24)
        if now - last_run > max_window:
            logger.warning(
                f"last_run is {(now - last_run).total_seconds() / 3600:.1f}h "
                f"old; capping window to {max_window} to avoid an overlarge "
                f"single-cycle pull"
            )
            return now - max_window, now
        return last_run, now

    lookback = cfg.cycle.initial_lookback_hours
    if lookback and lookback > 0:
        logger.info(
            f"initial cycle: backfilling {lookback}h "
            f"(TPOT2CTI_INITIAL_LOOKBACK_HOURS={lookback})"
        )
        return now - timedelta(hours=lookback), now

    # Default v1.0: start fresh from "now".  Use a 1-second window so
    # the ES query is a near-no-op; next cycle has a real range.
    logger.info("initial cycle: starting fresh from 'now' (no backfill)")
    return now - timedelta(seconds=1), now


# ---------------------------------------------------------------------------
# run_cycle — one iteration of the main loop
# ---------------------------------------------------------------------------

def run_cycle(
    cfg: Config,
    state: CycleState,
    es: TpotESClient,
    builder_factory,        # callable () -> STIXBuilder (fresh per cycle)
    publisher: Publisher,
    *,
    now: Optional[datetime] = None,
) -> dict:
    """Run ONE importer cycle and return a summary dict.

    Per V1_SPEC.md §3 steps 1-8.  Catch + log + continue at the
    SESSION boundary so a single bad session doesn't lose the whole
    cycle.  Cycle-level exceptions propagate to the main loop, which
    records them via `state.record_cycle_failure`.
    """
    cycle_id = state.start_cycle()
    started_monotonic = time.monotonic()
    now = now or datetime.now(timezone.utc)

    window_start, window_end = _compute_window(state, cfg, now)
    logger.info(
        f"cycle {cycle_id}: window=[{window_start.isoformat()}, "
        f"{window_end.isoformat()}) ignore_types={cfg.cycle.ignore_types}"
    )

    # ── Step 1: ES query ──────────────────────────────────────────────
    events_read = 0
    events_parsed = 0
    events_dropped = 0
    events_self_filtered = 0  # src_ip matched our own honeypot's IP set
    parsed_by_type: dict[str, list[ParsedEvent]] = defaultdict(list)
    sensors_seen: set[str] = set()
    honeypot_ips = cfg.tpot.honeypot_ips  # local ref — frozenset

    try:
        for doc in es.stream_events(
            window_start, window_end,
            index_pattern=cfg.es.index_pattern,
            batch_size=cfg.cycle.batch_size,
            ignore_types=cfg.cycle.ignore_types,
        ):
            events_read += 1
            try:
                event = dispatch(doc)
            except Exception as e:
                events_dropped += 1
                logger.debug(f"cycle {cycle_id}: dispatch raised: {e}")
                continue
            if event is None:
                events_dropped += 1
                continue
            # Self-filter: drop events whose src_ip is one of our own
            # honeypot's public IPs. Suricata observes both directions of
            # traffic; when our honeypot is the source (e.g. it's serving
            # a deceptive `Host: www.google.com` response), the resulting
            # event carries OUR ip as `src_ip` and pollutes the bundle.
            # See the first-live-install postmortem for the exact case
            # that motivated this filter.
            if honeypot_ips and event.src_ip in honeypot_ips:
                events_self_filtered += 1
                continue
            events_parsed += 1
            parsed_by_type[event.event_type].append(event)
            if event.sensor_hostname:
                sensors_seen.add(event.sensor_hostname)
    except Exception as e:
        # ES query failed — record cycle failure and bail (the main loop
        # will sleep and retry the next interval per V1_SPEC §7).
        logger.exception(f"cycle {cycle_id}: ES stream failed: {e}")
        state.record_cycle_failure(
            cycle_id, f"ES stream failed: {e}",
            duration_seconds=time.monotonic() - started_monotonic,
        )
        raise

    logger.info(
        f"cycle {cycle_id}: events_read={events_read} events_parsed={events_parsed} "
        f"events_dropped={events_dropped} events_self_filtered={events_self_filtered} "
        f"types={sorted(parsed_by_type.keys())}"
    )

    # ── Steps 2-4: correlate → build STIX ─────────────────────────────
    builder = builder_factory()
    all_objects: list[dict] = []
    sessions_by_type: dict[str, int] = {}

    # Foundation objects — emitted once per bundle.  Per V1_SPEC §4
    # the operator Identity + TLP marking are always-present.
    all_objects.append(builder.build_operator_identity())
    all_objects.append(builder.build_tlp_marking())

    for type_name, events in parsed_by_type.items():
        parser = get_parser(type_name)
        if parser is None:
            logger.warning(
                f"cycle {cycle_id}: no parser for type={type_name!r} "
                f"(should have hit fallback) — dropping {len(events)} events"
            )
            continue
        try:
            sessions = parser.correlate(events)
        except Exception as e:
            logger.exception(
                f"cycle {cycle_id}: {type(parser).__name__}.correlate "
                f"failed on {len(events)} events: {e}"
            )
            continue
        sessions_by_type[type_name] = len(sessions)

        for session in sessions:
            try:
                # Parsers expose `.build(session, builder) -> list[dict]`
                # which internally chooses between full and drive-by
                # treatment via `parser.has_substance(session)`.
                # See parsers/cowrie.py for the canonical implementation.
                build_fn = getattr(parser, "build", None)
                if build_fn is None:
                    # Fallback: use the substance gate directly + the
                    # generic drive-by builder so we always emit *something*.
                    objs = builder.build_driveby_session(session)
                else:
                    objs = build_fn(session, builder)
                all_objects.extend(objs)
            except Exception as e:
                # Per V1_SPEC §7: caught + logged; cycle continues.
                logger.warning(
                    f"cycle {cycle_id}: session build failed for "
                    f"sensor={session.sensor_hostname!r} "
                    f"src_ip={session.src_ip!r} "
                    f"session_id={session.session_id!r}: {e}"
                )
                logger.debug(traceback.format_exc())

    # Remember which sensors we've seen, so the catch-up scan has a
    # list to iterate over even before any cycle has succeeded.
    if sensors_seen:
        daily_creds.remember_sensors(state, sensors_seen)

    # ── Step 5: daily creds Notes ─────────────────────────────────────
    creds_pairs: list[tuple] = []
    try:
        creds_result = daily_creds.maybe_emit_pending(
            state, es, builder, cfg,
            index_pattern=cfg.es.index_pattern,
        )
        if creds_result.stix_objects:
            all_objects.extend(creds_result.stix_objects)
            creds_pairs = creds_result.pairs
            logger.info(
                f"cycle {cycle_id}: daily_creds added "
                f"{len(creds_result.stix_objects)} objects "
                f"for {len(creds_result.pairs)} (sensor, date) pair(s)"
            )
    except Exception as e:
        logger.exception(
            f"cycle {cycle_id}: daily_creds.maybe_emit_pending failed: {e}"
        )

    # ── Step 6: publish ───────────────────────────────────────────────
    sdos_by_type = _count_by_type(all_objects)
    publish_ok = True
    publish_errors: list[str] = []
    publish_result: Any = None
    try:
        publish_result = publisher.publish(
            all_objects, cycle_id=str(cycle_id)
        )
        # PublishResult shape (Phase 5): may have .ok / .errors / etc.
        publish_ok = bool(getattr(publish_result, "ok", True))
        publish_errors = list(getattr(publish_result, "errors", []) or [])
        logger.info(
            f"cycle {cycle_id}: publish result: {publish_result!r}"
        )
    except Exception as e:
        publish_ok = False
        publish_errors.append(str(e))
        logger.exception(f"cycle {cycle_id}: publisher.publish failed: {e}")

    # ── Step 7: persist state (only on a successful publish) ──────────
    if publish_ok:
        state.set_last_run(window_end)
        # Record daily-creds emissions ONLY after a successful publish,
        # so a failed publish doesn't poison the log (next cycle retries).
        for sensor, utc_date in creds_pairs:
            try:
                state.record_daily_creds_emitted(sensor, utc_date)
            except Exception as e:  # pragma: no cover — sqlite is reliable
                logger.warning(
                    f"cycle {cycle_id}: record_daily_creds_emitted({sensor}, "
                    f"{utc_date}) failed: {e}"
                )
    else:
        logger.warning(
            f"cycle {cycle_id}: publish failed; NOT advancing last_run "
            f"or daily_creds_log (next cycle will retry the same window)"
        )

    # ── Step 8: cycle summary ─────────────────────────────────────────
    duration_s = time.monotonic() - started_monotonic
    summary = {
        "cycle_id": cycle_id,
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "events_read": events_read,
        "events_parsed": events_parsed,
        "events_dropped": events_dropped,
        "sessions_by_type": sessions_by_type,
        "sdos_emitted": len(all_objects),
        "sdos_by_type": dict(sdos_by_type),
        "daily_creds_pairs": [(s, d.isoformat()) for s, d in creds_pairs],
        "publish_ok": publish_ok,
        "publish_errors": publish_errors,
        "duration_seconds": round(duration_s, 3),
    }

    state.record_cycle(
        cycle_id,
        success=publish_ok,
        events_read=events_read,
        events_parsed=events_parsed,
        events_dropped=events_dropped,
        sdos_emitted=len(all_objects),
        errors_count=len(publish_errors),
        duration_seconds=duration_s,
    )

    logger.info(
        f"cycle {cycle_id}: complete in {duration_s:.2f}s — "
        f"events_read={events_read} sdos_emitted={len(all_objects)} "
        f"sdos_by_type={dict(sdos_by_type)} publish_ok={publish_ok}"
    )
    return summary


def _count_by_type(objects: list[dict]) -> dict[str, int]:
    """Count STIX objects by their `type` field (for cycle summary)."""
    counts: dict[str, int] = defaultdict(int)
    for o in objects:
        t = o.get("type", "unknown")
        counts[t] += 1
    return dict(counts)


# ---------------------------------------------------------------------------
# main() — entrypoint
# ---------------------------------------------------------------------------

def main() -> int:
    """Container entrypoint.  Returns the process exit code."""
    # 1) Load config — fail fast on missing required env vars.
    cfg = load_config()

    # 2) Configure JSON logging.  Per LESSONS_LEARNED §8.1 we set up
    #    BEFORE constructing pycti-using clients and restore AFTER.
    setup_logging(
        log_level=cfg.logging.level,
        log_retention_days=cfg.logging.retention_days,
        connector_name="tpot2cti",
        log_file=os.path.join(cfg.logging.log_dir, "tpot2cti.log"),
    )

    logger.info(
        f"tpot2cti starting — operator={cfg.operator.org_name!r} "
        f"tlp={cfg.operator.default_tlp} "
        f"interval={cfg.cycle.interval_iso} "
        f"tpot={cfg.tpot.host}:{cfg.tpot.ssh_port}"
    )

    # 3) State + ES + OpenCTI + Publisher.
    state_db = os.environ.get(
        "TPOT2CTI_STATE_DB", "/data/state.db"
    )
    state = CycleState(db_path=state_db)
    es = TpotESClient(
        host=cfg.es.host,
        port=cfg.es.port,
        scheme=cfg.es.scheme,
        username=cfg.es.username,
        password=cfg.es.password,
        verify_certs=cfg.es.verify_certs,
        request_timeout=cfg.es.request_timeout,
    )
    # Per LESSONS_LEARNED §8.2: OpenCTIClient requires both the platform
    # config AND a non-empty connector_id (pycti accepts an empty one
    # then fails asynchronously with BAD_USER_INPUT).  We pass the core
    # connector UUID from setup.sh's generation.
    opencti = OpenCTIClient(cfg.opencti, connector_id=cfg.connector_ids.core)
    restore_logging()      # pycti's __init__ may have clobbered handlers
    publisher = Publisher(opencti, state=state)

    # Builder is per-cycle (bundle-scoped dedup); pass a factory.
    def builder_factory() -> STIXBuilder:
        return STIXBuilder(cfg)

    # 4) Health endpoint — start before the first cycle so docker-compose
    #    healthcheck can probe immediately (it will read 503 until the
    #    first cycle lands, which is correct).
    interval_s = parse_iso_duration_seconds(cfg.cycle.interval_iso, default_seconds=900.0)
    health_bind = os.environ.get("TPOT2CTI_HEALTH_BIND", "0.0.0.0:8080")
    health = HealthServer(
        state, opencti,
        bind=health_bind,
        cycle_interval_seconds=interval_s,
    )
    health.start_in_background()

    # 5) Signal handlers — SIGTERM/SIGINT → finish current cycle, exit.
    shutdown = _Shutdown()
    signal.signal(signal.SIGTERM, shutdown.request)
    signal.signal(signal.SIGINT, shutdown.request)

    # 6) Main loop.
    exit_code = 0
    try:
        while not shutdown.requested:
            cycle_started = time.monotonic()
            try:
                run_cycle(cfg, state, es, builder_factory, publisher)
            except Exception as e:
                # Cycle failed (ES error, publisher crashed, etc.).  Per
                # V1_SPEC §7: log, record, sleep, continue.  Don't crash
                # — the container restart policy is a last-resort safety,
                # not our primary recovery mechanism.
                logger.exception(f"cycle failed: {e}")

            if shutdown.requested:
                break

            # Sleep until the next cycle boundary, but wake immediately
            # on shutdown signal.
            elapsed = time.monotonic() - cycle_started
            sleep_for = max(0.0, interval_s - elapsed)
            logger.debug(
                f"sleeping {sleep_for:.1f}s until next cycle "
                f"(interval={interval_s:.0f}s, elapsed={elapsed:.1f}s)"
            )
            if shutdown.wait(sleep_for):
                break
    finally:
        logger.info("tpot2cti shutting down")
        try:
            health.stop()
        except Exception as e:
            logger.debug(f"health.stop() raised (ignored): {e}")
        try:
            es.close()
        except Exception as e:
            logger.debug(f"es.close() raised (ignored): {e}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
