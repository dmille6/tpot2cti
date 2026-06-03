"""tpot2cti — main importer entrypoint and cycle loop.

This module wires together every Phase 1-5 piece:

  - `config.load_config()`        — load env / yaml
  - `log.setup_logging()`         — JSON logs to stdout + rotated file
  - `state.CycleState`            — SQLite-backed cycle bookkeeping
  - `es_client.TpotESClient`      — read T-Pot's ES via SSH tunnel
  - `parsers.dispatch()`          — type → parser dispatch
  - `parsers.<P>.correlate()`     — events → sessions
  - `parsers.<P>.build()`         — sessions → STIX (substance-filtered)
  - `credential_store` + `build_ip_credential_note()` — bruteforce pairs to
    the local store; one per-IP summary Note to OpenCTI
  - `publisher.Publisher.publish()` (Phase 5)  — three-pass send to OpenCTI
  - `opencti_client.OpenCTIClient` (Phase 5)
  - `health.HealthServer`         — /health endpoint

Per V1_SPEC.md §3 (cycle behavior) the loop is:

    every TPOT2CTI_INTERVAL (default PT15M):
        1. ES query for events since last_run
        2. dispatch each doc → ParsedEvent
        3. group by parser type_name → correlate → AttackSessions
        4. parser.build(session, builder) → STIX objects
        5. credentials → store (bulk) + one per-IP summary Note
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

from tpot2cti import attacker_profile
from tpot2cti import campaigns
from tpot2cti.config import Config, ConfigError, load_config
from tpot2cti.credential_store import CredentialStore
from tpot2cti.es_client import TpotESClient
from tpot2cti.net import wait_for_host
from tpot2cti.health import HealthServer, parse_iso_duration_seconds
from tpot2cti.log import restore_logging, setup_logging
from tpot2cti.benign_filter import BenignScannerFilter, FilterStats
from tpot2cti.parsers import dispatch, get_parser
from tpot2cti.parsers.base import AttackSession, ParsedEvent
from tpot2cti.state import CycleState
from tpot2cti.stix.builder import STIXBuilder

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Parser → builder-method dispatch (the V0 parser-vs-builder separation rule)
# ---------------------------------------------------------------------------
# Parsers stay pure (parse + correlate + has_substance). The per-parser
# STIX shape lives in STIXBuilder.build_<x>_session methods. The
# orchestrator dispatches via session.event_type. Anything not listed
# here flows through builder.build_driveby_session() (the minimal
# IP+Sighting graph used for one-shot probes).
#
# Add a row when a parser gains a dedicated builder method.
_PARSER_DISPATCH: dict[str, str] = {
    "Cowrie":       "build_cowrie_session",
    "Suricata":     "build_suricata_alert",
    "Honeytrap":    "build_honeytrap_probe",
    # Web / HTTP honeypot family → build_<type>_session (shared _build_web_session)
    "Galah":        "build_galah_session",
    # Galah's LLM-response subtypes (separate parser instances) → same builder
    "cacheHit":            "build_galah_session",
    "successfulResponse":  "build_galah_session",
    "failedResponse":      "build_galah_session",
    "emptyLLMResponse":    "build_galah_session",
    "invalidJSONResponse": "build_galah_session",
    "contentGenerationError": "build_galah_session",
    "Tanner":       "build_tanner_session",
    "H0neytr4p":    "build_h0neytr4p_session",
    "ElasticPot":   "build_elasticpot_session",
    "Ciscoasa":     "build_ciscoasa_session",
    "Wordpot":      "build_wordpot_session",
    "NGINX":        "build_nginx_session",
    "Honeyaml":     "build_honeyaml_session",
    # Malware-drop family → File + indicator + download URL/domain + drops
    "Adbhoney":     "build_adbhoney_session",
    "Dionaea":      "build_dionaea_session",
    # Fingerprint family → HASSH/JA3 Cryptographic-Key
    "Fatt":         "build_fatt_session",
    # Protocol / ICS / VoIP / shell family → protocol AttackPattern + Process
    "ConPot":       "build_conpot_session",
    "Dicompot":     "build_dicompot_session",
    "Ipphoney":     "build_ipphoney_session",
    "Redishoneypot": "build_redishoneypot_session",
    "Sentrypeer":   "build_sentrypeer_session",
    "Miniprint":    "build_miniprint_session",
    "Medpot":       "build_medpot_session",
    "Router":       "build_router_session",
    "Heralding":    "build_heralding_session",
    "Mailoney":     "build_mailoney_session",
    "Beelzebub":    "build_beelzebub_session",
    "__fallback__": "build_fallback_event",
}


from tpot2cti.publisher import Publisher, PublishResult
from tpot2cti.opencti_client import OpenCTIClient


# ---------------------------------------------------------------------------
# OpenCTI connect — patient startup so a cold platform doesn't crash-loop us
# ---------------------------------------------------------------------------

def _connect_opencti(cfg: Config, *, connector_id: str) -> OpenCTIClient:
    """Construct an :class:`OpenCTIClient`, waiting for the platform.

    pycti's client constructor does a synchronous GraphQL health check and
    raises if OpenCTI isn't answering yet. After a full-stack restart the
    platform can take minutes to come up (ES / Redis / migrations), so the
    naive ``OpenCTIClient(...)`` call used to raise on the first probe,
    crash ``main()``, and rely on the container restart policy — producing
    a noisy crash loop (an ERROR traceback every ~20s, inflated restart
    count) until OpenCTI was finally ready.

    Instead we poll the TCP port first (cheap, no pycti import / no ERROR
    log), then retry client construction with capped backoff until
    ``cfg.opencti.connect_timeout_seconds`` elapses. Only then do we give
    up and re-raise (container restart = genuine last resort). A real
    misconfiguration (:class:`ConfigError`, e.g. empty connector id) is
    NOT retried — it can never succeed — so it propagates immediately.

    This mirrors the existing :func:`tpot2cti.net.wait_for_host` cold-start
    handling for the SSH tunnel (LESSONS §10) and the health endpoint's
    deliberate refusal to couple our liveness to OpenCTI's (health.py).
    """
    from urllib.parse import urlparse

    deadline_s = max(0, int(cfg.opencti.connect_timeout_seconds))
    parsed = urlparse(cfg.opencti.url)
    host = parsed.hostname or "opencti"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    deadline = time.monotonic() + deadline_s
    backoff = 5.0
    attempt = 0
    while True:
        attempt += 1
        # TCP reachability first — absorbs the common "port not open yet"
        # window without paying pycti's ValueError + traceback.
        remaining = deadline - time.monotonic()
        if remaining > 0:
            wait_for_host(
                host, port,
                timeout=int(min(remaining, 30)),
                interval=2.0,
            )
        try:
            return OpenCTIClient(cfg.opencti, connector_id=connector_id)
        except ConfigError:
            # Misconfiguration — retrying can't help. Fail fast.
            raise
        except Exception as e:  # noqa: BLE001 — pycti raises ValueError etc.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                logger.error(
                    f"OpenCTI not reachable at {cfg.opencti.url} after "
                    f"{attempt} attempt(s) / {deadline_s}s — giving up "
                    f"(container restart policy takes over): "
                    f"{type(e).__name__}: {e}"
                )
                raise
            logger.warning(
                f"OpenCTI not ready at {cfg.opencti.url} "
                f"(attempt {attempt}, {remaining:.0f}s left): "
                f"{type(e).__name__}: {e}. Retrying in {backoff:.0f}s."
            )
            time.sleep(min(backoff, max(0.0, remaining)))
            backoff = min(backoff * 1.5, 30.0)


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
        """Signal handler: politely ask the cycle loop to exit after the
        current cycle finishes. Idempotent — a second signal logs but
        doesn't escalate (partial publish corrupts OpenCTI state, so we
        always let the in-flight cycle complete).
        """
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

def _session_credential_attempts(session) -> list[dict]:
    """Flatten a session's credential attempts into credential-store rows.

    The pair the honeypot accepted (``session.successful_credential``) is
    marked ``success=True``. service/port come from the session's protocol
    + dst_port; geo from the first event. These rows go to the credential
    store (bulk), NOT to OpenCTI — only a per-IP summary Note does.
    """
    first = session.events[0] if session.events else None
    service = (
        (sorted(session.protocols)[0] if session.protocols else None)
        or (first.protocol if first else None)
        or session.event_type.lower()
    )
    port = (
        (sorted(session.dst_ports)[0] if session.dst_ports else None)
        or (first.dst_port if first else None)
        or 0
    )
    succ = session.successful_credential
    rows: list[dict] = []
    for pair in session.credentials_tried:
        u, p = pair
        rows.append({
            "username": u, "password": p,
            "attacker_ip": session.src_ip,
            "honeypot_name": session.sensor_hostname,
            "honeypot_type": session.event_type,
            "service": str(service), "port": int(port) if port else 0,
            "when": session.last_seen,
            "success": succ is not None and tuple(pair) == tuple(succ),
            "country": getattr(first, "src_country_code", None) if first else None,
            "asn": getattr(first, "src_asn", None) if first else None,
            "org": getattr(first, "src_as_org", None) if first else None,
        })
    return rows


def run_cycle(
    cfg: Config,
    state: CycleState,
    es: TpotESClient,
    builder_factory,        # callable () -> STIXBuilder (fresh per cycle)
    publisher: Publisher,
    *,
    now: Optional[datetime] = None,
    benign_filter: Optional[BenignScannerFilter] = None,
    credential_store=None,  # Optional[CredentialStore]
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
    # Liveness heartbeat — a cycle is now in progress. Bumped again after
    # the ES stream and after each publisher pass so /health stays at 200
    # for a long-running cycle instead of flapping the container to
    # "unhealthy". See state.heartbeat() / health.compute_status().
    state.heartbeat()

    window_start, window_end = _compute_window(state, cfg, now)

    # FATT cadence split (PoC pattern): FATT fingerprints are slowly-
    # evolving passive observations; processing them every cycle is
    # wasteful. Skip them unless the cycle index is a multiple of
    # cfg.cycle.fatt_cycle_multiplier. With default multiplier=4 and
    # base interval PT15M, FATT is processed every ~60 min.
    effective_ignore_types = list(cfg.cycle.ignore_types)
    try:
        cycle_n = int(cycle_id)
    except (TypeError, ValueError):
        cycle_n = 0  # str cycle ids: never skip
    fatt_mult = max(1, cfg.cycle.fatt_cycle_multiplier)
    fatt_this_cycle = fatt_mult == 1 or (cycle_n > 0 and cycle_n % fatt_mult == 0)
    if not fatt_this_cycle and "Fatt" not in effective_ignore_types:
        effective_ignore_types.append("Fatt")

    logger.info(
        f"cycle {cycle_id}: window=[{window_start.isoformat()}, "
        f"{window_end.isoformat()}) ignore_types={effective_ignore_types} "
        f"fatt_this_cycle={fatt_this_cycle}"
    )

    # ── Step 1: ES query ──────────────────────────────────────────────
    events_read = 0
    events_parsed = 0
    events_dropped = 0
    events_self_filtered = 0  # src_ip matched our own honeypot's IP set
    parsed_by_type: dict[str, list[ParsedEvent]] = defaultdict(list)
    honeypot_ips = cfg.tpot.honeypot_ips  # local ref — frozenset
    benign_stats = FilterStats()  # populated by benign-scanner allowlist below

    try:
        for doc in es.stream_events(
            window_start, window_end,
            index_pattern=cfg.es.index_pattern,
            batch_size=cfg.cycle.batch_size,
            ignore_types=effective_ignore_types,
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
            # Benign-scanner allowlist: drop events from Google / Censys /
            # Shodan / Shadowserver / Internet-Archive etc. before they
            # become Indicators. Per the user decision: "we can't blanket
            # report google as malicious that's silly" — these aren't
            # attackers, they're internet-wide research scanners. See
            # tpot2cti/data/benign_scanners.yaml for the source list.
            if benign_filter is not None:
                benign_vendor = benign_filter.match(event)
                if benign_vendor:
                    benign_stats.record(benign_vendor)
                    continue
            events_parsed += 1
            parsed_by_type[event.event_type].append(event)
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
        f"events_benign={benign_stats.total_filtered} "
        f"benign_by_vendor={dict(benign_stats.by_vendor)} "
        f"types={sorted(parsed_by_type.keys())}"
    )
    state.heartbeat()  # ES stream done — still alive before build/publish.

    # ── Steps 2-4: correlate → build STIX ─────────────────────────────
    builder = builder_factory()
    all_objects: list[dict] = []
    sessions_by_type: dict[str, int] = {}
    # Per-cycle set of attacker IPs that contributed at least one session
    # to a profile-emitting parser. Drives emit_live_profile_notes() at
    # the end of the cycle (see tpot2cti/attacker_profile.py).
    profile_active_ips: set[str] = set()
    # Per-cycle credential capture — bulk pairs go to the credential store
    # (NOT OpenCTI); one Note per attacker IP summarises them. See
    # tpot2cti/credential_store.py + docs/credential-store.md.
    cred_attempts: list[dict] = []
    cred_ips: set[str] = set()
    # Per-cycle set of shared-IoC artifact keys observed; re-checked for
    # >=2-IP campaign thresholds after the build loop (see tpot2cti/campaigns.py).
    campaign_keys: set[str] = set()

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
            # Feed the attacker-profile aggregator BEFORE STIX build so
            # even a build-time exception doesn't cost us the activity
            # signal (the per-cycle live-profile emitter runs after the
            # main build pass and reads the SQLite state independently).
            try:
                attacker_profile.update_activity_from_session(state, session)
                if session.src_ip and session.event_type in (
                    attacker_profile._PROFILE_PARSERS
                ):
                    profile_active_ips.add(session.src_ip)
            except Exception as e:  # pragma: no cover — defensive
                logger.debug(
                    f"cycle {cycle_id}: attacker_profile.update_activity_from_session "
                    f"raised (ignored): {e}"
                )
            # Shared-IoC campaign ledger — record this session's concrete
            # artifacts (malware/ssh-key/hassh/ja3) for cross-cycle >=2-IP
            # grouping. record_session_artifacts is itself defensive.
            campaign_keys.update(campaigns.record_session_artifacts(state, session))
            # Credential capture — accumulate for the store + per-IP Note.
            # Done before the STIX build so a build-time error doesn't cost
            # us the credential record.
            if credential_store is not None and session.credentials_tried and session.src_ip:
                try:
                    cred_attempts.extend(_session_credential_attempts(session))
                    cred_ips.add(session.src_ip)
                except Exception as e:  # pragma: no cover — defensive
                    logger.debug(f"cycle {cycle_id}: credential capture raised (ignored): {e}")
            try:
                # Per the V0 parser-vs-builder separation rule: parsers are pure data; STIX-shape
                # decisions live on the builder. We dispatch by the
                # PARSER's type_name (not session.event_type — which
                # carries the raw T-Pot type even when the fallback
                # parser handled it). Parsers without a dedicated builder
                # method route through build_driveby_session (the ~20
                # parsers that produce the minimal IP + Sighting graph).
                method_name = _PARSER_DISPATCH.get(parser.type_name)
                if method_name and hasattr(builder, method_name):
                    objs = getattr(builder, method_name)(session)
                elif method_name:
                    # Listed in dispatch table but the builder doesn't
                    # have the method — programmer error, not data error.
                    logger.error(
                        f"_PARSER_DISPATCH names {method_name!r} for "
                        f"parser type_name={parser.type_name!r} but "
                        f"builder has no such method; falling back to "
                        f"build_driveby_session"
                    )
                    objs = builder.build_driveby_session(session)
                else:
                    objs = builder.build_driveby_session(session)
                all_objects.extend(objs)
                # Behaviour-driven ATT&CK techniques — applies uniformly to
                # EVERY parser from the normalised session signals (not just
                # Suricata/web). See tpot2cti/attack_mapping.py.
                all_objects.extend(builder.build_session_attack_patterns(session))
            except Exception as e:
                # Per V1_SPEC §7: caught + logged; cycle continues.
                logger.warning(
                    f"cycle {cycle_id}: session build failed for "
                    f"sensor={session.sensor_hostname!r} "
                    f"src_ip={session.src_ip!r} "
                    f"session_id={session.session_id!r}: {e}"
                )
                logger.debug(traceback.format_exc())

    # ── Step 5: credentials → store (bulk) + one Note per attacker IP ──
    # Bruteforce runs are tens of thousands of pairs; we keep them OUT of
    # OpenCTI (credential_store) and emit only a per-IP summary Note with
    # the pairs tried + which was accepted. Replaces the old daily
    # top-100-per-sensor Note (per the 2026-06-02 user decision). The bulk
    # detail stays queryable in the local store / can feed exports.
    if credential_store is not None:
        try:
            n_written = credential_store.record_attempts(cred_attempts)
            n_notes = 0
            for ip in sorted(cred_ips):
                try:
                    rows = credential_store.get_ip_credentials(ip)
                    note = builder.build_ip_credential_note(ip, rows)
                    if note:
                        all_objects.append(note)
                        n_notes += 1
                except Exception as e:
                    logger.warning(
                        f"cycle {cycle_id}: credential Note for {ip} failed: {e}"
                    )
            if n_written or n_notes:
                logger.info(
                    f"cycle {cycle_id}: credentials — {n_written} attempt(s) "
                    f"stored, {n_notes} per-IP Note(s) emitted"
                )
        except Exception as e:
            logger.exception(
                f"cycle {cycle_id}: credential store/note emission failed: {e}"
            )

    # ── Step 5a: shared-IoC Campaigns ─────────────────────────────────
    # Materialise a Campaign for any concrete artifact (malware / planted
    # SSH key / HASSH / JA3) now shared by >=2 distinct attacker IPs — the
    # "same actor/toolkit" signal. See tpot2cti/campaigns.py.
    try:
        campaign_objs = campaigns.emit_campaigns(state, builder, list(campaign_keys))
        if campaign_objs:
            all_objects.extend(campaign_objs)
            logger.info(
                f"cycle {cycle_id}: campaigns emit added "
                f"{len(campaign_objs)} object(s) "
                f"(from {len(campaign_keys)} candidate artifact(s))"
            )
    except Exception as e:
        logger.exception(
            f"cycle {cycle_id}: campaigns.emit_campaigns failed: {e}"
        )

    # ── Step 5b: attacker-profile Notes (live + daily + weekly) ───────
    # Replaces the per-session Cowrie Notes formerly emitted by
    # STIXBuilder.build_cowrie_session. See tpot2cti/attacker_profile.py
    # and the 2026-05-21 user decision (the V0 "don't emit 50K Notes/day" finding).
    try:
        live_objs = attacker_profile.emit_live_profile_notes(
            state, builder, profile_active_ips,
        )
        if live_objs:
            all_objects.extend(live_objs)
            logger.info(
                f"cycle {cycle_id}: attacker_profile live emit added "
                f"{len(live_objs)} object(s) for "
                f"{len(profile_active_ips)} active IP(s)"
            )
    except Exception as e:
        logger.exception(
            f"cycle {cycle_id}: attacker_profile.emit_live_profile_notes "
            f"failed: {e}"
        )

    try:
        boundary_objs = attacker_profile.maybe_emit_daily_and_weekly(
            state, builder, now=now,
        )
        if boundary_objs:
            all_objects.extend(boundary_objs)
            logger.info(
                f"cycle {cycle_id}: attacker_profile daily/weekly emit "
                f"added {len(boundary_objs)} object(s)"
            )
    except Exception as e:
        logger.exception(
            f"cycle {cycle_id}: attacker_profile.maybe_emit_daily_and_weekly "
            f"failed: {e}"
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
    else:
        logger.warning(
            f"cycle {cycle_id}: publish failed; NOT advancing last_run "
            f"(next cycle will retry the same window)"
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

    # State-DB hygiene (per 2026-05-22 audit #2): prune bounded tables
    # every cycle and run VACUUM monthly. Failure here is non-fatal — we
    # log and continue so a stuck VACUUM never blocks a cycle.
    try:
        prune_counts = state.prune_all()
        vacuumed = state.maybe_vacuum(min_age_days=30)
        db_size_mb = state.db_size_bytes() / (1024 * 1024)
        if any(prune_counts.values()) or vacuumed:
            logger.info(
                f"cycle {cycle_id}: state-db hygiene pruned={prune_counts} "
                f"vacuumed={vacuumed} db_size={db_size_mb:.1f}MB"
            )
        summary["db_size_mb"] = round(db_size_mb, 2)
        summary["prune_counts"] = prune_counts
    except Exception as e:
        logger.warning(f"cycle {cycle_id}: state-db hygiene failed (non-fatal): {e}")

    # Surface bundle-dedup % per LESSONS §6 (bundle dedup with label-union):
    # the label-union pass should be cutting ~20-25% before send. If our
    # ratio drops to ~0% it likely means parsers aren't emitting labels
    # (each cycle starts clean — no dedup hits); if it spikes above ~40%
    # it means we're re-emitting more than we should and the call sites
    # need investigation.
    dedup_pct = getattr(publish_result, "dedup_reduction_pct", 0.0)
    dedup_before = getattr(publish_result, "total_objects_before_dedup", 0)
    dedup_after = getattr(publish_result, "total_objects_after_dedup", 0)
    logger.info(
        f"cycle {cycle_id}: complete in {duration_s:.2f}s — "
        f"events_read={events_read} sdos_emitted={len(all_objects)} "
        f"sdos_by_type={dict(sdos_by_type)} publish_ok={publish_ok} "
        f"dedup={dedup_before}->{dedup_after} ({dedup_pct:.1f}%)"
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

    # 2) Configure JSON logging.  Per LESSONS §8.1 we set up
    #    BEFORE constructing pycti-using clients and restore AFTER.
    setup_logging(
        log_level=cfg.logging.level,
        log_retention_days=cfg.logging.retention_days,
        connector_name="tpot2cti",
        log_file=os.path.join(cfg.logging.log_dir, "tpot2cti.log"),
    )

    # Build a richer startup banner so post-upgrade "which build is
    # running" is answerable from logs alone (audit #L6). Best-effort —
    # any sub-piece that fails to resolve drops to "unknown" rather than
    # blocking startup.
    def _banner_bits() -> dict:
        bits = {}
        # Git SHA from build-time env (Dockerfile ARG)
        bits["git_sha"] = os.environ.get("TPOT2CTI_GIT_SHA", "unknown")[:12]
        # pycti version — already imported via OpenCTIClient module
        try:
            import pycti  # type: ignore
            bits["pycti"] = getattr(pycti, "__version__", "unknown")
        except Exception:
            bits["pycti"] = "unknown"
        # Config fingerprint (excluding secrets) — short hash so an
        # operator can compare "same config across containers" without
        # leaking tokens.
        import hashlib as _h
        cfg_fp = {
            "tlp": cfg.operator.default_tlp,
            "interval": cfg.cycle.interval_iso,
            "tpot": f"{cfg.tpot.host}:{cfg.tpot.ssh_port}",
            "ignore_types": sorted(cfg.cycle.ignore_types),
            "batch": cfg.cycle.batch_size,
            "fatt_mult": cfg.cycle.fatt_cycle_multiplier,
        }
        bits["cfg_hash"] = _h.sha256(repr(sorted(cfg_fp.items())).encode()).hexdigest()[:8]
        return bits

    _bits = _banner_bits()
    logger.info(
        f"tpot2cti starting — operator={cfg.operator.org_name!r} "
        f"tlp={cfg.operator.default_tlp} "
        f"interval={cfg.cycle.interval_iso} "
        f"tpot={cfg.tpot.host}:{cfg.tpot.ssh_port} "
        f"git_sha={_bits['git_sha']} pycti={_bits['pycti']} "
        f"cfg_hash={_bits['cfg_hash']} "
        f"ignore_types={sorted(cfg.cycle.ignore_types)}"
    )

    # 2.5) Parser-registry parity check (per 2026-05-22 audit #8).
    #
    # The two dispatch tables in builder.py (_PARSER_LABEL_VOCAB and
    # _INDICATOR_NAME_TEMPLATES) MUST list the same parser type_name set
    # as the runtime parser registry — otherwise events fall through to
    # generic fallback labels / name templates ("Honeypot Attacker —
    # 1.2.3.4 (1 event)") and operators lose per-honeypot scannability.
    # We log a WARNING (not fatal) so a brand-new parser added before
    # its vocab entry doesn't break the container — just makes the gap
    # impossible to miss at startup.
    try:
        from tpot2cti.parsers import registered_types, FALLBACK_KEY
        from tpot2cti.stix.builder import (
            _PARSER_LABEL_VOCAB, _INDICATOR_NAME_TEMPLATES,
        )
        runtime_parsers = set(registered_types()) | {FALLBACK_KEY}
        vocab_keys = set(_PARSER_LABEL_VOCAB.keys())
        templ_keys = set(_INDICATOR_NAME_TEMPLATES.keys())
        missing_in_vocab = runtime_parsers - vocab_keys
        missing_in_templ = runtime_parsers - templ_keys
        extra_in_vocab = vocab_keys - runtime_parsers
        extra_in_templ = templ_keys - runtime_parsers
        if missing_in_vocab or missing_in_templ or extra_in_vocab or extra_in_templ:
            logger.warning(
                f"parser-registry parity drift: "
                f"missing_in_vocab={sorted(missing_in_vocab)} "
                f"missing_in_templ={sorted(missing_in_templ)} "
                f"extra_in_vocab={sorted(extra_in_vocab)} "
                f"extra_in_templ={sorted(extra_in_templ)} — "
                f"events may emit with generic labels / names"
            )
        else:
            logger.info(
                f"parser-registry parity OK: {len(runtime_parsers)} parsers "
                f"(vocab + name-templates match registry)"
            )
    except Exception as e:  # pragma: no cover — defensive
        logger.debug(f"parser-registry parity check skipped: {e}")

    # 3) State + ES + OpenCTI + Publisher.
    state = CycleState(db_path=cfg.runtime.state_db_path)
    # Credential store — bulk bruteforce pairs live here (SQLite), NOT in
    # OpenCTI; the cycle emits only a per-IP summary Note. Best-effort: a
    # store failure must not stop ingestion.
    credential_store = None
    try:
        credential_store = CredentialStore(db_path=cfg.runtime.credential_db_path)
    except Exception as e:
        logger.warning(f"credential store unavailable (continuing without it): {e}")
    es = TpotESClient(
        host=cfg.es.host,
        port=cfg.es.port,
        scheme=cfg.es.scheme,
        username=cfg.es.username,
        password=cfg.es.password,
        verify_certs=cfg.es.verify_certs,
        request_timeout=cfg.es.request_timeout,
    )
    # Per LESSONS §8.2: OpenCTIClient requires both the platform
    # config AND a non-empty connector_id (pycti accepts an empty one
    # then fails asynchronously with BAD_USER_INPUT).  We pass the core
    # connector UUID from setup.sh's generation.
    #
    # _connect_opencti waits for a cold platform instead of crashing on
    # the first probe (the old behavior crash-looped the container after
    # a stack restart until OpenCTI warmed up). See _connect_opencti.
    opencti = _connect_opencti(cfg, connector_id=cfg.connector_ids.core)
    restore_logging()      # pycti's __init__ may have clobbered handlers
    publisher = Publisher(
        opencti, state=state,
        indexing_delay_seconds=cfg.cycle.indexing_delay_seconds,
    )

    # Benign-scanner allowlist — static yaml, loaded once at startup.
    # Filters events from Google / Censys / Shodan / Shadowserver /
    # Internet-Archive at parse time. See benign_filter.py.
    benign_filter = BenignScannerFilter.from_yaml()

    # Builder is per-cycle (bundle-scoped dedup); pass a factory.
    def builder_factory() -> STIXBuilder:
        """Return a fresh ``STIXBuilder`` for one cycle.

        Each cycle gets its own builder instance so the per-bundle
        dedup state (which Identity / Location / AS objects have
        already been emitted in *this* bundle) doesn't leak between
        cycles. Used by ``run_cycle()`` once per cycle.
        """
        return STIXBuilder(cfg)

    # 4) Health endpoint — start before the first cycle so docker-compose
    #    healthcheck can probe immediately (it will read 503 until the
    #    first cycle lands, which is correct).
    interval_s = parse_iso_duration_seconds(cfg.cycle.interval_iso, default_seconds=900.0)
    health = HealthServer(
        state, opencti,
        bind=cfg.runtime.health_bind,
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
                run_cycle(cfg, state, es, builder_factory, publisher,
                          benign_filter=benign_filter,
                          credential_store=credential_store)
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
            #
            # Cycle-overrun guard: if the cycle ran longer than the
            # configured interval (e.g. a 27-min publish at hive scale
            # against a PT15M interval), we log a WARNING and apply a
            # minimum-breathing-room sleep so OpenCTI's worker has a
            # chance to catch up before we slam it with the next bundle.
            # Per PoC HP_CONNECTOR_HANDOFF §4: at hive scale,
            # indexing_delay_seconds=300 + back-to-back cycles is how
            # they avoid worker queue-depth blowups.
            elapsed = time.monotonic() - cycle_started
            _MIN_INTER_CYCLE_BREATHING_S = 10.0
            sleep_for = max(_MIN_INTER_CYCLE_BREATHING_S, interval_s - elapsed)
            if elapsed > interval_s:
                logger.warning(
                    f"cycle overrun: ran {elapsed:.0f}s (interval={interval_s:.0f}s); "
                    f"sleeping minimum {_MIN_INTER_CYCLE_BREATHING_S:.0f}s before next cycle. "
                    f"Consider raising TPOT2CTI_INDEXING_DELAY_SECONDS (currently "
                    f"{cfg.cycle.indexing_delay_seconds}s) or TPOT2CTI_INTERVAL "
                    f"(currently {cfg.cycle.interval_iso}) per PoC HP_CONNECTOR_HANDOFF §4."
                )
            else:
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
        if credential_store is not None:
            try:
                credential_store.close()
            except Exception as e:
                logger.debug(f"credential_store.close() raised (ignored): {e}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
