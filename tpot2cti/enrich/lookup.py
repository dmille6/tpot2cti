"""Lane B — budgeted per-object lookups (docs/ENRICHMENT.md §3, §6, §11 phase B).

Lane A matches downloaded lists locally and costs zero per-object calls. Lane B
calls a provider once per object, so its health question is different — *"is the
quota exhausted?"* rather than *"is the list stale?"* — which is why the two are
deliberately not merged: a combined health signal cannot honestly answer either.

WHAT SHIPS HERE (phase B): the two Tier-0 sources, InternetDB and CIRCL
hashlookup. Neither needs a key. Tier 1/2 sources plug into the same registry
and self-disable when their credential is absent.

WHY LANE A AND C SHIPPED FIRST — measured, not assumed (§6): attacker IPs
repeat 2.19x over 7 days so a cache removes ~54% of lookups, but ~16,000 new
IPs/day against a 1,000/day free tier is still only ~6% coverage. The noise gate
(which shrinks the candidate set) and the cache (which removes repeats) are both
required before a metered source is worth wiring at all.

HEALTH STATES (§6) — the reason this module exists in this shape:

    healthy            recent successful work                      200
    quiet              no eligible candidates                      200
    budget-exhausted   quota spent — explicitly healthy and NAMED  200
    stalled-with-work  backlog > 0 AND budget > 0 AND calls == 0   503

`budget-exhausted` must be healthy and named or the alarm gets ignored.
`stalled-with-work` is the condition this project has twice needed and never
asserted. It arms only AFTER the first successful cycle, so a fresh install
stays healthy.
"""
from __future__ import annotations

import logging
import os
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from tpot2cti.config import ConfigError, load_config
from tpot2cti.enrich.ledger import EnrichmentLedger
from tpot2cti.enrich.lookup_sources import (
    DEFAULT_SOURCES, LookupError_, LookupSource, is_ipv4, selected_sources,
)
from tpot2cti.enrich.sweep import ActivityReadError, SweepCursor, read_activity
from tpot2cti.health import HealthServer, parse_iso_duration_seconds
from tpot2cti.log import restore_logging, setup_logging
from tpot2cti.state import CycleState

logger = logging.getLogger(__name__)

SOURCES_ENV = "ENRICH_LOOKUP_SOURCES"
WINDOW_HOURS = max(1, int(os.environ.get("ENRICH_LOOKUP_ACTIVE_WITHIN_HOURS", "168")))
MAX_PER_CYCLE = max(1, int(os.environ.get("ENRICH_LOOKUP_MAX_PER_CYCLE", "500")))
DAILY_BUDGET = max(0, int(os.environ.get("ENRICH_LOOKUP_DAILY_BUDGET", "5000")))
FETCH_TIMEOUT = max(3, int(os.environ.get("ENRICH_LOOKUP_FETCH_TIMEOUT", "15")))
#: Politeness gap between provider calls. InternetDB publishes no limit, but a
#: free service answering us thousands of times an hour deserves throttling.
CALL_GAP_MS = max(0, int(os.environ.get("ENRICH_LOOKUP_CALL_GAP_MS", "120")))


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Write-back: labels always, graph objects only where §7 says promote
# ---------------------------------------------------------------------------

def build_objects(builder, src: LookupSource, obs_type: str, value: str,
                  verdict: dict) -> list[dict]:
    """Turn a normalised verdict into STIX. Labels-first, promote sparingly.

    §7 hard rule — never emit a floating edgeless SDO. Every promoted object
    below is emitted together with the edge that ties it to the observable.
    """
    out: list[dict] = []
    if obs_type == "ipv4":
        obj = builder.build_ip_observable(str(value))
        if not obj:
            return []
        labels = _ip_labels(src, verdict)
        obj["x_opencti_labels"] = sorted(
            set(list(obj.get("x_opencti_labels") or []) + labels))
        out.append(obj)

        # InternetDB vulns[] -> Vulnerability SDO + edge. This is the one
        # promotion in this lane: a CVE is a typed, queryable, gate-able fact.
        if src.key == "internetdb":
            obs_id = obj.get("id")
            for cve in (verdict.get("vulns") or [])[:25]:
                vid = builder._emit_vulnerability(
                    cve, out=out,
                    description=(
                        f"{cve} reported against this address by Shodan "
                        f"InternetDB. NOT observed by our sensors: this is a "
                        f"third-party assertion about the host's exposed "
                        f"surface, recorded for context."),
                )
                if not vid or not obs_id:
                    continue
                rel = builder.build_relationship(
                    obs_id, "related-to", vid,
                    description=("Shodan InternetDB associated this CVE with the "
                                 "address at lookup time."),
                )
                if rel:
                    out.append(rel)
        return out

    if obs_type == "sha256":
        obj = builder.build_file(str(value))
        if not obj:
            return []
        obj["x_opencti_labels"] = sorted(set(
            list(obj.get("x_opencti_labels") or []) + _hash_labels(src, verdict)))
        return [obj]
    return out


def _ip_labels(src: LookupSource, v: dict) -> list[str]:
    if src.key != "internetdb":
        return []
    labels = ["shodan:seen"]
    tags = {str(t).lower() for t in (v.get("tags") or [])}
    for t in sorted(tags):
        labels.append(f"shodan:tag-{t}"[:60])
    if v.get("vulns"):
        labels.append("shodan:has-cve")
    if v.get("ports"):
        labels.append(f"shodan:ports-{min(len(v['ports']), 99)}")
    # hostnames are carried in the verdict but are LABEL-ONLY and not even
    # emitted as a label value: a PTR name is chosen by whoever owns the
    # netblock, so for attacker-owned ranges the attacker picks the name we
    # would publish as their infrastructure (EVIDENCE.md §6). We record only
    # that a name exists.
    if v.get("hostnames"):
        labels.append("shodan:has-ptr")
    return labels


def _hash_labels(src: LookupSource, v: dict) -> list[str]:
    if src.key != "circl" or not v.get("known_good"):
        return []
    # Suppression is a LABEL, never a lowered score: the publisher keeps the
    # maximum score across cycles, so a score can only ratchet up (§7).
    return ["hashlookup:known-good"]


# ---------------------------------------------------------------------------
# Cycle
# ---------------------------------------------------------------------------

def candidates_ipv4(core_db: str, sweep: SweepCursor, limit: int) -> tuple[list[str], list[dict]]:
    """One page of CORE's `attacker_activity`, via the shared sweep pager.

    Uses the same cursor discipline as Lane A/C rather than a fresh query: the
    pager exists because every lane has this identical problem, and a second
    implementation is a second thing that can silently stop paging.
    """
    cursor = sweep.position()
    try:
        rows = read_activity(core_db, window_hours=WINDOW_HOURS,
                             limit=limit, after_ip=cursor)
    except ActivityReadError as exc:
        logger.warning("lookup: activity read failed: %s", exc)
        return [], []
    return [r["src_ip"] for r in rows if is_ipv4(r.get("src_ip", ""))], rows


def candidates_sha256(core_db: str, limit: int) -> list[str]:
    """Captured-sample hashes from CORE's `campaign_artifacts`.

    A different candidate source from the IP lane, deliberately: CIRCL answers
    about FILES, and `attacker_activity` is keyed per address. Only 64-char
    values are taken — the column also holds ssh-key and JA3 artifacts.
    """
    import sqlite3
    try:
        con = sqlite3.connect(f"file:{core_db}?mode=ro", uri=True, timeout=15)
        rows = con.execute(
            "SELECT DISTINCT artifact_value FROM campaign_artifacts "
            "WHERE artifact_type='malware' AND length(artifact_value)=64 "
            "ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        con.close()
    except Exception as exc:  # noqa: BLE001
        logger.warning("lookup: sample-hash read failed: %s", exc)
        return []
    return [r[0].lower() for r in rows if r and r[0]]


def run_cycle(sources: list[LookupSource], ledger: EnrichmentLedger,
              state: CycleState, core_db: str, builder_factory, publish) -> dict:
    """One pass. Returns the counters health_state() turns into a named state."""
    cycle_id = state.start_cycle()
    calls = hits = cached = errors = skipped = backlog = 0
    budget_blocked: list[str] = []
    objects: list[dict] = []
    builder = builder_factory()
    sweep = SweepCursor(state, "lk")
    swept = False

    #: (source_key, obs_type, value, ttl) awaiting a CONFIRMED publish. Held in
    #: memory, never in the ledger — writing the verdict before publish() lands
    #: is exactly the "cache on attempted" bug that hid dropped writes for weeks.
    pending: list[tuple[str, str, str, int]] = []

    for src in sources:
        if src.obs_type == "ipv4":
            pool, rows = candidates_ipv4(core_db, sweep, MAX_PER_CYCLE)
        elif src.obs_type == "sha256":
            pool, rows = candidates_sha256(core_db, MAX_PER_CYCLE), []
        else:
            logger.warning("lookup: %s has obs_type %r with no candidate source",
                           src.key, src.obs_type)
            continue
        if not pool:
            continue

        spent = ledger.spent_today(src.key)
        allowance = DAILY_BUDGET if src.daily_budget == 0 else min(DAILY_BUDGET, src.daily_budget)

        for value in pool:
            hit = ledger.lookup(src.key, src.obs_type, value)
            if hit is not None:
                cached += 1
                if hit.status == "found" and hit.verdict:
                    objects.extend(build_objects(builder, src, src.obs_type,
                                                 value, hit.verdict))
                continue
            if ledger.in_backoff(src.key, src.obs_type, value):
                skipped += 1
                continue
            backlog += 1
            if allowance and spent >= allowance:
                if src.key not in budget_blocked:
                    budget_blocked.append(src.key)
                continue

            try:
                verdict = src.fetch(value, timeout=FETCH_TIMEOUT,
                                    credential=src.credential)
            except LookupError_ as exc:
                # A failed call still consumed provider quota.
                ledger.record_error(src.key, src.obs_type, value, str(exc))
                calls += 1; spent += 1; errors += 1
                if CALL_GAP_MS:
                    time.sleep(CALL_GAP_MS / 1000.0)
                continue
            calls += 1; spent += 1
            if CALL_GAP_MS:
                time.sleep(CALL_GAP_MS / 1000.0)

            if verdict is None:
                # A real "the provider has nothing", not a failure. Safe to cache
                # immediately: there is no downstream write to confirm.
                ledger.record_result(src.key, src.obs_type, value,
                                     status="not_found", verdict={},
                                     ttl_seconds=src.ttl_not_found)
                continue

            new = build_objects(builder, src, src.obs_type, value, verdict)
            if new:
                objects.extend(new)
            hits += 1
            pending.append((src.key, src.obs_type, value, src.ttl_found))
            # NOTE: no ledger write here. See `pending` above.

        if src.obs_type == "ipv4" and rows:
            swept = sweep.advance(rows, MAX_PER_CYCLE)

    published_ok = True
    if objects:
        try:
            publish(objects, cycle_id)
        except Exception as exc:             # noqa: BLE001
            published_ok = False
            logger.error("lookup: publish FAILED — not caching %d verdict(s), "
                         "they will be retried next cycle: %s", len(pending), exc)

    confirmed = 0
    if published_ok:
        for key, obs_type, value, ttl in pending:
            ledger.record_result(key, obs_type, value, status="found",
                                 verdict={"confirmed": True}, ttl_seconds=ttl)
            confirmed += 1

    return {"cycle_id": cycle_id, "calls": calls, "hits": hits, "cached": cached,
            "errors": errors, "skipped_backoff": skipped, "backlog": backlog,
            "objects": len(objects), "published": published_ok,
            "confirmed": confirmed, "budget_blocked": budget_blocked,
            "sweep_complete": swept}


def health_state(counters: dict, *, had_success: bool) -> tuple[str, int]:
    """Map counters to the four named states in §6."""
    if counters["backlog"] == 0 and counters["calls"] == 0:
        return "quiet", 200
    if counters["budget_blocked"] and counters["calls"] == 0:
        return "budget-exhausted", 200
    if had_success and counters["backlog"] > 0 and counters["calls"] == 0 \
            and not counters["budget_blocked"]:
        # The condition two prior silent failures needed and nobody asserted.
        return "stalled-with-work", 503
    return "healthy", 200


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> int:
    setup_logging(connector_name="tpot2cti-lookup")
    try:
        cfg = load_config()
    except ConfigError as exc:
        logger.error("lookup: configuration error: %s", exc)
        return 2
    try:
        sources = selected_sources(os.environ.get(SOURCES_ENV, DEFAULT_SOURCES))
    except ValueError as exc:
        # An unknown source name is fatal on purpose, matching Lane A: a typo
        # must not silently disable a source and leave the operator believing
        # it runs.
        logger.error("lookup: %s", exc)
        return 2
    if not sources:
        # NOT an error. Every configured source was tier 1/2 without a
        # credential, which is the expected state of a fresh open-source
        # install that has not signed up for anything.
        logger.warning("lookup: no sources enabled — nothing to do. Set %s or "
                       "provide a credential for a tier 1/2 source.", SOURCES_ENV)

    interval = parse_iso_duration_seconds(
        os.environ.get("ENRICH_LOOKUP_INTERVAL", "PT15M"))
    core_db = str(cfg.runtime.state_db_path)
    own_db = os.environ.get(
        "ENRICH_LOOKUP_STATE_DB",
        os.path.join(os.path.dirname(str(cfg.runtime.state_db_path)), "lookup.db"))
    ledger_db = os.environ.get(
        "ENRICH_LOOKUP_LEDGER_DB",
        os.path.join(os.path.dirname(str(cfg.runtime.state_db_path)), "enrichment_ledger.db"))

    logger.info(
        "tpot2cti-lookup starting — sources=%s window=%dh interval=%ds "
        "budget/day=%d max/cycle=%d core_db=%s (read-only) own_db=%s ledger=%s",
        ",".join(s.key for s in sources) or "<none>", WINDOW_HOURS, int(interval),
        DAILY_BUDGET, MAX_PER_CYCLE, core_db, own_db, ledger_db)
    for s in sources:
        logger.info("lookup: %-11s tier %d  owns %-14s adds: %s",
                    s.key, s.tier, s.label_prefix, s.meaning)

    state = CycleState(own_db)
    ledger = EnrichmentLedger(ledger_db)

    # Bind /health BEFORE connecting: a cold platform makes _connect_opencti
    # wait up to 300s, longer than the image HEALTHCHECK start period, so
    # connecting first makes a warming module look unhealthy. Same ordering as
    # Lane A, for the same reason.
    health = HealthServer(
        state, None, bind=os.environ.get("ENRICH_LOOKUP_HEALTH_BIND", ":8080"),
        cycle_interval_seconds=interval,
    )
    health.start_in_background()

    from tpot2cti.main import _connect_opencti
    from tpot2cti.publisher import Publisher
    from tpot2cti.stix.builder import STIXBuilder
    opencti = _connect_opencti(cfg, connector_id=cfg.connector_ids.core)
    restore_logging()
    publisher = Publisher(opencti, state=state,
                          indexing_delay_seconds=cfg.cycle.indexing_delay_seconds)

    def builder_factory():
        return STIXBuilder(cfg, {})

    def publish(objects: list[dict], cycle_id) -> None:
        publisher.publish(objects, cycle_id=str(cycle_id))

    stopping = False

    def _stop(signum, _frame):
        nonlocal stopping
        logger.info("lookup: signal %s received, finishing current cycle", signum)
        stopping = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    had_success = False
    while not stopping:
        started = time.monotonic()
        try:
            counters = run_cycle(sources, ledger, state, core_db,
                                 builder_factory, publish)
            state_name, _code = health_state(counters, had_success=had_success)
            if counters["calls"] or counters["objects"]:
                had_success = True
            logger.info(
                "lookup cycle %s complete in %.1fs — %s | calls=%d hits=%d "
                "cached=%d errors=%d backoff=%d backlog=%d objects=%d "
                "confirmed=%d budget_blocked=%s ledger=%s",
                counters["cycle_id"], time.monotonic() - started, state_name,
                counters["calls"], counters["hits"], counters["cached"],
                counters["errors"], counters["skipped_backoff"],
                counters["backlog"], counters["objects"], counters["confirmed"],
                counters["budget_blocked"] or "-", ledger.stats())
            if state_name == "stalled-with-work":
                # The condition two prior silent failures needed and nobody
                # asserted. Loud on purpose.
                logger.error("lookup: STALLED WITH WORK — backlog=%d, budget "
                             "available, yet zero provider calls. Something is "
                             "consuming candidates without dispatching them.",
                             counters["backlog"])
            state.heartbeat()
        except Exception as exc:  # noqa: BLE001
            logger.exception("lookup: cycle failed: %s", exc)
        slept = 0.0
        while not stopping and slept < interval:
            time.sleep(min(2.0, interval - slept))
            slept += 2.0
    ledger.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
