"""Classify attacker IPs as broad-scanning noise or focused activity.

This is the first ENRICH module and the only one that needs **no third party
at all** — it derives its answer from telemetry the fleet already collected.
That makes it free, private, unlimited, and impossible for an outside feed to
replicate: nobody else knows how an IP behaved against *your* sensors.

Why it matters more than another reputation source: a production fleet sees
~16,000 distinct attacker IPs per day and most are commodity internet
scanners. For sharing, the urgent problem is not "add more context" — it is
"do not publish mass-scanner noise as targeted intelligence." The predecessor
platform had an abuse.ch key banned for publishing unqualified data.

**The denominator is surfaces touched, not sensors hit.** A single-sensor
install is the open-source default, and classifying by sensor count returns
"1 sensor" for everything there — which would make this module useless for
exactly the audience it is written for. Counting *distinct honeypot services*
an IP touched works on one sensor and only sharpens with a fleet.

**The two labels are observations, not verdicts, and are never revoked.**
An IP that fanned out across services did so; an IP that authenticated and ran
commands did that. Both can be true over time. The predecessor treated them as
mutually exclusive states while accreting both, producing contradictory
labels. Here the *export gate* does the reasoning: `noise:fleet-scan`
suppresses shareability **unless** overridden by concrete evidence
(successful auth, commands, malware, C2, KEV-backed exploit, campaign link).

Runs as its own process::

    python -m tpot2cti.enrich.noisefloor
"""
from __future__ import annotations

import json
import logging
import os
import re
import signal
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from tpot2cti.config import ConfigError, load_config
from tpot2cti.enrich.sweep import (  # shared: one copy of the sweep, by design
    ActivityReadError,
    SweepCursor,
    read_activity,
)
from tpot2cti.health import HealthServer, parse_iso_duration_seconds
from tpot2cti.log import restore_logging, setup_logging
from tpot2cti.publisher import Publisher
from tpot2cti.state import CycleState
from tpot2cti.stix.builder import STIXBuilder
from tpot2cti.stix_ids import attacker_ip_observable_id

logger = logging.getLogger(__name__)


#: Distinct honeypot services an IP must touch to count as broad fan-out.
#: Three is deliberately conservative: two can happen by accident (a scanner
#: hitting SSH and Telnet), three suggests indiscriminate sweeping.
FANOUT_SUPPRESS = max(1, int(os.environ.get("ENRICH_NOISEFLOOR_FANOUT_SUPPRESS", "3")))

#: How far back to look when classifying.
#: How recently an IP must have been active to be considered this cycle.
#: NOT a metric window — the counters CORE stores are lifetime totals.
#: See read_activity() for why that is deliberate.
WINDOW_HOURS = max(1, int(os.environ.get("ENRICH_NOISEFLOOR_ACTIVE_WITHIN_HOURS", "168")))

#: Max IPs classified per cycle (bundle-size guard).
#: Page size for the sweep. Floored at 1: a non-positive value resurrects
#: silent zero-work in two different ways. At 0 every cycle reads no rows and
#: records success — green forever. At -1 SQLite reads LIMIT as *unlimited*,
#: so cycle 1 parks the cursor at the highest src_ip and `len(rows) < -1` is
#: never true, so the reset never fires and the cursor sticks — green forever,
#: and worse, because it appears to work once. Both are one .env typo away.
MAX_PER_CYCLE = max(1, int(os.environ.get("ENRICH_NOISEFLOOR_MAX_PER_CYCLE", "2000")))

STATE_DB_ENV = "ENRICH_NOISEFLOOR_STATE_DB"
#: Resume point for the src_ip sweep. Reset to "" when a short page proves the
#: end of the window was reached, so the next cycle starts a fresh pass.
SWEEP_CURSOR_KEY = "nf_sweep_cursor"
#: Consecutive failed publishes at the SAME cursor before the wedge is called
#: out by name. The sweep deliberately does NOT skip the page — advancing past
#: data that never published is the exact defect this project already shipped
#: once — so a page that fails deterministically blocks the sweep until an
#: operator intervenes. That trade is accepted, but it must not be silent:
#: health already reads unhealthy, and this makes the CAUSE greppable.
STUCK_PAGE_ALERT = max(1, int(os.environ.get("ENRICH_NOISEFLOOR_STUCK_PAGE_ALERT", "3")))
STUCK_COUNT_KEY = "nf_stuck_count"
STUCK_AT_KEY = "nf_stuck_at"

#: This module owns these label prefixes and writes no others
#: (docs/ENRICHMENT.md §8).
#: Two ORTHOGONAL observations. They are not alternatives: an address can
#: both sweep broadly and land a real interaction, and that combination is the
#: single most important case to represent — it is exactly what lets an export
#: gate say "suppressed as a scanner UNLESS it actually got in".
LABEL_NOISE = "noise:fleet-scan"          # broad surface/port fan-out
LABEL_SUBSTANTIVE = "targeted:substantive"  # auth success, commands, or malware


# ---------------------------------------------------------------------------
# Read CORE's telemetry (read-only)
# ---------------------------------------------------------------------------

def _distinct_ports(ports_json: Optional[str]) -> int:
    """Count distinct destination ports in concatenated JSON port lists.

    SQLite's GROUP_CONCAT joins rows with commas, so several JSON arrays arrive
    as ``"[22,23],[23,80]"`` — splitting on commas shreds them. Pulling every
    integer out is simpler and works regardless of how the lists were joined.
    """
    if not ports_json:
        return 0
    return len({int(n) for n in re.findall(r"\d+", str(ports_json))})


# ---------------------------------------------------------------------------
# Classify
# ---------------------------------------------------------------------------

def classify(row: dict, *, fanout: int = FANOUT_SUPPRESS) -> list[str]:
    """Return zero, one, or BOTH observation labels for one aggregated IP.

    These are independent observations, never a single verdict. An address that
    swept 40 ports *and* executed commands gets both — and that pairing is the
    whole point: `noise:fleet-scan` suppresses shareability, while
    `targeted:substantive` is the concrete evidence that overrides the
    suppression. Returning only the first would silently discard the override.

    Silence is still a valid answer. An ambiguous middle case gets no label:
    a wrong suppression hides real intelligence, and a wrong activity tag
    inflates noise into a finding.
    """
    substantive = (
        int(row.get("auth_success") or 0)
        + int(row.get("commands") or 0)
        + int(row.get("malware_drops") or 0)
    ) > 0
    surfaces = int(row.get("surfaces") or 0)
    # Port fan-out counts as surface breadth: a Honeytrap-only scanner sweeping
    # 40 ports is fanning out even though it touched one parser.
    surfaces = max(surfaces, min(_distinct_ports(row.get("ports_json")), 99) // 5)

    labels: list[str] = []
    if surfaces >= fanout:
        labels.append(LABEL_NOISE)
    if substantive:
        labels.append(LABEL_SUBSTANTIVE)
    return labels


def build_objects(builder: STIXBuilder, row: dict, labels: list[str]) -> list[dict]:
    """Attach the classification to the attacker's existing IP observable.

    Deterministic ids mean this lands on the observable CORE already created,
    and OpenCTI unions labels on upsert, so nothing CORE wrote is disturbed.
    """
    ip = row.get("src_ip")
    obs_id = attacker_ip_observable_id(ip)
    if not obs_id:
        return []
    obj = builder.build_ip_observable(ip)
    if obj is None:      # already emitted in this bundle
        return []
    obj["x_opencti_labels"] = sorted(
        set(list(obj.get("x_opencti_labels") or []) + list(labels))
    )
    return [obj]


# ---------------------------------------------------------------------------
# Cycle
# ---------------------------------------------------------------------------

def run_cycle(cfg, state: CycleState, core_db: str, builder_factory,
              publisher) -> dict:
    cycle_id = state.start_cycle()
    started = time.monotonic()
    state.heartbeat()

    sweep = SweepCursor(state, "nf", stuck_alert=STUCK_PAGE_ALERT)
    cursor = sweep.position()
    try:
        # limit passed explicitly: the default arg binds at import time, so
        # reading the module global here is what makes the page size actually
        # configurable (and testable) rather than frozen at first import.
        rows = read_activity(core_db, after_ip=cursor,
                             limit=MAX_PER_CYCLE, window_hours=WINDOW_HOURS)
    except ActivityReadError as exc:
        # Fail the cycle loudly: /health goes unhealthy rather than reporting a
        # successful zero-work run.
        logger.error("noisefloor cycle %s: %s", cycle_id, exc)
        state.record_cycle(
            cycle_id, success=False, events_read=0, events_parsed=0,
            events_dropped=0, sdos_emitted=0, errors_count=1,
            duration_seconds=time.monotonic() - started,
        )
        return {"cycle_id": cycle_id, "ips": 0, "fleet_scan": 0,
                "substantive": 0, "unlabelled": 0, "already": 0,
                "publish_ok": False, "read_error": str(exc)}
    builder = builder_factory()
    objects: list[dict] = [
        builder.build_operator_identity(),
        builder.build_tlp_marking(),
    ]
    n_foundation = len(objects)
    counts = {LABEL_NOISE: 0, LABEL_SUBSTANTIVE: 0, "unlabelled": 0, "malformed": 0}
    pending_marks: list[tuple[str, str]] = []

    already = 0
    for row in rows:
        labels = classify(row, fanout=FANOUT_SUPPRESS)
        if not labels:
            counts["unlabelled"] += 1
            continue
        ip = row.get("src_ip")
        # Cache per (ip, LABEL) — not one value per ip — so a later observation
        # can still be added. Without the per-cycle cap this would starve the
        # long tail (tens of thousands of addresses); with a single-value cache
        # a scanner that later got in could never gain its evidence label.
        fresh = [l for l in labels if state.get(f"nf:{ip}:{l}") != "1"]
        if not fresh:
            already += 1
            continue
        objs = build_objects(builder, row, fresh)
        if not objs:
            # build_objects rejects anything that is not a parseable address.
            # CORE's telemetry does contain such rows (measured: 30, all from
            # H0neytr4p, which stores raw exploit payloads in src_ip), and
            # dropping them without a count is the silent-loss pattern this
            # project keeps re-learning. Count them where they can be seen.
            counts["malformed"] += 1
            continue
        if objs:
            for l in fresh:
                counts[l] = counts.get(l, 0) + 1
                pending_marks.append((f"nf:{ip}:{l}", "1"))
            objects.extend(objs)

    publish_ok = True
    if len(objects) > n_foundation:
        try:
            result = publisher.publish(objects, cycle_id=str(cycle_id))
            errs = list(getattr(result, "errors", []) or [])
            publish_ok = not errs
            if errs:
                logger.error("noisefloor: publish reported %d error(s): %s",
                             len(errs), errs[:3])
        except Exception as exc:
            publish_ok = False
            logger.exception("noisefloor: publish failed: %s", exc)
    else:
        logger.info("noisefloor cycle %s: nothing to label", cycle_id)

    swept = False
    if not publish_ok:
        sweep.hold(cursor)
    else:
        # Mark only on confirmed publish — a cache that records work which
        # never landed is the failure this project keeps re-learning.
        for k, v in pending_marks:
            state.set(k, v)
        # Advance only after the page landed, so a failed publish retries the
        # same addresses instead of skipping past them.
        swept = sweep.advance(rows, MAX_PER_CYCLE)

    duration = time.monotonic() - started
    logger.info(
        "noisefloor cycle %s complete in %.1fs — ips=%d fleet-scan=%d "
        "substantive=%d unlabelled=%d malformed=%d already=%d publish_ok=%s "
        "cursor=%s sweep_complete=%s",
        cycle_id, duration, len(rows), counts[LABEL_NOISE],
        counts[LABEL_SUBSTANTIVE], counts["unlabelled"], counts["malformed"],
        already, publish_ok, (state.get(SWEEP_CURSOR_KEY) or "<start>"), swept,
    )
    state.record_cycle(
        cycle_id, success=publish_ok, events_read=len(rows),
        events_parsed=counts[LABEL_NOISE] + counts[LABEL_SUBSTANTIVE],
        events_dropped=counts["unlabelled"], sdos_emitted=len(objects),
        errors_count=0 if publish_ok else 1, duration_seconds=duration,
    )
    return {
        "cycle_id": cycle_id, "ips": len(rows),
        "fleet_scan": counts[LABEL_NOISE], "substantive": counts[LABEL_SUBSTANTIVE],
        "unlabelled": counts["unlabelled"], "malformed": counts["malformed"],
        "already": already,
        "publish_ok": publish_ok, "sweep_complete": swept,
        "duration_seconds": round(duration, 3),
    }


def main() -> int:  # pragma: no cover - process entrypoint
    cfg = load_config()
    setup_logging(cfg.logging.level, connector_name="tpot2cti-noisefloor")
    interval = parse_iso_duration_seconds(
        os.environ.get("ENRICH_NOISEFLOOR_INTERVAL", "PT1H"), 3600.0
    )
    core_db = str(cfg.runtime.state_db_path)
    own_db = os.environ.get(
        STATE_DB_ENV,
        (core_db.rsplit("/", 1)[0] + "/noisefloor.db") if "/" in core_db
        else "noisefloor.db",
    )
    logger.info(
        "tpot2cti-noisefloor starting — fanout>=%d window=%dh interval=%.0fs "
        "core_db=%s (read-only) own_db=%s",
        FANOUT_SUPPRESS, WINDOW_HOURS, interval, core_db, own_db,
    )

    # Own state DB: this module writes heartbeats and cycle_log rows, which are
    # what CORE's /health reads. Sharing would let a quiet enrichment cycle
    # hold CORE's health green while CORE was dead.
    state = CycleState(db_path=own_db)
    # Bind /health BEFORE connecting: _connect_opencti waits patiently for a
    # cold platform (up to connect_timeout_seconds, default 300s) while the
    # image's HEALTHCHECK has a 60s start period. Binding first means a slow
    # OpenCTI start no longer shows as an unhealthy container.
    health = HealthServer(
        state, None, bind=os.environ.get("ENRICH_NOISEFLOOR_HEALTH_BIND", ":8080"),
        cycle_interval_seconds=interval,
    )
    health.start_in_background()

    from tpot2cti.main import _connect_opencti
    opencti = _connect_opencti(cfg, connector_id=cfg.connector_ids.core)
    restore_logging()
    publisher = Publisher(opencti, state=state,
                          indexing_delay_seconds=cfg.cycle.indexing_delay_seconds)

    stopping = False

    def _stop(_sig, _frm):
        nonlocal stopping
        stopping = True
        logger.info("noisefloor: shutdown requested; finishing cycle")

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    while not stopping:
        try:
            summary = run_cycle(cfg, state, core_db,
                                lambda: STIXBuilder(cfg), publisher)
            # Surface sweep progress at the top level. Coverage is the one
            # property this module guarantees, and a stuck cursor otherwise
            # reads exactly like a fleet with nothing left to label.
            if summary.get("sweep_complete"):
                logger.info("noisefloor: sweep complete — next cycle restarts "
                            "the pass from the beginning of the window")
            elif not summary.get("publish_ok"):
                logger.warning("noisefloor: sweep NOT advancing — cursor held "
                               "at %r pending a successful publish",
                               state.get(SWEEP_CURSOR_KEY) or "<start>")
        except Exception as exc:
            logger.exception("noisefloor: cycle failed: %s", exc)
        for _ in range(int(interval)):
            if stopping:
                break
            time.sleep(1)
    health.stop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    try:
        sys.exit(main())
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        sys.exit(2)
