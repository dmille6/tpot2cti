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
FANOUT_SUPPRESS = int(os.environ.get("ENRICH_NOISEFLOOR_FANOUT_SUPPRESS", "3"))

#: How far back to look when classifying.
WINDOW_HOURS = int(os.environ.get("ENRICH_NOISEFLOOR_WINDOW_HOURS", "168"))

#: Max IPs classified per cycle (bundle-size guard).
MAX_PER_CYCLE = int(os.environ.get("ENRICH_NOISEFLOOR_MAX_PER_CYCLE", "2000"))

STATE_DB_ENV = "ENRICH_NOISEFLOOR_STATE_DB"

#: This module owns these label prefixes and writes no others
#: (docs/ENRICHMENT.md §8).
LABEL_NOISE = "noise:fleet-scan"
LABEL_FOCUSED = "targeted:focused"


# ---------------------------------------------------------------------------
# Read CORE's telemetry (read-only)
# ---------------------------------------------------------------------------

def read_activity(core_db: str, *, window_hours: int = WINDOW_HOURS,
                  limit: int = MAX_PER_CYCLE) -> list[dict]:
    """Aggregate ``attacker_activity`` per src_ip over the window.

    Reads CORE's state DB **read-only**. This is a read of a WAL database, so
    it does not contend with CORE's writer, and — unlike the predecessor's
    equivalent, which re-queried Elasticsearch and burned ~3.65M redundant
    document reads an hour — the roll-up already exists.
    """
    since = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
    sql = """
        SELECT src_ip,
               COUNT(DISTINCT parser)              AS surfaces,
               COUNT(DISTINCT sensor)              AS sensors,
               SUM(sessions_count)                 AS sessions,
               SUM(auth_success_count)             AS auth_success,
               SUM(commands_count)                 AS commands,
               SUM(malware_drop_count)             AS malware_drops,
               GROUP_CONCAT(sample_dst_ports_json) AS ports_json
          FROM attacker_activity
         WHERE last_seen >= ?
      GROUP BY src_ip
      ORDER BY MAX(last_seen) DESC
         LIMIT ?
    """
    uri = f"file:{core_db}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=10.0)
    except sqlite3.Error as exc:
        logger.error("noisefloor: cannot open CORE state DB %s: %s", core_db, exc)
        return []
    try:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(sql, (since, limit))]
    except sqlite3.Error as exc:
        logger.error("noisefloor: activity query failed: %s", exc)
        return []
    finally:
        conn.close()


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

def classify(row: dict, *, fanout: int = FANOUT_SUPPRESS) -> Optional[str]:
    """Return a label for one aggregated IP, or ``None`` to stay silent.

    Silence is a valid answer. Labelling an ambiguous middle case is worse
    than leaving it unlabelled — a wrong suppression hides real intelligence,
    and a wrong "focused" tag inflates noise into a finding.
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

    if surfaces >= fanout:
        return LABEL_NOISE
    if surfaces <= 1 and substantive:
        return LABEL_FOCUSED
    return None


def build_objects(builder: STIXBuilder, row: dict, label: str) -> list[dict]:
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
        set(list(obj.get("x_opencti_labels") or []) + [label])
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

    rows = read_activity(core_db)
    builder = builder_factory()
    objects: list[dict] = [
        builder.build_operator_identity(),
        builder.build_tlp_marking(),
    ]
    n_foundation = len(objects)
    counts = {LABEL_NOISE: 0, LABEL_FOCUSED: 0, "unlabelled": 0}
    pending_marks: list[tuple[str, str]] = []

    already = 0
    for row in rows:
        label = classify(row)
        if label is None:
            counts["unlabelled"] += 1
            continue
        # Skip IPs already carrying this exact classification. Without this the
        # per-cycle cap would re-label the same busiest IPs forever and the long
        # tail (tens of thousands of addresses) would never be reached.
        seen_key = f"nf:{row.get('src_ip')}"
        if state.get(seen_key) == label:
            already += 1
            continue
        objs = build_objects(builder, row, label)
        if objs:
            counts[label] += 1
            objects.extend(objs)
            pending_marks.append((seen_key, label))

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

    if publish_ok:
        # Mark only on confirmed publish — a cache that records work which
        # never landed is the failure this project keeps re-learning.
        for k, v in pending_marks:
            state.set(k, v)

    duration = time.monotonic() - started
    logger.info(
        "noisefloor cycle %s complete in %.1fs — ips=%d fleet-scan=%d "
        "focused=%d unlabelled=%d already=%d publish_ok=%s",
        cycle_id, duration, len(rows), counts[LABEL_NOISE],
        counts[LABEL_FOCUSED], counts["unlabelled"], already, publish_ok,
    )
    state.record_cycle(
        cycle_id, success=publish_ok, events_read=len(rows),
        events_parsed=counts[LABEL_NOISE] + counts[LABEL_FOCUSED],
        events_dropped=counts["unlabelled"], sdos_emitted=len(objects),
        errors_count=0 if publish_ok else 1, duration_seconds=duration,
    )
    return {
        "cycle_id": cycle_id, "ips": len(rows),
        "fleet_scan": counts[LABEL_NOISE], "focused": counts[LABEL_FOCUSED],
        "unlabelled": counts["unlabelled"], "already": already,
        "publish_ok": publish_ok,
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
    from tpot2cti.main import _connect_opencti
    opencti = _connect_opencti(cfg, connector_id=cfg.connector_ids.core)
    restore_logging()
    publisher = Publisher(opencti, state=state,
                          indexing_delay_seconds=cfg.cycle.indexing_delay_seconds)

    health = HealthServer(
        state, opencti, bind=os.environ.get("ENRICH_NOISEFLOOR_HEALTH_BIND", ":8080"),
        cycle_interval_seconds=interval,
    )
    health.start_in_background()

    stopping = False

    def _stop(_sig, _frm):
        nonlocal stopping
        stopping = True
        logger.info("noisefloor: shutdown requested; finishing cycle")

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    while not stopping:
        try:
            run_cycle(cfg, state, core_db, lambda: STIXBuilder(cfg), publisher)
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
