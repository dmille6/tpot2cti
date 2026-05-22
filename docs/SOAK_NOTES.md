# tpot2cti — Soak Notes (Phase 9 baseline)

This document is the operator-facing reference for "what does a healthy
tpot2cti deployment look like?" — populated from the first live soak
run starting 2026-05-21 at the threat-intel host against the single
T-Pot at `203.0.113.10`.

The numbers below are the **single-sensor baseline.** Hive deployments
will scale most of these linearly with sensor count (events_read,
sdos_emitted, publish duration); a few (dedup %, indicator count)
scale less than linearly because the same attackers hit multiple
sensors.

---

## Stack under test

| Component | Version |
|---|---|
| tpot2cti core | commit `a4fd6e7` (post P1+P2 rollup + parser-vs-builder refactor) |
| Python | 3.12 (python:3.12-slim) |
| pycti | 7.260521.0 |
| OpenCTI platform | 7.260521.0 |
| ES (T-Pot side) | 8.x via SSH tunnel on :64298 |
| Host | Ubuntu 24.04, 4 cores, 39 GB RAM |
| T-Pot | single sensor at `203.0.113.10`, T-Pot 24.04.1 |
| Cycle interval | PT15M |
| Indexing delay between passes | 60s (default) |
| FATT cadence multiplier | 4 (FATT every ~60 min) |
| Ignored types | `P0f` |
| Self-filter IPs | `203.0.113.10` |
| Benign scanner ASNs | 10 vendors (Google, Censys, Shodan, Shadowserver, Internet Archive, Stretchoid, Rapid7, BinaryEdge, Onyphe, NSR) |

---

## Per-cycle envelope (single sensor, normal traffic)

Captured from cycles 15-16, 2026-05-21 16:30 UTC and 16:45 UTC. The
sample is small but representative — both cycles fell in a busy
window (~10-20K events per 15-min slice from a single internet-
facing T-Pot).

| Metric | Cycle 15 | Cycle 16 | Notes |
|---|---|---|---|
| events_read | 15,087 | 20,538 | Raw ES doc count in the 15-min window |
| events_parsed | 7,120 | 14,997 | Successfully became `ParsedEvent` |
| events_dropped | 7,218 | 4,780 | Parser couldn't parse (mostly malformed P0f / Suricata-non-alert / etc.) |
| events_self_filtered | 419 | 648 | `TPOT_HONEYPOT_IPS` matched (our own server) |
| events_benign | 330 | 113 | Benign scanner allowlist matched |
| sdos_emitted | 697 | 729 | STIX objects in the bundle |
| Publish duration | 350s | 317s | ~5.5 min — three passes with 60s sleep between |
| Cycle duration (total) | ~410s | ~370s | Includes ES scroll + parse + correlate + build + publish |
| Dedup % (in-bundle) | 0.1% | 0.1% | Single-sensor: most UUID5s appear once per bundle |
| publish_ok | True | True | No errors |
| Notes emitted | ~20 | ~21 | Post-refactor: only Cowrie session-transcripts + 7 daily-creds (LESSONS A.1) |

### Per-bundle STIX type breakdown (cycle 16)

```
identity:           2    (operator + sensor)
marking-definition: 1
ipv4-addr:        116    (unique attacker IPs)
indicator:        116    (1 per IP)
sighting:         116    (1 per IP/sensor pair)
location:          62    (countries)
autonomous-system: 58    (unique ASNs)
relationship:     241    (located-at, belongs-to, based-on, etc.)
attack-pattern:     2    (MITRE techniques flagged by Suricata)
cryptographic-key:  3    (HASSH SSH client fingerprints from Cowrie)
note:              21    (Cowrie command transcripts + daily creds)
```

---

## What the cycle summary log line looks like

```
cycle 16: events_read=20538 events_parsed=14997 events_dropped=4780
events_self_filtered=648 events_benign=113 benign_by_vendor={'google': 75, 'censys': 38}
types=['Adbhoney', 'Ciscoasa', 'Cowrie', 'Dionaea', 'Fatt',
'H0neytr4p', 'Honeytrap', 'Ipphoney', 'Sentrypeer', 'Suricata', 'Tanner']
fatt_this_cycle=True

[16] Publish complete: passes={'foundation': 87, 'entities': 380,
'relationships': 262} dedup=729->728 errors=0 duration=317.3s

cycle 16: complete in 369.5s — events_read=20538 sdos_emitted=729
sdos_by_type={...} publish_ok=True dedup=729->728 (0.1%)
```

---

## What "healthy" looks like — the operator checklist

| Signal | Healthy | Warning | Critical |
|---|---|---|---|
| Cycle duration | < 60% of interval | 60-90% | > 90% (overrun warning fires) |
| Per-cycle errors | 0 | 1-5 transient | persistent > 5 |
| dedup % (single sensor) | 0.1-3% | unusual fluctuation | sudden 0% across many cycles → label emission broken |
| dedup % (hive) | 15-30% | < 5% | 0% (label-union not running) |
| events_benign trend | stable | sudden 0 across many cycles | likely the yaml didn't get baked into the image |
| events_self_filtered | stable | sudden 0 | check TPOT_HONEYPOT_IPS env var loaded |
| sdos_emitted per cycle | hundreds to low thousands | ten thousand+ | likely substance filter regressed |
| Notes per cycle | ~1 per real Cowrie session + 7 daily creds | hundreds | LESSONS §7.1 regression: Honeytrap/Fallback emitting per-event again |
| OpenCTI Work queue depth | < 100 | 100-1000 | > 1000: workers can't keep up; raise replicas |
| RabbitMQ queue depth | < 1000 | 1000-10000 | > 10000: same |

---

## Cycle-overrun behavior (V1_SPEC §3 + commit `879b286`)

If a cycle takes longer than `TPOT2CTI_INTERVAL` (default PT15M = 900s):
- A WARNING log fires: `cycle overrun: ran X s (interval=900s); sleeping minimum 10s before next cycle. Consider raising TPOT2CTI_INDEXING_DELAY_SECONDS ...`
- The next cycle starts immediately after a 10s breathing-room sleep (not back-to-back, but no anchored 15-min wait)
- The system never skips a cycle (no event-window gaps)
- This is the signal to either:
  1. Raise `TPOT2CTI_INDEXING_DELAY_SECONDS` (currently 60s → try 120 or 300s) — slows the publish but reduces OpenCTI worker pressure
  2. Lengthen `TPOT2CTI_INTERVAL` (currently PT15M → try PT30M) — fewer cycles, larger bundles
  3. Add OpenCTI worker replicas — scales the ingest throughput

The PoC at 5-sensor hive scale runs `indexing_delay_seconds=300` and
PT15M intervals comfortably; expect similar tuning at this scale.

---

## V0 footguns that this build does NOT exhibit

Validated during the live soak:

- ✅ **No sentinel-poll plateau** (LESSONS §7.2 anti-pattern). Three-pass send uses fixed `time.sleep`, never polls.
- ✅ **No UUID drift** (LESSONS §3). All `sensor_infra_name(sensor)` callers go through the canonical helper.
- ✅ **No per-IP per-cycle Activity Notes** (LESSONS §7.1). Cowrie session-transcript Notes only; Honeytrap/Fallback summaries live in `Sighting.description`.
- ✅ **No `x-opencti-cryptographic-key` typo** (LESSONS §8.4). HASSH observables use the spec-correct `cryptographic-key` type.
- ✅ **No silent type drops** (LESSONS §8.4). `KNOWN_STIX_TYPES` allowlist + `validate_types()` runs pre-send each cycle.
- ✅ **No pycti logger hijack** (LESSONS §8.1). `setup_logging()` before pycti, `restore_logging()` after.
- ✅ **No empty CONNECTOR_ID footgun** (LESSONS §8.2). `OpenCTIClient.__init__` raises `ConfigError` if the connector_id is whitespace.
- ✅ **No own-server attribution** (live-install postmortem). `TPOT_HONEYPOT_IPS` self-filter drops events where src_ip is our public IP.
- ✅ **No Google/Censys/Shodan flagged as malicious** (live-install postmortem). Benign-scanner allowlist filters at parse time.
- ✅ **No 30-Notes-per-attacker bug** (live-install postmortem). LESSONS §7.1 refactor moved per-probe summaries to Sighting.description.
- ✅ **No score drift on re-emission** (PoC LESSONS §29 + score-plateau smoke). Same session = same score across cycles.

---

## How to capture metrics during a soak run

```bash
# Tail the structured JSON log and pull cycle summaries:
docker compose -p tpot2cti logs -f tpot2cti 2>&1 | \
  python3 -c "
import sys, json, re
for line in sys.stdin:
    if 'tpot2cti-core' not in line: continue
    payload = line.split('|', 1)[1].strip()
    try:
        d = json.loads(payload)
        msg = d.get('message','')
        if 'complete in' in msg or 'cycle overrun' in msg:
            print(d.get('ts',''), msg[:300])
    except: pass
"

# Single cycle's per-vendor benign breakdown:
docker compose -p tpot2cti logs --since=1h tpot2cti 2>&1 | \
  grep -oE 'benign_by_vendor=\{[^}]+\}'

# Health endpoint (no auth):
docker exec tpot2cti-core curl -s http://localhost:8080/health | python3 -m json.tool
```

---

## Open questions for soak observation

These won't be answerable from a single short soak; flag for the
operator running the multi-day window:

1. **Does the dedup % rise as more sensors are added?** Single-sensor baseline is 0.1%; PoC hive sees 18-25%. The label-union code has been verified to merge correctly (`tpot2cti/publisher.py:_dedup_label_union`); proving it scales is empirical.

2. **Does the 60s indexing delay hold up at hive scale?** Recommended tuning: 60s for 1 sensor, 120s for 2-3 sensors, 300s for 5+ sensors. If `cycle overrun` warnings start firing, raise it.

3. **T-Pot daily reboot (01:33 UTC) impact.** V1 doesn't have a specific cycle-anchor avoidance for the 4-5h post-reboot instability window. Cycle should retry on the next interval; verify gracefully.

4. **Has any of the 5 newly-added benign-scanner ASNs caused false-negative attacker activity to drop?** Spot-check by querying ES for activity from those ASNs and comparing against our cycle summary `events_benign` counts.

5. **Memory drift over a 7-day window?** Container memory was stable through 17 cycles (~4 hours); a 7-day soak is the realistic test.

— end of document —
