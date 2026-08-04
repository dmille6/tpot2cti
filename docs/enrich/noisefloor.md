# noisefloor — scanner vs focused, from our own telemetry

> **Status: implemented.** Optional — `COMPOSE_PROFILES=enrich`.
> Runs as `python -m tpot2cti.enrich.noisefloor`. **Owns `noise:*` and `targeted:*`.**

The only enrichment that needs **no third party at all**. It derives its answer
from telemetry the fleet already collected, so it is free, private, unlimited —
and produces a judgement no public feed can replicate: nobody else knows how an
IP behaved against *your* sensors.

## Why this before any reputation source

A production fleet sees ~16,000 distinct attacker IPs a day, most of them
commodity internet scanners. For sharing, the urgent problem is not "add more
context", it is **"do not publish mass-scanner noise as targeted
intelligence."** The predecessor platform had an abuse.ch key banned for
publishing unqualified data, then switched every sharing channel off.

## The denominator is *surfaces touched*, not sensors hit

A **single-sensor install is the open-source default.** Classifying by sensor
count returns "1 sensor" for everything there, which would make this module
useless for exactly the audience it exists for. Counting distinct honeypot
services (and port fan-out) works on one sensor and only sharpens with a fleet.

## Labels are observations, never revoked

| label | meaning |
|---|---|
| `noise:fleet-scan` | touched ≥ `FANOUT_SUPPRESS` distinct surfaces — broad sweeping |
| `targeted:focused` | a single surface **plus** substantive activity (successful auth, commands, or malware) |
| *(none)* | ambiguous middle — **silence is a valid answer** |

Both can become true of one IP over time, and that is fine: they record what
was *observed*, not a verdict. The predecessor treated them as mutually
exclusive states while accreting both, producing contradictory labels.

**The export gate does the reasoning:** `noise:fleet-scan` suppresses
shareability *unless* overridden by concrete evidence — successful auth,
commands, malware, C2, a KEV-backed exploit, or campaign linkage.

## Measured on live telemetry

Of 2,000 recently-active IPs: **805 `noise:fleet-scan` (40%)**, **14
`targeted:focused` (0.7%)** — each with 15–19 executed commands — and **1,181
unlabelled (59%)**. The suppressed set includes IPs independently confirmed on
public blocklists.

## Configuration

| variable | default | meaning |
|---|---|---|
| `ENRICH_NOISEFLOOR_FANOUT_SUPPRESS` | `3` | surfaces for broad fan-out |
| `ENRICH_NOISEFLOOR_WINDOW_HOURS` | `168` | look-back window |
| `ENRICH_NOISEFLOOR_MAX_PER_CYCLE` | `2000` | bundle-size guard |
| `ENRICH_NOISEFLOOR_INTERVAL` | `PT1H` | cycle interval |
| `ENRICH_NOISEFLOOR_STATE_DB` | `<data>/noisefloor.db` | own state |

## Operational notes

- **Own state DB.** Never CORE's: this module writes heartbeats and `cycle_log`
  rows, exactly what CORE's `/health` reads, so sharing would let a quiet
  enrichment cycle hold CORE's health green while CORE was dead.
- **Reads CORE's DB read-only** (`mode=ro`), and reads the roll-up rather than
  re-querying Elasticsearch — the predecessor's equivalent burned ~3.65M
  redundant document reads an hour. The *mount* must still be writable:
  SQLite needs WAL bookkeeping even for readers.
- **Tail coverage.** Classifications are recorded so later cycles skip
  unchanged IPs; without that the per-cycle cap would re-label the busiest
  addresses forever and never reach the tail (tens of thousands).
- **Recorded only after a confirmed publish** — a cache that records work which
  never landed is the failure this project keeps re-learning.
