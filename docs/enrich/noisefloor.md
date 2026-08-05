# noisefloor — scanner vs substantive, from our own telemetry

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
| `targeted:substantive` | successful auth, executed commands, or a malware drop |
| *(none)* | ambiguous middle — **silence is a valid answer** |

The two are **orthogonal, not alternatives**, and an IP frequently earns both:
it really did sweep broadly, and it really did get in. Emitting only the first
would be a silent data-loss bug — see the measurement below. They record what
was *observed*, never a verdict, so they need no revocation. The predecessor
treated them as mutually exclusive states while accreting both, which is what
produced contradictory labels; orthogonal observations cannot conflict.

**The export gate does the reasoning:** `noise:fleet-scan` suppresses
shareability *unless* overridden by concrete evidence — successful auth,
commands, malware, C2, a KEV-backed exploit, or campaign linkage.

> ⚠️ **The export gate does not exist yet.** No component currently reads
> these labels to decide what may be shared. Until SHARE lands, they are
> descriptive only — nothing is actually being withheld or released on their
> basis, and `noise:fleet-scan` must not be read as "this was filtered out".

## Measured on live telemetry

Across all **14,751** addresses active in the 168h window:

| outcome | count | share |
|---|---:|---:|
| `noise:fleet-scan` only | 2,538 | 17.2% |
| **both labels** | **1,073** | **7.3%** |
| `targeted:substantive` only | 567 | 3.8% |
| unlabelled | 10,573 | 71.7% |

**29.7% of suppressed addresses (1,073 of 3,611) carry confirmed substantive
activity.** That number is why `classify()` returns a list: an earlier version
returned the first matching label only, so every one of those 1,073 would have
been marked as scanner noise with the overriding evidence never recorded — and
the skip-cache would have made the omission permanent.

## Configuration

| variable | default | meaning |
|---|---|---|
| `ENRICH_NOISEFLOOR_FANOUT_SUPPRESS` | `3` | surfaces for broad fan-out |
| `ENRICH_NOISEFLOOR_ACTIVE_WITHIN_HOURS` | `168` | how recently an IP must have been active to be considered — **not** a metric window (see below) |
| `ENRICH_NOISEFLOOR_MAX_PER_CYCLE` | `2000` | sweep page size / bundle-size guard |
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
- **Coverage is a sweep, not a top-N.** Rows are ordered by `src_ip` and
  resumed from a cursor, so a full pass reaches every address in the window
  (14,751 live ÷ 2,000 ≈ 8 cycles). An earlier version ordered by recency and
  relied on the skip-cache to advance — but the cache filters *after* the SQL
  `LIMIT`, so it returned the same most-recent page every cycle and the older
  ~12,700 addresses were never read at all. The cache still prevents
  re-publishing work already done; it is not what provides coverage.
- **Window vs counters.** `ACTIVE_WITHIN_HOURS` selects rows *last active*
  within N hours, but CORE stores lifetime cumulative counters per
  `(src_ip, parser, sensor)`, so the summed activity is lifetime, not
  windowed. This is deliberate: evidence that lifts export suppression should
  not expire because an attacker went quiet. Note the asymmetry — fan-out is
  effectively windowed (only in-window rows are counted) while substantive
  evidence is lifetime, so drift over time runs toward *eroding* suppression
  rather than deepening it.
- **Recorded only after a confirmed publish** — a cache that records work which
  never landed is the failure this project keeps re-learning.
