# TSEC v2 / Open-Source Handoff Document

**Audience:** Whoever is rebuilding this system from scratch — whether
that's an open-source release, a separate jurisdiction adopting the
architecture, or a clean-room v2 inside the same project.

**Purpose:** Capture *why* the current implementation made the design
choices it did, what we'd do the same, what we'd do differently, and
what's expensive lessons not to repeat. This document is opinionated.

This document does not duplicate per-connector docs or step-by-step
"how to install" instructions — those live in `docs/*_HANDOFF.md` and
`docs/SENSOR_LESSONS.md` respectively. This is the *strategic* layer.

---

## 1. What the system does (one paragraph)

A fleet of distributed T-Pot honeypot sensors, each customized to
impersonate a real organization in a specific industry vertical
(healthcare, MSP, petrochem refinery), ships honeypot events via
logstash to a central Elasticsearch "hive". A separate compute host
("cti1") runs ~20 connectors that pull from the hive, enrich the
data through ~10 threat-intel sources (VirusTotal, AbuseIPDB, OTX,
Shodan, GreyNoise, MalwareBazaar, Triage, CrowdStrike, …), and
publish curated STIX 2.1 objects into OpenCTI for analyst use and
intel sharing. A separate `sensor_health_alert.py` cron monitors
sensor liveness and pages on anomalies.

---

## 2. The five strategic decisions

These are the things to think hard about before re-implementing. If
you keep these decisions, you'll save weeks. If you change them, do
it with eyes open.

### 2.1 OpenCTI as the data graph, not Elasticsearch directly

We considered storing everything directly in Elasticsearch and
exposing dashboards (Kibana, Grafana). We chose OpenCTI because:

- STIX 2.1 is a real standard. ISAC and ISAO partners consume STIX
  bundles natively. Building our own schema means perpetually
  translating to STIX at export time.
- OpenCTI has the entity-relationship model out of the box. We get
  "this IP attacked these honeypots" with a few clicks; in ES we'd
  build all of that in Kibana queries.
- pycti (their Python client) is workable. Not great, but workable.
  See `docs/LESSONS_LEARNED.md` §33 (silent-failure modes) for the
  pycti potholes — they exist and matter, but none are deal-breakers.

**The cost:** OpenCTI is heavy. ~16 GB of RAM dedicated. ~9 supporting
containers (Redis, RabbitMQ, MinIO, Elasticsearch, etc.). The platform
itself is a non-trivial sysadmin burden. Don't underestimate it.

**Verdict:** Right call. The STIX-native data model paid off the
moment we started sharing data with sector ISACs.

### 2.2 Bulk-importer + enrichment-connectors, not all-in-one

The natural temptation is to write one big script that reads ES,
enriches everything, and posts to OpenCTI. We split it explicitly:

- **One bulk importer** (`hp-connector`) reads honeypot events from
  ES every 15 minutes, correlates them into sessions, emits STIX
  observables + indicators + sightings + relationships. Stateless
  between cycles.

- **Many enrichment connectors**, one per threat-intel source, listening
  on RabbitMQ for "new observable created" events. Each one is
  responsible for ONE data domain (IPv4-Addr → Shodan host info,
  StixFile → MalwareBazaar lookup, etc.).

Why this shape:

1. **Pacing.** Each enrichment source has its own rate limits and cost
   model. Embedding them in the bulk importer makes a 5-minute
   cycle into a 50-minute cycle once we add 10 enrichers.

2. **Failure isolation.** When Shodan's API has a bad day, MaxMind
   keeps enriching. The bulk importer doesn't care.

3. **Per-type ownership.** Each connector owns one data type's
   classification. No two connectors fight over who labels an IP.

4. **Easy add/remove.** Adding GreyNoise is "make a new directory,
   add a service to docker-compose, set the env var." It doesn't
   touch any other code path.

**The cost:** ~20 containers instead of 1. More to monitor, more to
configure, more environment variables. The audit infrastructure
(`tsec-pipeline-audit-*` index, sensor_health_alert.py, audit_growth_check.py)
is non-trivial.

**Verdict:** Right call. The decoupling is worth it. See
`LESSONS_LEARNED.md` §31 for the "two-question rule" that decides
when to add a new enrichment connector vs extending the bulk importer.

### 2.3 Per-vertical custom personas, not default T-Pots

Default T-Pot is a great honeypot framework but produces *generic*
data. Custom personas (medical clinic, MSP, refinery) produce
*vertical-targeted* data.

The full analysis is in `docs/PERSONA_QUALITY_COMPARISON.md`. Headline:

| Indicator | Default T-Pot | Custom persona |
|---|---|---|
| Login-success rate from bait creds | 3% | 6% (2×) |
| File-download rate / day | 81 | 165 (2×) |
| ICS-protocol Suricata alerts | ~0 | 44 in 5.7 days |
| Domain-name-derived credential attempts | none | 1,132+ direct + 533 cross-IP-spillover |

**The cost:** ~2-5 days of work per persona to build (conpot ICS
profiles, custom Cowrie userdb, vertical-specific fake services,
matching nginx_tls SSL certs, vertical-flavored website content,
DNS provisioning). See `sensor-personas/` and
`docs/SENSOR_LESSONS.md` §14.

**Verdict:** Right call, by a wide margin. The vertical-specific
signal is the part the sponsors care about.

### 2.4 No asyncio, sync only

pycti's RabbitMQ callback fires from a thread pool. The first time
we mixed asyncio (aiohttp HTTP client) with that thread pool, it
broke the event loop and the connector silently froze.

We rewrote everything sync. Use `requests` for HTTP. Use ThreadPoolExecutor
when you need concurrency. Never use asyncio inside a pycti connector.

See `docs/LESSONS_LEARNED.md` §15 and §32 (or wherever it ended up
re-numbered) for the specific failure mode.

**Verdict:** Right call. Saved many hours of debugging mysterious freezes.

### 2.5 STIX 2.1 deterministic UUID5 IDs everywhere

Every SDO we emit has its ID computed by `uuid.uuid5(NS_DNS, <stable_seed>)`.

- Malware family: `malware:family:<lowercased-family-slug>`
- Per-source Note: `<source>-note:<sha256>:<family>`
- AttackPattern: `mitre:<TTP_ID>`
- Author identity: `identity:<connector-name>`
- Relationship: `<src_id>:<dst_id>:<rel_type>`

Why: idempotency. We can re-run anything any number of times without
creating duplicates. If GTI Sandbox re-emits a `Malware(name='mirai')`
with the same family, it's the same UUID5 → OpenCTI upserts in place.
If Triage *also* emits `Malware(name='mirai')` with the same UUID5,
it's the same node. Both classifiers now point at one shared Malware
SDO, which is exactly what we want.

The shared namespace constant is `uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")`
across all connectors. Don't change this — every deployed connector
references it and changing it would create a parallel universe of
new IDs that aren't connected to existing ones.

**Verdict:** Right call. Critical for safe re-runs and connector
restarts.

---

## 3. Repository structure rationale

```
tsec-tpot-connectors/
├── shared/                              # cross-cutting Python modules
│   ├── tsec_logging.py                  # rotating logs + restore_logging() pattern for pycti
│   ├── tsec_scoring.py                  # canonical score-from-labels rubric
│   ├── tsec_es_metrics.py               # ES audit/heartbeat/metrics client
│   ├── tsec_heartbeat.py                # liveness signals
│   ├── tsec_observatory.py              # honeypot-census writeback
│   ├── tsec_env.py                      # truthy_env() helper (LESSONS_LEARNED §38)
│   └── ...
├── tsec-tpot-<source>-connector/        # one dir per connector (~20)
│   ├── Dockerfile
│   ├── entrypoint.py                    # banner + config load + orchestrator launch
│   ├── requirements.txt                 # connector-specific deps only
│   └── src/                             # connector implementation
├── config/                              # per-connector YAML configs (mounted ro)
├── docs/                                # the doc set this file is part of
├── scripts/                             # one-shot / cron utilities
│   ├── refresh_mb_database.py           # daily MB CSV pull
│   ├── classify_orphan_files.py         # daily orphan-File cleanup
│   ├── audit_growth_check.py            # daily silent-drop check
│   ├── sensor_health_alert.py           # 5-min sensor liveness
│   ├── cleanup_garbage_malware_sdos.py  # nightly legacy cleanup
│   └── backfill_*.py                    # one-shot backfill utilities
├── data/                                # mounted into containers (gitignored)
│   ├── malware-vault/samples/           # raw sample bytes
│   ├── mb_hashes.db                     # ~446 MB SQLite mirror
│   ├── triage-sandbox/triage_state.db   # Triage state
│   └── ...
├── logs/                                # host-side log files (gitignored)
├── sensor-personas/                     # per-sensor persona build artifacts (tracked!)
├── requirements.txt                     # shared deps (pycti, stix2, PyYAML, requests, elasticsearch)
├── docker-compose.yml                   # full fleet definition
├── .env                                 # secrets (gitignored)
└── CLAUDE.md                            # entry point for new collaborators
```

### Things that matter

- **`shared/` is bind-mounted into every connector at `/opt/shared`**.
  Changes there propagate without rebuilding container images. Use
  this — it's the right tool for cross-cutting fixes. (E.g. the
  `tsec_env.truthy_env()` migration in `LESSONS_LEARNED §38`.)

- **Per-connector `Dockerfile` is intentionally repetitive** — each
  connector defines its own base image, system deps, pip installs.
  We tried sharing a base image; it created tight coupling (every
  connector had to update simultaneously when a dep changed). The
  duplication is worth the independence.

- **Configs in `config/*.yaml` are mounted, not baked in.** Edit the
  YAML, restart the container, no rebuild. This was a deliberate
  trade-off: slightly slower deploys but much faster iteration.

- **`sensor-personas/` is tracked in git.** Sensor-side state on the
  T-Pots' host disk survives reboots but NOT `update.sh` (which does
  `git reset --hard`). The persona artifacts live in our repo and
  are deployed onto sensors via paramiko scripts. See
  `docs/SENSOR_LESSONS.md` §14.

### Things to copy verbatim

- **`shared/tsec_logging.restore_logging()` pattern.** pycti's
  `OpenCTIConnectorHelper.__init__()` hijacks the root logger. Always
  call `restore_logging()` immediately after to keep your file
  handlers. See `LESSONS_LEARNED.md` §7 / §29.

- **`shared/tsec_es_metrics.ESMetricsClient` audit shape.** The per-
  cycle audit doc structure (`tsec-pipeline-audit-*` index with
  `type_counts_sent`, `es_created_by_type`, `audit_outcome` fields)
  is what `audit_growth_check.py` and `sensor_health_alert.py` both
  read from. Change the schema and both break.

- **The `_PER_TYPE_DROP_EXCLUDE` list in `hp-connector`.** Each entry
  has a comment explaining *why* that type was excluded. Don't
  delete entries without re-reading the comment; many are subtle
  upsert-vs-create distinctions.

---

## 4. The data graph

```
File (StixFile observable, sha256-keyed)
   │
   ├── labels:  honeypot, honeypot:cowrie, malware-delivery, mb:enriched, gti:sandbox-analyzed, triage:family:mirai, ...
   ├── external_references: [tria.ge/<id>, bazaar.abuse.ch/sample/<sha256>/, virustotal.com/file/<sha256>, ...]
   ├── notes: [MB Note, GTI Sandbox Note, Triage Note, CS Note] (one per classifier source)
   │
   ├──[related-to]── Malware(name=<family>, is_family=True)
   │                    │
   │                    └──[uses]── AttackPattern(<MITRE TTP>)  ×N
   │
   └──[as Indicator]── Indicator(pattern=hash-match)
                          │
                          └──[indicates]── AttackPattern(malware-delivery)


IPv4-Addr observable
   │
   ├── labels:  p0f:os:linux, p0f:link:dsl, gti:malicious, shodan:has-cve, abuseipdb:reported, otx:enriched, ...
   ├── score:   computed from labels via tsec_scoring.py rubric
   └──[sighted-by]── Sighting(target=this-ip, where=sensor-organization)  ×N
```

### Critical invariants

1. **One `Malware(name=<family>)` SDO per family across the whole
   pipeline.** Many Files point at it. Deterministic UUID5 enforces
   this — different classifiers emitting the same family name produce
   the same Malware UUID.

2. **`malware-delivery` is a *behavioral* AttackPattern, not a family.**
   It's attached to Files that came from a Cowrie session that
   download+executed. It's never confused with the Malware-family SDO.
   See `LESSONS_LEARNED.md` §36 for the "don't pre-classify" history.

3. **Sightings reference an Indicator, not the observable directly.**
   Honeypot-saw-attacker is captured as `Indicator → indicates →
   AttackPattern` + per-sighting `Sighting(target=Indicator, where=Org)`.
   This makes the sighting count meaningful for severity scoring.

---

## 5. Operational maturity matrix

What works in production today and is battle-tested vs what's
fragile / immature:

| Area | Maturity | Notes |
|---|---|---|
| Bulk importer (`hp-connector`) | **Mature** | 21 parsers, audit infra, runs for weeks without intervention |
| IPv4 enrichment (P0f, MaxMind, Shodan, GreyNoise, AbuseIPDB, GTI) | **Mature** | Standard enrichment pattern, all stable |
| File enrichment (MB, GTI sandbox, Triage) | **Mature** | Three-classifier architecture documented in `MULTI_CLASSIFIER_ARCHITECTURE.md` |
| Sensor liveness / health alerting | **Mature** | sensor_health_alert.py running every 5 min, paged 2 events in last 24h, both auto-recovered |
| Audit / drop detection | **Mature** | `tsec-pipeline-audit-*` + audit_growth_check.py daily cron |
| Export connectors (GTI, OTX, AbuseIPDB, abuse.ch) | **Beta** | Working but less observed; partner-side validation pending |
| LLM enrichment (qwen3-14b via LM Studio) | **Fragile** | Local LLM goes down regularly; circuit breaker handles it but full feature is inconsistent |
| CrowdStrike Sandbox | **Dormant** | Code complete, container not deployed (poor fit for Linux samples) |
| Persona artifacts | **Mature on 3 sensors** | Persona A/B/C in production; persona-D-onwards is template work |
| Multi-worker scaling | **Documented, manually triggered** | See `MB_CONNECTOR_HANDOFF.md` §8. Worked great for the 121k File backfill. |
| Cleanup / housekeeping | **Mature** | classify_orphan_files (daily), cleanup_garbage_malware_sdos (nightly at 1500/night, ~36 day drain) |

---

## 6. Cost & quota model

What it actually costs to operate (in dollars, hours, and rate-limit
budget) per month at our current scale.

| Item | Cost | Notes |
|---|---|---|
| cti1 host (10-core, 80 GB RAM, 1 TB SSD) | varies | Self-hosted; could be a single ~$200/mo cloud VM |
| 3× T-Pot sensors (residential ISP IPs) | low | Existing infra; bandwidth ~10-50 GB/mo each |
| OpenCTI deployment | $0 | Open-source |
| VirusTotal / GTI API | $0 (we're on academic/research tier) | Public+enterprise rate limits apply |
| Shodan API | ~$59/mo | Or $0 with .edu / academic license |
| AbuseIPDB | $0 | Free tier sufficient at our volume |
| OTX (AlienVault) | $0 | Free |
| MalwareBazaar | $0 | Public CSV mirror, no auth |
| Hatching Triage | $0 | Researcher tier (must apply, 100 submits/day) |
| CrowdStrike Falcon Intel | varies | Subscription-tier (currently active) |
| MaxMind GeoLite2 | $0 | Self-hosted DB updates weekly |
| MITRE ATT&CK feed | $0 | Public STIX feed |

**Quota constraints worth knowing:**

- **GTI Sandbox:** 500 file submissions/day on academic tier
- **Triage Sandbox:** ~100/day on researcher tier (the binding constraint)
- **Shodan:** 1 request/sec hard limit; ~10k credits/mo on $59 plan
- **AbuseIPDB:** 1,000 lookups/day free tier
- **VT API v3 enrichment:** 4 requests/min on free, much higher on academic
- **CrowdStrike:** Subscription-rate-limited; we haven't hit limits

If reproducing at a smaller scale, the **single most expensive
operational quota is Triage submissions**. Plan for ~100/day max
unless you can buy higher tier ($$$). Use MB (local, free, unlimited)
as the primary classifier and Triage as the second-opinion layer.

---

## 7. What we'd do differently in v2

A non-exhaustive list, in rough priority order.

### Definite changes

1. **Persona-build automation from day 1.** We built persona A/B/C
   by hand-editing files via paramiko scripts. A v2 should have a
   declarative persona definition (YAML or HCL) that generates all
   the artifacts (Cowrie userdb, ConPot profiles, nginx pages, cert
   SAN list, bait files) deterministically.

2. **Connector scaffold tool.** Adding a new connector currently
   takes ~2 hours of boilerplate (Dockerfile, entrypoint, config
   YAML, env vars, docker-compose entry, OpenCTI ID generation,
   audit logger). A `make new-connector NAME=foo` would cut this to
   ~10 minutes.

3. **Unified secrets management.** `.env` works but is fragile. v2
   should use Docker secrets or HashiCorp Vault, especially for
   production deployments where API keys rotate.

4. **OpenCTI as a library, not as our partner.** We currently call
   pycti's GraphQL wrappers. pycti hides the GraphQL details but
   leaks abstractions (the `stixCoreObjectEdit` vs `stixCyberObservableEdit`
   confusion in `LESSONS_LEARNED §33b`). Going direct GraphQL via
   `urllib`/`requests` for the trickier mutations would have been
   faster to debug.

5. **Multi-classifier confidence meta-scorer.** Currently each
   classifier independently labels. v2 should have a final
   "consolidated verdict" computed from the union (e.g. "all 3
   sources agree this is mirai" → high confidence).

### Things worth experimenting with

6. **Streaming, not 15-min batch.** ES has streaming APIs. The
   hp-connector could be event-driven (new doc → process immediately)
   instead of batch. Trade-off: more pycti API calls, less
   correlation across short-window events. Worth measuring.

7. **Separate OpenCTI per persona.** All three persona sensors feed
   one OpenCTI today. A v2 might keep separate OpenCTI tenants per
   vertical (one for healthcare, one for petrochem) and federate
   them. Probably overkill at our scale; could matter if we ever
   federate across organizations.

8. **GreyNoise integration.** We have it ranked #1 in the
   "future enrichment sources" list and haven't built it yet.
   Purpose-built for honeypot deconvolution ("is this attacker
   targeting US specifically vs scanning everyone").

### Things to keep verbatim

9. **Deterministic UUID5 IDs.** §2.5. Don't change this.

10. **The audit infrastructure** (`tsec-pipeline-audit-*` index +
    `audit_growth_check.py`). Caught real silent-drop bugs we'd
    have missed for weeks.

11. **The `_PER_TYPE_DROP_EXCLUDE` discipline.** Adding to that list
    has been the right call every time. The comments in the list
    explain why each entry is there — read them.

12. **The bulk-importer vs enrichment-connector split.** Item §2.2.
    Critical for failure isolation and pacing.

13. **Persona-vertical fit.** Item §2.3. Resist any urge to "save
    time" by deploying generic honeypots.

---

## 8. Specific things to read before starting v2

If you have an afternoon to read before designing v2, in this order:

1. **`docs/CLAUDE.md`** — the project-instructions file. Lists where
   everything else lives.

2. **`docs/PROJECT_OVERVIEW.md`** — current container inventory,
   architecture diagram, planned-work backlog.

3. **`docs/LESSONS_LEARNED.md` §31-§42** — the most recent and
   actionable lessons (older entries are also valuable but the
   newest ones have the freshest context).

4. **`docs/SENSOR_LESSONS.md` §14 (persona build) + §18 (free pipe
   pattern) + §24 (logstash heap tuning)** — the highest-leverage
   sensor-side knowledge.

5. **`docs/MULTI_CLASSIFIER_ARCHITECTURE.md`** — how the malware
   classification layer works.

6. **`docs/PERSONA_QUALITY_COMPARISON.md`** — the data justification
   for the persona investment.

7. **One per-connector handoff doc** (pick TRIAGE or MB — both are
   recent and well-documented) to see the per-connector shape.

After that you'll have ~80% of the context. The remaining 20% is
distributed in source comments — especially `hp-connector` and
`shared/tsec_es_metrics.py`.

---

## 9. What's intentionally out of scope for this doc

- **Step-by-step installation.** That's `docs/SENSOR_LESSONS.md` §14
  for sensors and `README.md` for cti1.
- **OpenCTI deployment.** Vendor-supported; use their docs.
- **API-key acquisition processes.** Each vendor has its own application
  flow; documented in the per-connector handoffs where relevant.
- **Per-persona detail.** `sensor-personas/persona-*/README.md` (one
  per persona).
- **Specific YAML config schemas.** Per-connector handoff docs.
- **Test plans.** No formal test suite exists. Validation is via the
  audit infrastructure + smoke tests after each deploy. v2 should
  consider proper integration tests.

---

## 10. Sign-off

This system, in its current form, exists because of a specific
combination of:
- Available threat-intel API access (academic / researcher tiers)
- An OpenCTI deployment we already had
- Three operator-affiliated sensors with public IPs
- ~6 months of iterative development

Don't assume a clean-room v2 can be built in less time without
those preconditions. The hardest parts weren't writing code; they
were:
- Discovering pycti's silent-failure modes empirically
- Iterating on what counts as a "good" honeypot persona
- Building the audit infrastructure that catches drops
- Cleaning up the legacy mess (`cleanup_garbage_malware_sdos.py` cron)
- Getting persona credentials right enough that targeted scanners actually use them

If you have those preconditions, this doc + the per-connector handoffs
should let you re-implement in ~2-3 months of focused work. Less if
you copy our patterns verbatim; more if you re-derive everything.

Good luck. The data is genuinely interesting.
