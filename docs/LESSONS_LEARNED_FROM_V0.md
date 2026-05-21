# Lessons Learned from `tpot_threatintel` (the V0 prototype)

**Purpose:** Capture what we discovered during the ~12-day `tpot_threatintel`
experiment that the original V1_SPEC.md didn't yet cover. These are the
things to bake into `tpot2cti` from day 1 instead of re-discovering the
hard way.

**Status:** Reference document for `tpot2cti` development. Companion to
V1_SPEC.md and V2_OPENSOURCE_HANDOFF.md.

**Generated:** 2026-05-21, after the PoC vs OSS gap analysis revealed
the OSS was emitting 5× more STIX per session than the PoC and falling
behind on a single sensor.

---

## TL;DR — the seven most important lessons

If you only read seven things, read these:

1. **Substance filter from day 1.** The PoC has it (`has_substance()` per
   parser), the spec calls for it, and skipping it means emitting 5× more
   STIX per session than necessary. This single decision is the difference
   between "one sensor saturates 15 workers" and "five sensors run easily
   on 8 workers."

2. **Centralize the canonical-name → UUID5 helper before writing the
   first parser.** Multiple parsers and the SDO builder all need to agree
   on what string gets hashed to produce an entity's deterministic ID.
   When they disagree, every relationship references a phantom entity
   and OpenCTI's worker pool deadlocks trying to auto-create it. See §3.

3. **Don't add a `User-Account` SCO per credential attempt.** Use the
   daily top-100 Note pattern from V1_SPEC §6 + an optional DuckDB sidecar.
   Honeypots log credential attempts at firehose volumes; treating each
   one as a STIX entity buries OpenCTI.

4. **Don't emit a per-IP Activity Report Note per cycle.** It's seductive
   ("one tidy summary per attacker") but at hive scale you get 50K+ Notes
   per day that nobody reads. Put the summary in the Sighting description
   or the daily aggregate Note instead.

5. **T-Pot reboots itself at 01:33 UTC every day.** This is a default
   from T-Pot's Ansible install. The post-reboot recovery window is
   4-5 hours during which the SSH tunnel + ES are unstable. Plan cycle
   schedules to avoid this window.

6. **HARDENING gotchas 3 and 4 exist** — the loopback INPUT issue and
   the DOCKER-USER ESTABLISHED-return issue. Both bit us in production.
   Both should be in any port-lockdown script from day 1. See §4.

7. **In-bundle dedup with label-union saves 20-25% before send.** The
   PoC does it; the spec doesn't (yet) explicitly require it. Adding it
   to the publisher is ~50 lines and dramatically reduces OpenCTI worker
   load. See §6.

---

## 1. The "over-engineering trap" — what we did wrong at the strategic level

The V1_SPEC.md is intentionally narrow: one core importer + two optional
sidecars (credentials, vault). No enrichment connectors. No scoring. No
LLM. No analytical labels.

We built `tpot_threatintel` with:
- 5 core data-ingestion connectors (HP, Suricata, FATT, malware-vault, observatory)
- 9 enrichment connectors (AbuseIPDB, OTX, FireHOL, score-reconciler,
  campaign-correlator, daily-digest, weekly-intel-digest,
  enrichment-refresh, platform-watchdog)
- A 5-module observatory (census / discovery / verification / drift / health)
- A separate non-pycti platform-watchdog daemon
- Three-pass STIX publisher with sentinel polling
- Cross-cycle relationship dedup (Pattern A v1+v2)
- Cycle anchor + transient-error retry
- ~14,000 lines of documentation

**The result:** an over-built system that couldn't keep up with one
sensor. The PoC handles five sensors with 8 workers and a 181-message
queue. We handled one sensor poorly with 18 workers and a 327,000-message
queue.

**The lesson:** scope discipline matters more than feature richness.
Every enrichment connector we added was the right idea in isolation;
adding all of them before the core importer was right was the wrong
order.

### Concrete rule for tpot2cti

**Build the V1 spec exactly. No additions. No "while we're at it."**

If a feature isn't in V1_SPEC.md it doesn't belong in v1.0 of tpot2cti.
Companion connectors are explicitly planned post-v1.0; they go in
separate repos and follow the v1.0 release.

Resist any urge to add:
- Enrichment connectors (post-v1.0)
- LLM features (post-v1.0)
- Sandbox classification (post-v1.0)
- Score reconciliation (post-v1.0)
- Multi-tenant support (deferred indefinitely)
- Custom dashboards (use OpenCTI's built-in ones)

If you want to ship any of these, ship them as separate
`tpot2cti-<source>` repos following the companion pattern in
V1_SPEC §8.

---

## 2. Substance filter — the single most important per-parser pattern

V1_SPEC §5.1 (Cowrie) explicitly specifies:

> **Substance filter:** Cowrie sessions with no commands, no downloads,
> and no successful login are emitted as a Sighting only (no Note,
> Process, etc.). Pure probe-and-leave noise gets one-line
> representation rather than full SDO graph.

This is repeated in §5.4 (Honeytrap) and implied in the broader spec
philosophy. **The OSS rewrite did not implement this.** Every session
got the full ~30-object treatment regardless of substance.

### The math

PoC, 2026-05-21 cycle: 797 sessions → 4,925 objects → **6.2 obj/session**
OSS, 2026-05-20 cycle 3: 5,787 sessions → 181,205 objects → **31.3 obj/session**

The 5× delta is almost entirely the missing substance filter. Drive-by
probes (single-event, no auth attempt, no commands, no malware) make
up ~70% of honeypot traffic at typical internet exposure.

### Implementation pattern (port verbatim from PoC)

```python
def has_substance(session) -> bool:
    """Per V1_SPEC §5.1 — drive-by probes get Sighting-only treatment."""
    return (
        getattr(session, 'auth_success', False)
        or getattr(session, 'commands', None)
        or getattr(session, 'malware_hashes', None)
        or getattr(session, 'credentials_tried', None)
        or getattr(session, 'event_count', 0) > 2
    )

def _build_session_objects(session) -> List[dict]:
    objects = []
    ipv4 = build_ipv4_observable(session)
    objects.append(ipv4)

    if not has_substance(session):
        # Drive-by probe — observable + sighting only
        sighting = build_sighting(session, ipv4)
        if sighting:
            objects.append(sighting)
        return objects

    # Substantive session — full treatment
    objects.append(build_indicator(session))
    objects.extend(build_process_objects(session))
    # ... etc
    return objects
```

This single function is the difference between "scales" and "doesn't
scale."

### Per-parser substance criteria

Each parser should define its own `has_substance()` per its protocol:

| Parser | Substance criteria |
|---|---|
| Cowrie | auth_success OR commands OR malware_hashes OR credentials_tried OR event_count > 2 |
| Honeytrap | payload_printable.len > 8 (non-trivial bytes) |
| Suricata | always substantive (alerts are pre-filtered) |
| Dionaea | has download (always substantive if it captured a file) |
| ConPot | non-default ICS protocol command (e.g., write_register, not just read) |
| H0neytr4p | body present OR matched exploit signature |
| Heralding | credential attempt present |
| Mailoney | non-empty data OR auth attempt |
| ElasticPot | request body present |
| RedisHoneypot | commands beyond INFO/PING |
| Tanner | matched attack_type (sqli, rfi, xss) |
| Wordpot | matched wp-* path |
| FATT | always substantive (fingerprints are pre-filtered by min_observation_count) |
| Fallback | always emit Sighting + Note (worst-case capture) |

---

## 3. The UUID-drift bug and the centralized helper

V1_SPEC §4 ("Deterministic STIX IDs") shows the pattern:

```python
def sdo_id(stix_type, *seed_parts):
    seed = ":".join(str(p) for p in seed_parts)
    return f"{stix_type}--{uuid.uuid5(NS_DNS, seed)}"
```

What it DOESN'T explicitly call out: **when multiple parsers reference
the same logical entity (e.g., "the sensor this attacker hit"), they
MUST agree on what string gets passed as the seed.**

### The bug we hit

In `tpot_threatintel`:
- `build_infrastructure()` used `sensor["name"]` → produced UUID A
- HP per-session emission used `sensor.get("alias", sensor.get("name"))` → produced UUID B (different)
- Suricata used `sensor.get("alias", sensor.get("name"))` → UUID B
- FATT used the same → UUID B

Result: every relationship referenced UUID B, but the actual SDO
existed at UUID A. OpenCTI's worker pool saw dangling references,
tried to auto-create UUID B, 9 workers contended → 600+ LOCK_ERROR/h,
queue grew unbounded, throughput collapsed to 55 ops/min.

### Fix (port verbatim)

```python
# In shared module, used by EVERY parser AND every builder
def sensor_infra_name(sensor: dict) -> str:
    """
    Canonical sensor-name string for Infrastructure SDO UUID generation.
    
    EVERY caller that needs the sensor's Infrastructure UUID MUST go
    through this function. Direct hashing of sensor["name"] or
    sensor["alias"] is forbidden — it produces UUID drift across
    parsers and triggers the LOCK_ERROR cascade documented in the
    tpot_threatintel post-mortem (commit 15521dc).
    """
    name = (sensor.get("name") or "").strip()
    if name:
        return name
    alias = (sensor.get("alias") or "").strip()
    return alias

def generate_infrastructure_id_for_sensor(sensor: dict) -> str:
    return sdo_id("infrastructure", "infrastructure", sensor_infra_name(sensor))
```

### Why this matters disproportionately

Most STIX entity UUIDs are derived from immutable identifiers (an IP
address, a SHA-256, an MITRE TTP number). There's only one possible
string, so no drift.

Sensor names are different. A sensor has a `name` AND an `alias` in
the config. Different developers (or different code paths) naturally
reach for different fields. Without an enforced helper, drift is
inevitable.

**Add the helper before writing the first parser. Then every parser
imports it. The bug becomes impossible.**

---

## 4. HARDENING gotchas the spec doesn't document yet

The V1_SPEC doesn't have a hardening section yet, but it should. We
documented four gotchas in `docs/HARDENING.md` that all bit us in
production:

### Gotcha 1 — T-Pot adds wide-open INPUT ACCEPTs for every port

T-Pot's `~/tpotce/docker/tpotinit/dist/bin/rules.sh` runs on every
container startup and appends INPUT-chain ACCEPT rules for every port
T-Pot listens on, including management ports (64294-64305). Any DROP
rule added later in INPUT is unreachable.

**Mitigation:** insert lockdown rules at top of INPUT (`iptables -I INPUT 1`),
not appended (`-A INPUT`). When inserting multiple rules at position 1,
insert in reverse so the final stack reads correctly.

### Gotcha 2 — `--ctorigdst` beats `-d` in DOCKER-USER

Docker-published ports use DNAT in PREROUTING. By the time DOCKER-USER
evaluates the packet, the destination IP has been rewritten to the
container's internal IP. `-d <sensor_public_ip>` therefore never matches.

**Mitigation:** use `-m conntrack --ctorigdst <sensor_ip> --ctorigdstport <port>`
which queries the pre-NAT destination.

### Gotcha 3 — INPUT-chain DROPs also match loopback packets

Mgmt-port DROPs without `-i` constraint kill locally-originated traffic
(SSH tunnels, observatory probes, local curl) because loopback packets
re-enter via `lo` and traverse INPUT.

**Mitigation:** insert `-i lo -j ACCEPT` at INPUT position 1. Standard
practice on any Linux distro; T-Pot doesn't add it by default.

### Gotcha 4 — DOCKER-USER needs ESTABLISHED-return RETURN

The `--ctorigdst` fix from Gotcha 2 handles the forward path of
docker-NAT'd ports correctly, but return packets (container → client)
have source = container_ip, not admin_ip. They fall past per-port admin
ACCEPTs and hit the catch-all DROP.

**Mitigation:** `iptables -I DOCKER-USER 1 -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN`.

### Full battle-tested lockdown script

The complete `tpot-port-lockdown.sh` from `tpot_threatintel/docs/HARDENING.md`
should be ported verbatim to tpot2cti. Add a systemd oneshot for boot-time
re-application. Document the daily-reboot interaction (Gotcha 0 below).

---

## 5. T-Pot reboots itself daily — design around it

T-Pot's Ansible-installed default cron:

```cron
32 1 * * * root bash -c 'systemctl stop tpot.service && \
  docker container prune -f; docker image prune -f; docker volume prune -f; \
  /usr/sbin/shutdown -r +1 "T-Pot Daily Reboot"'
```

This fires at **01:33 UTC daily**. The reboot itself is fast (~30s),
but post-reboot the system is unstable for **4-5 hours**:

- SSH tunnel reconnects in storm pattern (autossh retries)
- T-Pot containers come up over ~3-5 minutes
- iptables rules re-apply
- ES cluster transitions through yellow → green

### Implications for tpot2cti

1. **Don't schedule cycles during 01:33-06:00 UTC.** If the importer
   runs PT15M cycles, most cycles will fall in stable hours, but some
   will hit the recovery window. Plan to tolerate this.

2. **The HP cycle anchor pattern:** if a cycle fires at a vulnerable
   time, retry once with 60s backoff. This catches transient tunnel
   blips. Implemented in tpot_threatintel commit 61b2835; port verbatim.

3. **Per-sensor health monitoring (for hive deployments):** if a sensor
   doesn't ship events for >2× the expected cycle interval, alert. The
   tpot_threatintel observatory health.py module (Sprint B5) is the
   reference, but a lightweight version belongs in tpot2cti core (NOT
   a separate observatory module).

4. **Don't try to "fix" T-Pot.** Tempting to remove the daily reboot
   cron, but it's there because T-Pot accumulates Docker cruft. Leave it.

### Sensible cycle scheduling

For the PT15M default cycle, 96 cycles/day. With the 4-5h recovery
window, ~17-20 cycles/day might be affected. Of those, the retry-once
pattern catches most. Net data loss: <1% of events under normal
conditions. Acceptable.

---

## 6. Bundle dedup with label-union — port from PoC

The PoC's STIX publisher has a 50-line block we never replicated:

```python
# Collapse duplicate STIX objects within a single bundle.
# Same standard_id from multiple emission sites → keep one base object,
# union the label-valued custom properties.

_by_id = {}
_order = []
for _o in all_objects:
    _oid = _o.get('id') or _o.get('standard_id')
    if not _oid:
        continue
    if _oid not in _by_id:
        _order.append(_oid)
    _by_id.setdefault(_oid, []).append(_o)

_deduped = []
_dupes_collapsed = 0
for _entry in _order:
    _variants = _by_id[_entry]
    if len(_variants) == 1:
        _deduped.append(_variants[0])
        continue
    _dupes_collapsed += len(_variants) - 1
    # Union list-valued custom props that are semantically sets
    _merge_keys = ('x_opencti_labels', 'labels')
    _seen_per_key = {k: [] for k in _merge_keys}
    for _v in _variants:
        for _k in _merge_keys:
            for _val in (_v.get(_k) or []):
                if _val not in _seen_per_key[_k]:
                    _seen_per_key[_k].append(_val)
    _base = dict(_variants[-1])
    for _k in _merge_keys:
        if _seen_per_key[_k]:
            _base[_k] = _seen_per_key[_k]
    _deduped.append(_base)

if _dupes_collapsed:
    logger.info(
        f"Bundle dedup: collapsed {_dupes_collapsed} duplicate "
        f"objects (label-union applied); "
        f"{len(all_objects)} → {len(_deduped)}"
    )
all_objects = _deduped
```

The PoC sees consistent 20-25% reduction with this. Combined with
substance filter, the bundle going to OpenCTI is dramatically smaller.

---

## 7. Anti-patterns we built — do NOT port these

### 7.1 Per-IP Activity Report Note per cycle

We emitted one `Note` SDO per unique attacker IP per HP cycle, summarizing
that IP's session activity. Seems tidy in theory; in practice at hive
scale this is 50K+ Notes per day that nobody reads.

**What to do instead:** the daily top-100 credentials Note (V1_SPEC §6)
is the only aggregate Note tpot2cti should emit. Per-session Sightings
provide the "this IP attacked this sensor at this time" record without
needing a Note.

### 7.2 Three-pass STIX publisher with sentinel polling

We built a publisher that splits each bundle into foundation/entities/
relationships passes, with sentinel-poll waits between them to ensure
OpenCTI's ES has indexed prior-pass entities before the next pass
references them.

It works, but the sentinel-poll plateau detection bug (we'd block on
80% threshold for up to 7200s, dropping ~36% of relationships if a
container restart occurred mid-wait) took weeks to find.

**What to do instead:** V1_SPEC §3 specifies three-pass with simple
30-second sleeps between passes. Use that. Don't over-engineer the
polling. If you hit MISSING_REFERENCE_ERROR, log it and continue —
next cycle re-emits and OpenCTI's deterministic-ID upsert handles
the duplicate.

### 7.3 Cross-cycle relationship dedup (Pattern A)

We built file-backed TTL caches that suppress re-emission of relationships
already sent in a prior cycle. Effective (70%+ skip rate) but only needed
because we were over-emitting in the first place.

**What to do instead:** substance filter handles the same problem at
the source. Don't ship cross-cycle dedup in v1.0.

### 7.4 Score reconciler / cross-source scoring

We built a separate connector that recomputes `x_opencti_score` from
all labels present on an entity. Useful, but V1_SPEC v1.0 has no
scoring — it lets OpenCTI manage scores via its native mechanisms.

**What to do instead:** ship without scoring. Add scoring as a
post-v1.0 companion if/when needed.

### 7.5 Platform watchdog as a standalone daemon

We built a non-pycti daemon that probes OpenCTI / RabbitMQ / ES every
60s and writes telemetry docs to ES. Useful for ops but heavy.

**What to do instead:** V1_SPEC §3 specifies a `/health` endpoint on
the core importer that Docker compose healthcheck reads. That's enough
for v1.0. The pipeline-audit jsonl (V1_SPEC §7) covers the rest.

### 7.6 Observatory (5-module daily census)

We built a daily-cadence connector that runs census / discovery /
verification / drift / health checks against the graph. Useful for
multi-sensor deployments; over-built for v1.0's single-deployment
scope.

**What to do instead:** the pipeline-audit jsonl covers what an
operator needs. If multi-sensor health monitoring becomes important,
add it as a companion connector post-v1.0.

---

## 8. Pycti silent failure modes we hit

Things that pycti does silently that look like normal operation but
break the pipeline:

### 8.1 `OpenCTIConnectorHelper.__init__()` hijacks the root logger

Any log handlers you set up before initializing the helper get clobbered.
Call `restore_logging()` immediately after `OpenCTIConnectorHelper.__init__()`.

The pattern from tpot_threatintel that worked:

```python
# Set up file + stdout handlers
setup_logging()
# Then init pycti (hijacks the logger)
self.helper = OpenCTIConnectorHelper(connector_config)
# Then restore our handlers
restore_logging()
```

### 8.2 `CONNECTOR_ID=""` produces `BAD_USER_INPUT`

Empty connector ID in env produces a pycti error that looks like a
GraphQL error. The fix is to ensure `setup.sh` generates a UUID
for every connector ID variable and writes it to .env.

If using docker compose with `--project-directory`, you MUST also pass
`--env-file ./.env` explicitly. Otherwise compose looks for .env inside
the project-directory and silently substitutes empty strings.

### 8.3 `stixCoreObjectEdit` vs `stixCyberObservableEdit`

For mutating an entity (adding a label, updating a field), pycti has
two endpoints:
- `stixCoreObjectEdit` works for SDOs and SROs
- `stixCyberObservableEdit` works for SCOs (IPv4-Addr, StixFile, etc.)

Using the wrong one returns success silently but doesn't actually
modify the entity. The bug is invisible until you query and notice
the change didn't take.

Per V2_OPENSOURCE_HANDOFF §7.4: consider going direct GraphQL via
`requests` for these mutations instead of pycti wrappers.

### 8.4 Silent drop of unknown STIX types

If you emit an object with a STIX `type` field that OpenCTI's worker
doesn't recognize, it's silently dropped. No error, no warning.

The PoC's defense: maintain a `KNOWN_STIX_TYPES` allowlist. Before
sending a bundle, check every object's type against the allowlist.
Anything unknown logs a WARNING.

This caught at least one real bug in the PoC (`x-opencti-cryptographic-key`
silently dropping; the right type is `cryptographic-key`).

### 8.5 Sentinel-poll plateau detection

If pycti's bundle splitter drops the last 1-2 sentinel sub-bundles to
the back of the worker queue, the publisher blocks on the "80% of
sentinels processed" threshold indefinitely (up to 7200s default).
A container restart inside that window orphans the entire deferred-bundle.

The PoC's workaround: treat `found_count` going N seconds without
progress (default 90s) as good-enough and proceed. Pycti workers
retry MISSING_REFERENCE on the relationship side anyway, so early
proceed is safe.

---

## 9. Docker / compose gotchas we hit

### 9.1 Layer cache and new files

Adding a NEW file to a connector requires `--no-cache` rebuild. The
COPY layer gets cached and Docker doesn't detect the new file's
presence on its own. We hit this with observatory's `health.py` —
the rebuild "succeeded" but the file wasn't in the image.

Mitigation: when adding new files to a connector, always
`docker compose build --no-cache <service>`.

### 9.2 The `--env-file` requirement with `--project-directory`

Docker Compose's env-file discovery breaks when you use
`--project-directory <other_dir>`. It looks for `.env` inside
`<other_dir>` instead of the cwd, and silently substitutes empty
strings for any missing variables.

Mitigation: every compose command must pass `--env-file ./.env`
explicitly. Make this part of the Makefile boilerplate from day 1.

### 9.3 `restart: always` vs `on-failure` for opt-in services

A service that intentionally exits 0 when disabled (e.g., malware-vault
when `enabled: false`) will infinitely restart-loop under
`restart: always`. Use `restart: on-failure` for services that may
legitimately exit 0.

### 9.4 MaxMind GeoLite2 download needs `-L`

MaxMind redirects to a CDN URL. Without `curl -L` to follow redirects,
the script writes a 0-byte file and tar fails with cryptic gzip errors.

---

## 10. Worker scaling and the single-platform ceiling

Measured curve on a single sensor at PT12H HP cadence:

| Workers | Ops/min | LOCK_ERROR/h | Notes |
|---|---|---|---|
| 9 | 69 | 470 | Baseline |
| 12 | 111 | 520 | +61% pace, +10% LOCK_ERROR (good ratio) |
| 15 | ~130-140 (estimated) | ~700 | Diminishing returns appear |
| 18 | ~150 (estimated) | ~1500+ | Worker contention dominates |

The ceiling isn't worker count — it's Redis's serial-write rate on hot
entities. OpenCTI's optimistic locking forces sequential updates to
the same node (e.g., the canonical "node2" Infrastructure SDO that
every relationship references).

### Implications for tpot2cti

1. **Don't ship with >9 workers as the default.** The default OpenCTI
   compose ships with 3 workers; bump to 9 if needed but don't go higher
   without measuring.

2. **The single-platform ceiling is fundamental, not a bug.** Multiple
   OpenCTI API platforms sharing one backend (Pattern 1 federation)
   scales linearly past the ceiling; pure worker scaling doesn't.

3. **Substance filter + bundle dedup prevent reaching the ceiling.**
   The PoC does 5 sensors on 8 workers with 181-message queue. The
   ceiling exists but proper emission discipline keeps you well below
   it.

---

## 11. Audit infrastructure — lightweight vs heavy

V1_SPEC §7 specifies a lightweight `data/cycles.jsonl` rotating local
file with one line per cycle:

```json
{
  "timestamp": "...",
  "duration_seconds": 18.4,
  "events_read": 12503,
  "events_parsed": 12489,
  "events_dropped": 14,
  "sdos_emitted": 47823,
  "sdos_by_type": {...},
  "errors_count": 0,
  "errors_sample": []
}
```

We built `tpoti-platform-health-*` + `tpoti-connector-errors-*` +
`tpoti-observatory-*` ES indices with rich schemas and Kibana
dashboards. Useful at scale; over-built for v1.0.

**For tpot2cti:** follow the spec. Ship the jsonl. Operators wanting
ES-backed audit can ship the jsonl into their own log aggregator. The
PoC's `tsec-pipeline-audit-*` index can be a post-v1.0 companion if
demand warrants.

---

## 12. The credentials decision — DuckDB sidecar vs STIX

V1_SPEC §6: emit one Note per sensor per UTC day with the top-100
credentials. Do NOT emit individual `User-Account` SCOs.

Optional `tpot2cti-credentials` connector (V1_SPEC §8.1): stores every
credential attempt in a local DuckDB file for analysts who want the
full firehose.

Our implementation in tpot_threatintel was close but emitted some
credential SDOs (we have DuckDB storage but the per-IP Activity Notes
also referenced credentials). Tighten this in tpot2cti.

### Lessons from the DuckDB implementation

- WAL mode is required (concurrent writers from cycle + offline queries)
- File-based, not server — no port to expose, no auth to configure
- Schema in V1_SPEC §8.1 is good; don't change it
- Hot copy via DuckDB's CHECKPOINT + filesystem copy works
- Don't try to query DuckDB from inside the importer cycle — it slows the cycle

---

## 13. Bundle size limits and OpenCTI worker behavior

OpenCTI's worker accepts STIX bundles up to ~1 MB JSON. Larger bundles
get rejected with cryptic GraphQL errors.

Our publisher chunks bundles into multiple sends when over the limit.
The PoC does the same.

### Mitigations

1. **Cap Note body size at ~64 KB.** Notes are the largest objects;
   capping them prevents bundle-size explosions.

2. **Truncate command_line in Process SCOs** (50 commands max in the
   PoC; ours used the same cap).

3. **For sessions with thousands of events**, summarize rather than
   detail. The cycle audit jsonl has the full counts; the STIX
   representation just needs to be queryable.

---

## 14. What we measured that's useful for capacity planning

At a single sensor with PT6H HP cadence + restored Suricata metadata:

| Connector | Cycle cadence | Avg objects/cycle | Net daily input to queue |
|---|---|---|---|
| HP | PT6H | ~50K (substance filter would reduce ~5× to ~10K) | ~40K with substance filter, ~200K without |
| Suricata | PT30M | ~1,000 (metadata) + ~70 (alerts) | ~52K/day |
| FATT | PT60M | ~50-100 fingerprints | ~2K/day |
| Daily creds Note | PT24H | 1-5 Notes total per day | negligible |

**Total expected with substance filter:** ~95K objects/day per sensor.
At 9 workers × 60 ops/min × 24h = ~78K ops/day worker capacity.

Headroom: barely positive. Each sensor needs substance filter + bundle
dedup to keep up at the default 9-worker config. Hive deployments
need worker scaling.

At PoC's measured 5 sensors / 8 workers / 181-msg queue, the
substance-filter-enabled per-sensor input rate is ~30-40K objects/day.
That's the right target.

---

## 15. Documentation lessons

We wrote ~14,000 lines of documentation for tpot_threatintel. Most of
it is useful reference material; some is over-built.

### Keep these patterns in tpot2cti

- **Per-connector README** with template (what / inputs / outputs /
  config / schedule / failure modes / cross-references)
- **HARDENING.md** with the 4 gotchas
- **TROUBLESHOOTING.md** organized by symptom → diagnosis → fix
- **CONFIGURATION.md** consolidating every config knob

### Skip these for v1.0

- **ARCHITECTURE.md** at the depth we wrote (1,723 lines) — V1_SPEC.md
  already covers it. A short ARCHITECTURE.md (200-400 lines) cross-
  referencing the spec is enough.
- **DATA_DICTIONARY.md** of the size we wrote (1,555 lines) — too
  detailed for v1.0. A short version (200-300 lines) listing STIX
  types + label namespaces is enough.
- **HIVE_DEPLOYMENT.md** — v1.0 is single-sensor; defer hive doc to
  post-v1.0.
- **SOAK_NOTES.md, ALERTING.md, BACKUP_RECOVERY.md** — defer.

### The "long is good" trap

The user asked for thorough documentation. We wrote thorough
documentation. The result was 14K lines of docs for ~10K lines of
code — too much. For v1.0, aim for **rough parity**: documentation
volume should match code volume.

---

## 16. Things to verify in tpot2cti early (avoid finding out late)

Set up these as smoke tests / acceptance criteria from day 1:

1. **Substance filter works:** drive-by Cowrie session → 2 objects
   emitted. Substantive session → full graph.

2. **No UUID drift:** the same sensor's Infrastructure UUID is
   identical regardless of which parser emitted it.

3. **Bundle dedup logs counters:** every cycle's logs include
   "collapsed N duplicate objects" line.

4. **Daily creds Note is idempotent:** running the same cycle twice
   for the same UTC date produces the same Note (same UUID, updated
   timestamp).

5. **Fallback parser emits something:** introduce a fake event with
   `type: "UnknownHoneypot"` and verify a Sighting + Note appear in
   OpenCTI.

6. **Three-pass publisher handles MISSING_REFERENCE gracefully:**
   simulate a relationship referencing a not-yet-indexed entity;
   verify retry + continue.

7. **Cycle continues on per-doc parse failures:** introduce a malformed
   event; verify cycle skips it and continues (doesn't crash).

8. **HP cycle survives a tunnel hiccup:** kill the SSH tunnel mid-cycle;
   verify retry-once recovers within 60s.

9. **`make doctor` catches a missing env var:** delete `OPENCTI_TOKEN`
   from .env; verify preflight fails with a clear message.

10. **Compose healthcheck transitions correctly:** verify /health
    returns 503 before first cycle, 200 after first success, 503 if
    no cycle in 2× interval.

---

## 17. License consideration

V1_SPEC says AGPLv3. `tpot_threatintel` shipped as Apache 2.0. Pick
one and stick with it:

- **AGPLv3** (per spec): viral, ensures modifications stay open even
  when deployed as SaaS. Right answer if the goal is to keep the
  ecosystem open.
- **Apache 2.0**: permissive, allows commercial closed-source forks.
  Right answer if the goal is maximum adoption.

The spec's reasoning: AGPLv3 prevents "anyone from strip-mining the
code into a closed-source product." This matches the stated goal of
"keep the project genuinely open."

**Recommendation: ship AGPLv3 per spec.** Adoption is somewhat lower
under AGPL but the community-aligned signaling matters more than
maximum reach.

---

## 18. Concrete recommendations for tpot2cti development order

Based on what we learned, develop in this order:

1. **Project scaffold** — repo, license, scaffold per V1_SPEC §2.4
2. **`shared/stix_ids.py`** — UUID5 helpers AND `sensor_infra_name()`
   helper from day 1 (port from tpot_threatintel commits 15521dc + 3484548)
3. **`shared/net.py`** — `wait_for_host()` for tunnel cold-start race
4. **`shared/logging.py`** — `setup_logging()` + `restore_logging()`
5. **Core cycle loop** — ES query + state DB + log
6. **Per-parser modules** — start with Cowrie (richest), then Suricata,
   then Fallback. Each parser implements `has_substance()` AS PART OF
   THE PARSER, not bolted on later.
7. **Three-pass STIX publisher** with bundle dedup + label-union (port
   the dedup block from PoC)
8. **Daily top-100 credentials Note** (V1_SPEC §6)
9. **Cycle anchor + transient retry** (port pattern from
   tpot_threatintel commit 61b2835)
10. **`setup.sh`** that clones OpenCTI upstream
11. **HARDENING.md** + lockdown script with all 4 gotchas
12. **Optional connectors:** tpot2cti-credentials, then tpot2cti-vault
13. **End-to-end test against live T-Pot**

Estimated: 2-3 weeks of focused work, per V2_OPENSOURCE_HANDOFF
§"sign-off" estimate.

---

## 19. What we'd do differently a second time

If we were to do tpot_threatintel over (we're not — we're moving to
tpot2cti — but for the record):

1. **Read V1_SPEC.md and V2_OPENSOURCE_HANDOFF.md BEFORE writing any
   code.** We didn't have these docs during tpot_threatintel
   development. They would have prevented every major mistake.

2. **Run the PoC side-by-side from day 1.** Having the PoC available
   as a reference implementation would have prevented the
   over-emission bug from getting committed.

3. **Test against real T-Pot data on day 1.** We waited until day 4
   to point at real data. Without that, the over-emission was
   invisible.

4. **Set scope discipline.** Every "while we're at it" added a
   connector that delayed the core importer being right.

5. **Match the PoC's emission shape before adding any enrichment.**
   The order should be: emit correctly → match PoC's per-session
   object count → THEN add enrichment as separate connectors.

---

## 20. Final note

`tpot_threatintel` was an honest attempt at a V1 OSS rewrite that
exceeded the V1 scope and discovered why the scope was tight in the
first place. The lessons are valuable. The code is not the right
foundation for the actual `tpot2cti` project — start fresh, follow
the spec, port only the proven helpers.

These 20 sections are the complete handoff from the V0 prototype to
the V1 implementation. If anything else from `tpot_threatintel`
becomes relevant during tpot2cti development, the V0 repo lives on
in git history (or in archive if you delete the GitHub repo) and can
be referenced via commit hash.

Good luck with V1.

— end of original document —


---

## Appendix A — Lessons ported from the production PoC (newer than V0)

Added 2026-05-21 after the structural evaluation against the new PoC
codebase at `/home/mike/poc/tsec-tpot-connectors/`. Each item below is a
one-paragraph paraphrase of a lesson from PoC's `docs/LESSONS_LEARNED.md`;
the section number references theirs. Read the originals for full
context — they're the canonical source.

### A.1 PoC §29 — pycti's bundle splitter silently drops duplicate-id labels

When the SAME deterministic STIX ID (e.g. `ipv4-addr--<uuid5 from ip>`)
appears multiple times in a bundle with different label sets, pycti's
`OpenCTIStix2Splitter.split_bundle_with_expectations` builds an id→object
dict where the **last** copy wins. Earlier copies' labels are lost. In
one PoC production cycle, 306 of 1,678 objects (~18%) were silently
collapsed, and every single CVE/exploit label was destroyed for the
entire deployment lifetime — until they added label-union dedup BEFORE
the splitter.

**Where we stand:** Our `publisher.py:_dedup_label_union` does
label-union dedup before pycti's send. We're protected against this
specific failure mode. **Worth adding a unit test** that emits the same
IP from two parsers with different labels and asserts the shipped bundle
has the union (commit `0bc5261` is a partial test; a fuller one would
mock pycti and check the final bundle dict).

### A.2 PoC §31 — "Bulk-importer vs enrichment connector" two-question rule

Before adding a new T-Pot data source to the bulk importer, ask:
1. **Is each event independently actionable as an IoC?** (Heralding
   credential capture: yes. P0f OS fingerprint: no.)
2. **Does every event have a non-trivial probability of producing a
   downstream observable?** (Cowrie session: yes. P0f-only IPs: ~99%
   never engage substantively.)

If either is **no** → it belongs in an on-demand enrichment connector
that hooks OpenCTI's `INTERNAL_ENRICHMENT` mechanism, NOT in the bulk
importer. P0f at fleet scale was 2.3M events/day producing almost no
STIX after the substance filter — wasted ES bandwidth + parser cycles.

**Where we stand:** As of 2026-05-21 we default `TPOT2CTI_IGNORE_TYPES=P0f`
in `.env.example` per this lesson. The future P0f connector (when we add
one) will look more like the PoC's `tsec-tpot-p0f-connector` (scope =
IPv4-Addr, on-demand enrichment) than like a 25th parser.

### A.3 PoC §32 — Parser-vs-builder strict separation

Parsers should be PURE event categorizers: raw ES doc →
`ParsedEvent`/`HoneypotEvent` dataclass with category/action/outcome +
extended fields. **No STIX, no IoC extraction, no I/O.** STIX-shape
decisions (does this become a URL observable vs a string in a
description?) live in the STIX builder. URL/cookie/hash extraction from
semi-structured fields (shell commands, HTTP bodies, etc.) also lives in
the builder because:
1. Parsers stay easy to test and shareable across consumers (the PoC's
   report-generator imports from `parsers/` too).
2. Cross-event extraction (URLs spanning the full command sequence in a
   Cowrie session) only exists after the correlator builds the
   AttackSession — the parser has no visibility into it.
3. The "is this a URL observable or just text?" choice is a STIX-shape
   choice.

**Where we stand:** Our 4 parsers with `build()` methods (`cowrie`,
`suricata`, `honeytrap`, `fallback`) currently violate this — they call
`STIXBuilder` directly to produce IPv4 / IP-Indicator / URL / Note
objects. The other 20 parsers route through `build_driveby_session()`
and naturally follow the pattern. **Refactor planned** (task #48 P2) to
move the STIX-shape logic from those 4 parser `build()` methods into
builder methods (e.g. `builder.build_cowrie_session(session)`).

### A.4 PoC §33 — Three OpenCTI/pycti silent-failure modes

All three discovered while building audit infrastructure (we don't have
audit infra in V1, so these are forward-looking):
1. **`import_processed_number` doesn't count upserts.** A bundle that's
   all dedup-collapses to existing objects returns 0, even though the
   operation was correct.
2. **`pycti.api.work.get_work()` returns None for known-complete works**
   under certain timing conditions. Don't treat None as "failed"; verify
   with the search API.
3. **`status == 'complete'` is premature for batched bundles.** pycti
   reports complete after enqueueing, not after the worker finishes
   processing. If you rely on this to decide "now run pass 2 of the
   three-pass send," you'll hit MISSING_REFERENCE.

**Where we stand:** Not relevant today (we don't depend on these signals
— our publisher uses simple `time.sleep` between passes per V1_SPEC §3).
Will become relevant if/when we add audit infrastructure that checks
per-bundle success.

### A.5 PoC §36 — Don't pre-classify malware in the importer

PoC hp-connector used to emit `Malware(name="Malware-<sha[:16]>",
is_family=False)` for every captured file. Result: 54,023 entries with
garbage names like `Malware-5237503dedd7e264` polluting OpenCTI's
Malware index, all duplicating SHA256-keyed slots that real classifiers
(GTI sandbox, CrowdStrike sandbox) needed to own later. They removed the
emission; now only File observables emerge from the importer, and
classifier connectors add `Malware` SDOs only when they have
authoritative input (e.g., a VirusTotal `suggested_threat_label`).

**Where we stand:** We don't emit `Malware` SDOs (V1_SPEC §4 doesn't
list them). Correct outcome, partially by deliberate spec design and
partially by absence-of-enrichment. Worth flagging in V1_SPEC §4 as an
explicit "do not emit" so a future contributor doesn't add it back.
Honeypot droppers go in the malware-vault sidecar; sandbox-class
enrichment is post-v1.0.

### A.6 PoC §38 — `docker --env-file` does NOT strip inline comments

When spinning up additional containers from outside `docker compose`
(e.g. ad-hoc sidecar workers for backfill scaling), the obvious move is
`docker run --env-file .env ...`. **Don't.** Docker's `--env-file`
parser does not strip inline `#` comments — every character after `=`
and before newline becomes the variable's literal value. A line like
`TPOT2CTI_DRY_RUN=true   # smoke test` becomes the literal value
`"true   # smoke test"`, which fails any naive `.lower() == "true"`
check. Code that does this very-common pattern then silently disables
the feature.

The right pattern when spawning sidecar containers from a script:

```bash
set -a && source .env && set +a    # shell strips comments
docker run -d -e VAR_A="$VAR_A" -e VAR_B="$VAR_B" image
```

**Where we stand:** Our `setup.sh` writes `.env` files; we use
`docker compose --env-file`. Compose strips comments correctly. We are
NOT vulnerable today, BUT the moment someone follows a "scale up" guide
that uses raw `docker run --env-file`, they're in the footgun. Mitigation
added 2026-05-21: `tpot2cti/env.py` implements `truthy_env()` /
`truthy_str()` with explicit inline-comment stripping (port of PoC's
`shared/tsec_env.py`). `config.py:_env_bool` delegates to it.

### A.7 PoC §39 — Separate Notes per enrichment source (post-v1.0)

When multiple enrichers classify the same observable (GTI says "Mirai",
CrowdStrike says "Outlaw"), do NOT merge into a single `Notes` Note.
Emit one Note per source with the source name in the abstract. Analysts
then see the classifier disagreement explicitly. Merging hides it.

**Where we stand:** We have no enrichment yet, so this is moot.
Important to remember when the first companion connector lands — do NOT
design a "merged classification Note" pattern. One Note per source.

— end of appendix A —
