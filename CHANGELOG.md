# Changelog

All notable changes to `tpot2cti` are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); dates are UTC.

## [Unreleased]

### Suricata read scope + drop attribution

- CORE no longer fetches Suricata documents with no `alert` object. The parser
  discards them unconditionally, so they were fetched, decoded and thrown away:
  measured 1,816,522 of 3,399,134 documents/day, **53.4% of all read volume**.
  Verified to cost nothing — 217,748 alert-bearing Suricata documents before
  and after. Controlled by `TPOT2CTI_SURICATA_ALERT_ONLY` (default on); not
  retroactive once the watermark advances.
- The exclusion is **counted**, not assumed: two independent ES counts per
  cycle attribute it causally, reported as `query_excluded` and persisted.
- `unparsed` is attributed by sensor `type`, with Suricata split by
  `event_type`. It was a single ~172k/cycle pile in which a silently broken
  parser would have been invisible.
- The Suricata parser now also rejects an EMPTY `alert` object, closing an
  asymmetry with the read filter: ES `exists` treats `alert: {}` as missing
  while `isinstance({}, dict)` is true, so the query would have excluded a
  document the parser accepted. No live exposure; found by the guard test.


### Fixed

- **H0neytr4p parser was reading the wrong ES field names, silently
  emitting zero URLs.** A field-presence census over 34k live docs/24h
  found that the V1_SPEC §5.7 nested `request.*` shape has never existed
  in this hive's data, and that two flat schemas ship concurrently. The
  parser read only the legacy names, so on live traffic `method` and
  `user_agent` were `None` for ~99.6% of events and `host_header` was
  `None` for **100%** of them — neither schema ships `host_header`. URL
  reconstruction needs host + URI, so `session.urls` was never
  populated: **0 URLs and 0 domains across all 12,860 H0neytr4p rows**
  in the live state DB, against 1,072/1,072 for Tanner. The URL
  observable that V1_SPEC §5.7 promised had never once been emitted.
  Reads are now modern-first with legacy and nested fallbacks; verified
  on 333 real docs (host_header 297/333, 37 URLs reconstructed).

- **h0neytr4p reports the attacker-controlled `X-Forwarded-For` header
  as `src_ip`**, so Log4Shell scanners deposited obfuscated JNDI
  payloads in the source-address field: `src_ip` is byte-identical to
  `header_x-forwarded-for` in 33/33 documents carrying that header, and
  nothing in the document preserves the real TCP peer. 30 such rows
  reached `attacker_activity`. These now fail a central source-address
  gate in `run_cycle`; events whose XFF is a *plausible* address are
  flagged (`meta.src_ip_from_xff`) rather than dropped, since none has
  been observed and dropping would discard real attribution.

- **`state.upsert_attacker_activity` now rejects and canonicalizes its
  key.** A non-address `src_ip` silently poisoned every consumer that
  reads the table back as an address. `prune_malformed_attacker_activity`
  (wired into the per-cycle `prune_all`) removes rows written before the
  gate existed.

### Added

- **`drop_reasons.src_ip_rejected`** — rejected/unparseable source
  addresses are now counted and surfaced in `/health`'s
  `last_cycle_drops`, matching what the noisefloor enricher does with its
  `malformed` counter. Previously `canonical_ip()` returned `None`, the
  builders skipped the session, and the loss was invisible: the exact
  silent-zero-work shape this project keeps re-learning.

- **`tpot2cti/log4shell.py` + unattributed payload salvage.** A
  Log4Shell probe's JNDI endpoint is live attacker infrastructure and is
  worth more than the spoofable address it arrived in, but it was being
  discarded entirely (the `${jndi:` hint regex greps for a literal string
  that obfuscated payloads never match, and nothing scanned headers or
  `src_ip`). The new module resolves the `${x:y:-c}` per-character
  obfuscation — all 30 live payloads decode — and
  `STIXBuilder.build_unattributed_payload_objects` emits a
  sensor-anchored graph for them: URL, Domain-Name, `CVE-2021-44228`,
  `T1190`, a Sighting and an explanatory Note. It deliberately emits **no**
  IPv4-Addr and **no** Indicator — asserting a source we do not have
  would be fabricated attribution. Grouped by C2 host rather than URL,
  because the observed scanner encodes the probed header into the
  callback's leading label and so yields ~12 URLs per zone.

### Security

- **Removed real infrastructure identifiers from the public repository.**
  `deploy/phase2-honeypots/soak-snapshot.sh` hard-coded a live sensor address,
  SSH user and key path (`mike@76.165.200.142`, port 64295); it now reads
  `TPOT_HOST` / `TPOT_SSH_USER` / `TPOT_SSH_PORT` / `TPOT_SSH_KEY` from the
  environment with example defaults. `docs/V2_OPENSOURCE_HANDOFF.md` no longer
  names the real connector host. The live honeypot persona (organisation,
  domains `*.louisianatech.io`, internal hostnames, staff names, city) is
  genericised to `ExampleCo` / `*.example.com` across 19 files, and the TLS
  config renamed to `openssl-dev-example.cnf`.

  **These values were previously committed and are therefore already public in
  git history — this change stops them being served at HEAD but does not purge
  history.** Treat the affected sensor address, the `id_ed25519` key and that
  SSH account as exposed, and assume the published persona is burned for
  deception purposes.


### Documentation

- **Added `docs/ENRICHMENT.md`** — the specification for the ENRICH ring
  (not yet implemented; marked as such). Establishes: the "emits STIX ⇒ lives
  in the package" rule that keeps deterministic IDs shared; a three-lane
  architecture (bulk lists / per-object API / own telemetry) that ships in the
  core image as separate processes; a zero-signup source tier as the default;
  the enrichment ledger (cache + budget + backlog + health as one component);
  write-back rules against the predecessor's "reputation, not graph" failure;
  and a label-namespace registry. Updated the README roadmap, which previously
  described a superseded one-connector-per-source plan.


### Fixed (Tier 2 — pre-merge review round)

- **IPv6 dangling references, centralized.** The first IPv6 pass canonicalized
  the address for the *observable* id but several sites still minted the
  *indicator*/observable id from the raw string, so a non-canonical IPv6 (e.g.
  expanded/uppercase `2001:0DB8:…:DEAD:BEEF`) produced dangling
  `indicator→attack-pattern`, attacker-profile Note, and campaign edges. Both
  independent reviewers reproduced it. Fix: a single source of truth in
  `stix_ids` — `canonical_ip`, `attacker_ip_observable_id`,
  `attacker_ip_indicator_id` — used everywhere (builder, `attacker_profile`,
  `campaigns`), replacing the clever-but-misusable `_ip_sco_id(x) or
  generate_ipv4_id(x)` idiom. IPv4-mapped IPv6 (`::ffff:1.2.3.4`) now normalizes
  to IPv4 so an attacker isn't split across two observable families, and
  `build_ipv4` canonicalizes too (so malformed-but-regex-valid IPv4 can't dangle
  either). New regression tests use non-canonical IPv6.
- **Credentials health-check won't false-alarm on a quiet install.** The
  zero-event unhealthy signal now arms only *after* at least one nonzero cycle
  (proving the query works); a brand-new or genuinely quiet honeypot stays
  healthy until credentials have flowed at least once.

### Added (Tier 2 — CORE hardening)

- **IPv6 attacker support.** Previously only `_IPV4_RE` existed, so an IPv6
  `src_ip` produced no observable, no indicator, and no sighting (silent total
  loss). Added `generate_ipv6_id`, `build_ipv6`, a version-aware
  `build_ip_observable` dispatcher and `_classify_ip`/`_ip_sco_id` helpers
  (stdlib `ipaddress`, canonicalized/compressed), made `build_ip_indicator`
  and `build_attacker_context` version-aware, and switched the session
  builders' hardcoded `generate_ipv4_id(src_ip)` sites to the version-aware id
  (with an IPv4-identical fallback). IPv4 behaviour is unchanged; new
  `tests/test_ipv6.py` covers the observable/indicator/dispatch/canonicalization
  and a full IPv6 driveby session with no dangling references.

### Changed (Tier 2 — CORE hardening)

- **Deleted the dead `has_substance()` parser contract.** It was defined on
  every parser and documented as the key emission gate, but the cycle loop
  never called it — `_is_bare_scan()` (main.py) is the real, single gate.
  Removed the 26 parser methods + base default (no runtime change), rewrote the
  comments/docstrings/docs so `_is_bare_scan` is the one documented gate, and
  cleaned the tests that asserted the dead method.

### Fixed (Tier 2 — CORE hardening)

- **Credentials sidecar queried the wrong field.** `tpot2cti-credentials`
  filtered on the analyzed `type` (capitalized values match nothing), so it
  silently collected zero credentials while its healthcheck stayed green (CORE's
  own credential store was unaffected). Now queries `type.keyword`, reports the
  container unhealthy after 5 consecutive zero-event cycles, and has a
  query-shape regression test.

### Changed (pre-merge review round)

- **`/health` no longer false-alarms on a long *first* cycle.** The no-success
  ceiling is measured against the last *successful* cycle; a fresh install
  whose first cycle legitimately runs longer than the ceiling now stays
  `in-progress` as long as **no cycle has finished yet** (the ceiling only
  starts once a cycle has *completed* without success — the failing-loop case).
  (`tpot2cti/health.py`)
- **`events_dropped` is now the true total** (`sum(drop_reasons.values())`), so
  `events_read == events_parsed + events_dropped` holds even when the
  self/benign filters fire; the per-reason split stays in `drop_reasons`.
  (`tpot2cti/main.py`)
- **Health status computation extracted into a socket-free `HealthStatus`
  class**; `HealthServer` now owns one and delegates. Unit tests exercise the
  logic without binding a port (verified to pass with `socket.bind` blocked).
  (`tpot2cti/health.py`, `tests/test_health.py`)
- Integration regression guard now also asserts `attack_patterns > 0`, so a
  broken ATT&CK path can't make the bound pass vacuously.

### Fixed

- **CORE: attacker-IP ATT&CK patterns are no longer re-emitted per session
  (ingestion-outage fix).** `STIXBuilder.build_attack_pattern()` ended with
  `return self._dedup(...) or obj`; the `or obj` fallback re-emitted the full
  AttackPattern SDO on every duplicate id instead of returning `None` like
  every sibling `build_*` method. Because `build_session_attack_patterns()`
  runs for **every** session, the ~30 unique techniques were re-minted once
  per substantive session — a busy catch-up window produced ~947k duplicate
  attack-pattern dicts in a single bundle (~96% of all emitted SDOs). All five
  call sites already guard with `if ap:` / `if not ap: continue`, so `None`
  is the correct contract. (`tpot2cti/stix/builder.py`)

- **CORE: `/health` no longer stays green while cycles fail forever.** The
  health check kept returning 200 as long as cycles *started* (the heartbeat
  arm), so during the outage above it reported healthy for 16 days while no
  cycle ever *completed*. The heartbeat arm now has a hard ceiling
  (`NO_SUCCESS_CEILING_MULTIPLIER = 3.0` × cycle interval): if no cycle has
  succeeded within it, `/health` returns 503 with `liveness:
  "cycling-no-success"` even while the process keeps looping, so the Docker
  healthcheck (`curl -f`) marks the container unhealthy within ~3 intervals.
  A genuinely long single cycle stays under the ceiling and still won't flap.
  (`tpot2cti/health.py`)

- **CORE: `CycleState.get_max_state_bulk()` now chunks its `IN (...)` lookup.**
  The pre-dedup cross-cycle state lookup put one bound variable per emitted
  object into a single `WHERE stix_id IN (...)`. Combined with the runaway
  attack-pattern bundle above, this overflowed SQLite's
  `SQLITE_MAX_VARIABLE_NUMBER` and raised `OperationalError: too many SQL
  variables` on **every** publish. Because the cursor only advances on publish
  success (by design), `last_run` never moved and the importer retried the
  same window indefinitely — ingestion was stalled from ~2026-07-19 to
  2026-08-04 while the process stayed "healthy." The lookup now batches at
  `_SQL_VAR_CHUNK = 500`, well under the oldest limit (999), so no bundle size
  can trip it. (`tpot2cti/state.py`)

### Added

- **Per-reason drop counters in the cycle summary and `/health`.** The cycle
  loop previously folded every discarded event into one opaque `events_dropped`
  bucket — so "why did nothing land?" meant grepping logs. Reads are now
  accounted for as exactly one of `parsed / unparsed / dispatch_error /
  self_or_internal / benign_scanner`; the breakdown appears in the cycle
  summary log (`drops={...}`), the cycle summary dict, and the `/health`
  payload (`last_cycle_drops`), so a silent-loss regression (e.g. a filter that
  starts dropping everything) is visible at a glance. (`tpot2cti/main.py`,
  `tpot2cti/health.py`)

- **First end-to-end integration test for `run_cycle`** (`tests/test_run_cycle_integration.py`),
  closing the V1_SPEC §13 gap where the cycle was only tested indirectly. It
  drives real sanitized fixtures through the full parse → correlate → build →
  publish path with fake ES + publisher seams, and carries the integration-level
  regression guard for this incident: 60 distinct command-running attacker IPs
  must collapse to a **handful** of AttackPatterns (bounded by the technique
  allowlist), not one per session. (Surfaced that TEST-NET-sanitized fixture
  IPs are correctly dropped by the self-filter — tests remap to routable space.)

### Tests

- Added regression coverage for both fixes (446 passing, up from 439):
  - `tests/test_attack_mapping.py::test_attack_patterns_dedupe_across_sessions`
    and `::test_build_attack_pattern_returns_none_on_duplicate` — a duplicate
    technique from a second same-IP session must not be re-emitted.
  - `tests/test_state.py::test_get_max_state_bulk_chunks_large_id_list` —
    `get_max_state_bulk()` over 5,000 ids succeeds and still returns the rows
    it has.
  - `tests/test_health.py::test_cycling_but_never_succeeding_goes_stale` and
    `::test_never_succeeded_past_ceiling_goes_stale` — `/health` returns 503
    once no cycle has completed within the no-success ceiling.

### Operational note

- The window auto-caps to 1 day when `last_run` is >24h stale
  (`main.py:_compute_window`), so a multi-day stall resumes from *now* forward
  rather than backfilling. Recovering a gap requires a manual cursor rewind;
  see `docs/SOAK_NOTES.md` → "Known incidents."
