# Evidence gate (DR-02)

> **Status: scaffolding shipped; first rule (SIP_FRAUD) in.** The gate, the
> decoupled sightings, the sighting grain, the counters and the counts pattern
> exist in code behind flags that default to today's output. The rules that
> decide what is evidence (the evidence classes) come from DR-01, one class at
> a time. In so far: **SIP_FRAUD** (owner, 2026-09-27): a SentryPeer session is
> accepted (`sip-fraud-intl-dial`) only when it dialled an international number
> (`is_intl_dial`: `+`, `00`, `011`, `9011` or `900` then at least four digits), and
> refused (`sip-no-intl-dial`) otherwise. Every other session is still accepted
> by the stub (`stub-accept-all`). [`EVIDENCE.md`](EVIDENCE.md) is the design
> contract these rules implement.

## 1. Flags

| Setting | Values | Default | Effect |
|---|---|---|---|
| `TPOT2CTI_EVIDENCE_GATE` | `off`, `shadow`, `enforce` | `off` | `off`: the gate is never consulted and output is byte-identical to the builder before the gate existed. `shadow`: every decision is counted and each refusal is logged; nothing emitted changes. `enforce`: a refused session mints no attacker-IP Indicator, and the bundle carries no relationship or `object_refs` entry pointing at an Indicator that was withheld and not emitted by another session. |
| `TPOT2CTI_SIGHTINGS_DECOUPLED` | `true`/`1`/`yes`/`on`/`y`/`t`, `false`/`0`/`no`/`off`/`n`/`f` | `false` | Emit the observable's `:ipv4` Sighting at all five dual-sighting sites even when no Indicator was minted, whether the gate refused it or it could not be built. Off keeps today's behaviour: no Indicator means no Sighting at all. |
| `TPOT2CTI_SIGHTING_GRAIN` | `legacy`, `sensor-ip-day` | `legacy` | See section 3. |
| `TPOT2CTI_COUNTS_INDEX_PATTERN` | index pattern | `ES_INDEX_PATTERN` | See section 5. |

A value that is not in the list stops startup with a `ConfigError`, so a
typo in a safety switch cannot quietly mean `off`. This includes the boolean:
`TPOT2CTI_SIGHTINGS_DECOUPLED=ture` is an error, not `false`. Values are
case-insensitive, an inline `# comment` is stripped, and empty means the
default. `enforce` without decoupled sightings is allowed but logs a warning
at startup, and every refusal then shows up in `site_calls.none` (section 4).

**A bad value stops more than the core.** The malware-ingest, noisefloor,
blocklists and lookup sidecars read the same `.env` (`env_file: [.env]` in
`docker-compose.yml`) and call the same `load_config`. A typo in one of these
settings therefore crash-loops all five containers, not only `tpot2cti`.
Check the value with `docker compose -p tpot2cti logs --tail 20` after every
change, and fix it before anything else.

The five sites are the builder methods that mint an attacker-IP Indicator
and call `build_dual_sighting`: `build_cowrie_session`,
`build_suricata_alert`, `build_honeytrap_probe`, `build_fallback_event` and
`build_driveby_session` (the drive-by site also serves the web, protocol,
malware and fingerprint builders, which start from it). File Indicators (sample hashes)
are not gated: the gate decides whether an address is promoted.

## 2. What shadow logs

Accepts are only counted, because one line per accepted session would be
thousands of lines a cycle at hive scale. Refusals are grouped per cycle by
(reason, site, address, sensor, type): each group writes one line, when the
bundle is finalized, whose message is `evidence_gate ` followed by a JSON
object (one line per refused session would have been ~28k lines a day for
SentryPeer REGISTERs alone):

```json
{"action": "would-refuse", "event_type": "Sentrypeer", "events": 41,
 "first_seen": "2026-10-01T10:00:00+00:00", "last_seen": "2026-10-01T10:14:02+00:00",
 "mode": "shadow", "reason": "sip-no-intl-dial", "sensor": "pbx-prod-01",
 "sessions": 41, "site": "driveby", "src_ip": "…"}
```

`action` is `refused` under `enforce`. To extract the lines from the JSON
log:

```bash
jq -r '.message | select(startswith("evidence_gate ")) | .[14:]' tpot2cti.log
```

Once per cycle, `evidence_gate_summary {json}` logs the same counters that
reach `/health`.

## 3. Sighting grain

**Today's grain (`legacy`), exactly.** A Sighting's id is
`generate_sighting_id(sensor, "<target>:<YYYY-MM-DD>", discriminator)`
(`STIXBuilder._sighting_id`), where the day is the UTC date of the
session's `first_seen`. `target` is the attacker's IP Indicator (no
discriminator) or its IP observable (discriminator `ipv4`, also used for
IPv6 observables). So one address on one sensor on one UTC day has **at
most two Sightings, whatever honeypot types it touched**. Within a bundle,
later sessions fold into the one kept (`_merge_or_emit_sighting`):

- `count` is the day's authoritative total from ES (`daily_event_counts`:
  every document for that `src_ip`, `t-pot_hostname` and day, all types except
  `TPOT2CTI_IGNORE_TYPES`), taking the maximum across sessions, when ES
  returned one. Otherwise it is the sum over distinct sessions of each
  builder's per-session count: `event_count`, or 1 for a Suricata alert.
- `first_seen` and `last_seen` span every folded session.
- `description` is up to five distinct per-session lines, then
  `(+N further session(s) this day)`. Only the Cowrie, Honeytrap and
  fallback builders write a line. Suricata and drive-by sessions add to the
  count but not to the text, so a Sighting whose count covers Cowrie,
  Suricata and Heralding reads only "Cowrie SSH …".

A session that crosses midnight stays on the day it started. Across cycles,
OpenCTI upserts by id and replaces `count` and `description`.

**`sensor-ip-day`.** The ids, counts and windows stay the same (the id
grain already is one per sensor, address and day, and DR-02 rejected
per-type Sightings). The description starts with one line:

```
Types seen from this address on this sensor this UTC day: Cowrie, Heralding, Suricata
```

followed by today's per-session lines. The list joins the types seen in this
bundle with the day's types from ES. In this mode only, the counts
aggregation carries a `terms` sub-aggregation on `type.keyword` (size 64), so
a narrow later cycle cannot shrink a list that OpenCTI replaces on upsert.
Time that query (M4) before switching the mode on.

**Switch the grain at a UTC day boundary**, in either direction. The
description is replaced on every upsert, so switching mid-day gives that day's
Sightings a description that changes format part-way through the day. A
Sighting the new mode never touches again keeps the old text.

## 4. Counters in `/health`

`/health` gains `evidence_gate: {"last_cycle": {...}, "totals": {...}}`
(`null` before the first cycle). `last_cycle` is also in the cycle summary.
`totals` sums the cycles since `since` and lives in the state DB.

- **Totals restart**, with a new `since`, whenever `mode`,
  `sightings_decoupled` or `sighting_grain` differ from the stored values. A
  shadow window therefore never includes the off-mode cycles before it.
  Delete the `evidence_gate_totals` key to restart by hand; DR-03's reset
  empties it too.
- **Totals count only cycles whose publish succeeded.** A failed cycle is
  retried over the same window and would otherwise be counted twice.
  `last_cycle` is written every cycle, successful or not, and describes the
  latest attempt.

| Key | Meaning | Healthy reading |
|---|---|---|
| `mode`, `sightings_decoupled`, `sighting_grain` | the flags in force | what you deployed |
| `accepted`, `refused` | sessions by gate reason (empty when `off`) | `stub-accept-all`, plus `sip-fraud-intl-dial` / `sip-no-intl-dial` for SentryPeer (the other DR-01 classes pending) |
| `accepted_total`, `refused_total` | sums of the above | refused share is the shadow's result |
| `indicators_withheld` | refused sessions under `enforce` (sessions, not Indicators: an address with 40 refused REGISTERs counts 40, and one of its sessions may still emit the Indicator) | equals `refused_total` under `enforce` |
| `site_calls.with_indicator` | site calls where both Sighting sides existed | most calls |
| `site_calls.observable_only` | calls where only the observable Sighting was emitted (decoupled) | grows with refusals once decoupled |
| `site_calls.none` | calls that left **no** Sighting (no Indicator, not decoupled) | **0**; anything else is an observable Sighting lost |
| `observable_sightings.with_indicator` / `.without_indicator` | observable-side Sighting objects in the bundle after folding, by whether that sensor, address and day also has an Indicator Sighting | `without` is 0 today |
| `relationships_dropped`, `object_refs_dropped` | references removed because they pointed at a withheld Indicator | 0 outside `enforce` |
| `cycles` (totals only) | cycles summed | |

For the DR-02 M3 measurement, sample `/health` hourly: differences between
successive `totals` cover every cycle, not one in four.

### When the bookkeeping itself fails

`finalize_bundle` (the enforce cleanup plus the Sighting counters) and the
counter persistence never abort a cycle:

- **`off` and `shadow`:** the error is logged at ERROR and the unfiltered
  bundle is published. Nothing was withheld, so that bundle is the correct
  result. A persistence failure is logged at WARNING and the counters are
  skipped for that cycle.
- **`enforce`: fail closed.** A cleanup failure is logged at ERROR as
  `evidence gate cleanup FAILED under enforce`, nothing is published, and the
  cursor does not advance, so the next cycle retries the same window. An
  unfiltered bundle could carry edges to withheld Indicators, and OpenCTI
  never resolves those. A cleanup that keeps failing shows up as a cycle
  that never succeeds, and `/health` turns stale on its no-success ceiling.

## 5. Counts index pattern and DR-07 phase 2

`TPOT2CTI_COUNTS_INDEX_PATTERN` is read only by `daily_event_counts`. The
event read, and its exclusion count, always use `ES_INDEX_PATTERN`. The core
does not skip documents tagged `throttled` at read time, in the event read or
the counts query (a guard test enforces this). A throttled document is still
an event the source sent, and skipping it would take `AUTH_SUCCESS` and
commands out of a flood source's later sessions.

DR-07 phase 2 moves throttled documents out of `logstash-*` and publishes
their totals in the transform index `tsec-counts-suppressed` (`day`,
`src_ip`, `type`, `sensor`, `suppressed`). **Do not just add that index to
this pattern.** The counts query groups `logstash` fields (`@timestamp`,
`src_ip.keyword`, `t-pot_hostname.keyword`) and counts documents. It would
skip the transform's rows or count each one as 1, never sum `suppressed`.
Config loading warns if the pattern names a `tsec-counts` index. Phase 2
still needs a second aggregation: the sum of `suppressed` per (`src_ip`,
`sensor`, `day`) with `TPOT2CTI_IGNORE_TYPES` applied to `type`, added to the
kept count. Measured on 2026-09-25, the drop is concentrated in about 78
flood pairs a day. Every other pair keeps its count.

## 6. Rollout

1. **Deploy with every flag at its default.** Output is byte-identical
   (section 7). Check that `/health` shows `evidence_gate.last_cycle.mode:
   off` and `site_calls.none: 0`.
2. **`TPOT2CTI_EVIDENCE_GATE=shadow` and `TPOT2CTI_SIGHTINGS_DECOUPLED=true`**
   with the stub. This proves the plumbing only: output is still identical,
   and `accepted` shows `stub-accept-all` for every site call.
3. **Deploy DR-01's `decide()` in shadow.** DR-01's classes land one at a
   time; each class's 14-day shadow clock starts when it is deployed
   (SIP_FRAUD first, owner decision 2026-09-27), and enforcement waits for
   all of them. Over the window, collect the refusal lines (for the
   M2 join and the B-prime 5% trigger), `refused` by reason, and
   `last_cycle_duration_s` hourly (M3). The `/health` totals restart whenever
   the gate flags change (section 4). Deploying the predicate alone does not
   restart them, so note the deploy time, or delete `evidence_gate_totals`
   when the predicate goes live, so the totals cover exactly the window.
4. **Enforce** only when the known gaps in section 8 marked as blocking are
   closed, and both of these hold over the 14 days:
   - cycle p95 is at or under 450 s, and
   - no observable Sighting is lost: `totals.site_calls.none` stays 0 with
     decoupling on, and after the switch the per-cycle observable Sighting
     total (`with_indicator + without_indicator`) matches shadow's for
     comparable windows. `test_enforce_refusing_everything_loses_no_observable_sighting`
     checks the same property on fixtures.
5. **`TPOT2CTI_SIGHTING_GRAIN=sensor-ip-day`** is independent of steps 2 to
   4. Switch it on after timing the counts query with the types
   sub-aggregation.

**Reversal:** each flag is read at startup. Set it back and restart.
Indicators refused while `enforce` was on are not backfilled. Their
Sightings are not affected when decoupling was on.

## 7. How "off is byte-identical" is proven

`tests/dr02_harness.py` builds two bundles from fixed inputs, with a fixed
clock and fixed builder timestamps:

- one `run_cycle` over every real fixture under `tests/fixtures/real`,
  where the fake ES returns one authoritative daily count;
- one session per dual-sighting site, built directly (this covers Honeytrap
  and the fallback, which `_is_bare_scan` would skip, plus a second day, a
  multi-type day and an IPv6 address).

Their SHA-256 digests (`tests/fixtures/dr02/golden_digests.json`) were
taken on a clean origin/main 71e47ec worktree with only the harness added.
`tests/test_evidence_gate.py` compares every default-equivalent flag state
against those digests: unset, explicit `off`, `shadow`, `enforce` with the
stub, decoupled, and a counts pattern equal to the event pattern. After a
mismatch, run `python -m tests.dr02_harness --dump DIR` on both commits and
diff the output.

## 8. Deferred

- **To DR-01:** the evidence classes, meaning the real `decide()` and its
  reason tokens, which the builder, counters and log already carry. Also the
  trace test on the canary harness: an evidence session yields an Indicator
  plus both Sightings within two cycles, and a connect-only session yields
  the observable and its `:ipv4` Sighting and no Indicator.
- **B-prime cross-session promoter** (DR-02 decision 5): the design is fixed,
  but it is built only if the shadow shows the 5% miss rate or DR-01
  requires it. The promoter is the sole owner of demotions and the writer of
  `object_max_state`.
- **DR-07 phase 2 count summing** (section 5), after the transform is
  deployed.
- **Under `enforce`, known gaps.** The cleanup in `finalize_bundle` sees one
  bundle only. It removes references to an Indicator withheld in that bundle,
  but it cannot know which Indicators OpenCTI already holds.
  - **Blocking enforcement, over-strip across cycles:** an address whose
    evidence session came in an EARLIER cycle (so OpenCTI holds its
    Indicator) and whose later bundle has only refused sessions (e.g. a SIP
    address that dialled abroad yesterday and only REGISTERs today) has its
    Indicator treated as withheld, so the cleanup strips valid references to
    it (the protocol AttackPattern `indicates` edge, profile Note refs). Also
    note that Suricata SIP alerts on the same address still mint the
    Indicator through the stub, so enforce may withhold less than shadow
    counts suggest.
  - **Blocking enforcement:** attacker-profile Notes
    (`attacker_profile.py`, the live, daily and weekly emitters) put the
    address's Indicator id in `object_refs` for every active address. The
    daily and weekly Notes cover addresses from earlier cycles. An address
    refused in an earlier cycle, whose Indicator was never created, is
    therefore referenced from a later bundle that did not withhold it, and
    the cleanup does not catch it. These Notes need an "Indicator exists"
    check (state or OpenCTI) before `enforce`.
  - **Closed in this change:** the campaign ledger used to mark every pending
    member emitted even when the cleanup later dropped its `indicates` edge,
    so that member was never attached. `emit_campaigns` now asks
    `STIXBuilder.indicator_available()`, skips members whose Indicator was
    withheld in this bundle, and marks only the members it kept. The skipped
    ones stay pending and are attached in the cycle where their Indicator
    exists. Members refused in an earlier cycle have the same cross-cycle
    limit as the Notes above, because the predicate cannot see OpenCTI.
  - **By design:** the Indicator decision is per session. An address refused
    in one session and accepted in another in the same bundle is emitted, and
    its references stay.

## 9. ICS (2026-09-30)

**The class (shadow first).** `evidence._decide_ics` decides ConPot sessions
and ICS emulator sessions from `session.meta["ics"]` (docs/parsers/conpot.md):

| Reason | Decision | When |
|---|---|---|
| `ics-write-control` | accept | any write/control function, even from a research scanner |
| `ics-interaction` | refuse | a valid industrial request beyond the handshake, but no write (decision 2026-09-30: 94.5% of such addresses are census fingerprint reads; reconnaissance keeps its observable and Sighting, only a write mints a malicious-activity Indicator) |
| `ics-research-scanner` | refuse | the same, from a heuristically classified research scanner |
| `ics-handshake-only` | refuse | only session-opening frames |
| `ics-connect-only` | refuse | connection events or non-protocol bytes |
| `ics-snmp-only` | refuse | SNMP without a Set (normally refused before the gate, below) |

HTTP, FTP and IPMI sessions on the emulators get the stub accept. Like every
class, this changes nothing until `enforce`.

**The refusals (every gate mode).** `TPOT2CTI_ICS_REFUSALS` (strict boolean,
default true) stops harm now, independently of the gate:

- A session that only sent SNMP GetBulk (the spoofed-source reflection shape:
  one repeated GetBulk from fixed source ports; the "sources" are probably
  victims) is dropped in `run_cycle` before anything records it: no
  observable, no Indicator, no Sighting, no activity row. Counted in
  `ics.snmp_reflection_dropped` (sessions, events, distinct addresses, 25
  samples). The raw documents stay in the hive.
- Any other SNMP-only session (Get, GetNext) keeps its observable and
  Sighting (with `TPOT2CTI_SIGHTINGS_DECOUPLED=true`) but mints no Indicator:
  `ics.indicator_refused["ics-snmp-only"]`.
- A source on the benign-scanner allowlist is **kept** for ICS sessions,
  labelled `scanner:research` / `scanner:<vendor>` with its match basis in
  the description, and never minted as an Indicator:
  `ics.indicator_refused["ics-research-scanner-allowlisted"]`. Before, it was
  dropped with every other event of that source. Heuristic scanners
  (forward-confirmed PTR suffix or AS-organisation substring, `ics.py`) are
  labelled the same way and refused by the class above in `enforce`.
- A write/control session is never refused.

`false` restores the previous behaviour (Indicators for SNMP-only sessions,
allowlisted scanners dropped) without a rebuild. The parser fix itself is not
switchable.

**Counters.** The cycle summary and `/health` carry `ics.last_cycle`:
sessions by tier and protocol, the reflection drop, refusals, research-scanner
events and sessions, and write/control sessions (total and up to 25 with
address, sensor, time and functions).
