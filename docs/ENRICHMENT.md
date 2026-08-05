# Enrichment (ENRICH ring)

> **Status: SPECIFICATION — not yet implemented.**
> This document is the agreed design for the ENRICH ring. No enrichment
> connector ships yet. Anything described here in the present tense is a
> *contract to build against*, not a description of current behaviour.
> (See [`CHANGELOG.md`](../CHANGELOG.md) for what actually exists.)

---

## 1. What this ring is for

CORE turns honeypot events into a STIX graph. ENRICH adds **third-party and
self-derived context** to the observables CORE already emitted, so that a
later SHARE ring can decide, per indicator, *"is this worth publishing, and
to whom?"*

The design goal that outranks all others:

> **Open-source users must get meaningful enrichment at zero cost, with no
> signup.** Paid providers (VirusTotal/GTI, Censys, CrowdStrike) are optional
> overlays. **No release milestone may depend on a commercial entitlement.**

### The counter-intuitive priority: suppression before attribution

A production fleet produces ~16,000 distinct attacker IPs *per day*, and most
are commodity internet scanners. For sharing, the urgent problem is **not**
"add more reputation prose" — it is **"do not publish mass-scanner noise as
targeted intelligence."**

Publishing unqualified data has a real cost: the predecessor platform had an
abuse.ch API key **banned** for exactly this, and then switched every sharing
channel off. Noise labels are therefore built *before* attribution sources —
the gate that decides what **not** to publish is what makes publishing
possible at all.

---

## 2. The organizing rule

> **If a component emits STIX into OpenCTI, it lives inside the `tpot2cti/`
> package and shares the identity + publish stack.**
> **If it only moves bytes or rows, it may be a standalone sidecar with its
> own build context.**

This is not stylistic. Deterministic UUID5 identity is the single costliest
thing in this project to get wrong — an id drift orphans every previously
emitted SDO and cascades into `MISSING_REFERENCE_ERROR` storms (see
[`LESSONS_LEARNED_FROM_V0.md`](LESSONS_LEARNED_FROM_V0.md) §3). Anything that
emits STIX **must** import [`tpot2cti/stix_ids.py`](../tpot2cti/stix_ids.py)
rather than re-deriving ids.

It also explains the existing layout rather than adding a second unexplained
pattern: `tpot2cti-credentials` (writes DuckDB) and `tpot2cti-vault` (fetches
sample bytes over SFTP) emit no STIX, so their build-context independence is
correct and they stay as they are.

---

## 3. Architecture — three lanes, one image, many processes

Enrichment is **three lanes**, split by what their failure mode actually is:

| lane | module | shape | its health question |
|---|---|---|---|
| **A — bulk lists** | `enrich/blocklists.py` | fetch list → match locally → label | *"is the list stale?"* |
| **B — per-object API** | `enrich/lookup.py` | budgeted per-observable calls | *"is the quota exhausted?"* |
| **C — own telemetry** | `enrich/noisefloor.py` | derive from our own data | *"is the window populated?"* |

**Lanes A and B are deliberately not merged.** Their health questions are
different, and merging them produces a health signal that cannot honestly
answer either. This project's defining failure mode is *silent zero-work*
(a sidecar collected nothing for two months; a legacy enrichment stage looked
idle-vs-broken indistinguishably), so failure domains stay legible.

Lane A costs **zero per-object API calls** — a downloaded list matched locally
scales to any number of observables for free. That property is what makes the
no-signup tier genuinely useful rather than a crippled demo.

### One image, many processes

Every module below builds from the **existing root `Dockerfile`** and ships in
the **same image** as CORE. Compose services differ only by `command:` and
profile:

```yaml
tpot2cti:                 command: python -m tpot2cti.main               # CORE — unchanged
tpot2cti-malware-ingest:  command: python -m tpot2cti.ingest.malware     # profiles: [malware]
tpot2cti-noisefloor:      command: python -m tpot2cti.enrich.noisefloor  # profiles: [enrich]
tpot2cti-blocklists:      command: python -m tpot2cti.enrich.blocklists  # profiles: [enrich]
tpot2cti-lookup:          command: python -m tpot2cti.enrich.lookup      # profiles: [enrich-api]
```

Rationale:

- **No duplication.** The predecessor reimplemented label/observable
  ensure-or-create **21+ times**; each bug fix landed in one copy and the
  other twenty kept the bug. Sharing one package makes that impossible.
- **Isolation comes from the process boundary, not the repo boundary.** The
  predecessor's own evaluation concluded that one-container-per-source was the
  wrong axis; what matters is the ring boundary. Separate processes give full
  failure isolation — an enrichment stall cannot slow or break the honeypot
  cycle — without duplicating code.
- **CORE stays exactly as lean as `V1_SPEC.md` intended.** The CORE *process*
  still runs only `main.py`; its cycle does not grow.
- One build, one version, one mental model.

### Folder layout

```
tpot2cti/
├── main.py                    # CORE entrypoint — unchanged
├── stix_ids.py                # shared identity  ← the reason ENRICH lives here
├── stix/builder.py
├── publisher.py               # shared write path (3-pass, label-union dedup)
├── es_client.py  state.py  health.py  config.py
├── ingest/
│   └── malware.py             # hive malware-* → File + Malware SDO + attacker rels
└── enrich/
    ├── ledger.py              # cache + budget + backlog + health (one component)
    ├── noisefloor.py          # Lane C
    ├── blocklists.py          # Lane A
    ├── lookup.py              # Lane B
    └── sources/
        ├── firehol.py  spamhaus.py  tor_exit.py  feodo.py  kev.py
        └── internetdb.py  circl.py  abusech.py  abuseipdb.py  vt.py
```

---

## 4. Source catalog and the tiering story

Verified live 2026-08-04 against a production fleet. "Signup" is what a **new
open-source user** must do.

### Tier 0 — no signup, works out of the box

| source | lane | what it adds | evidence |
|---|---|---|---|
| **noisefloor** (own data) | C | scanner-vs-focused classification | fleet data; see §5 |
| **FireHOL** | A | IP on curated blocklists | 4,584 CIDRs; **matched 24.5%** of real attacker IPs |
| **Spamhaus DROP/EDROP** | A | known-bad netblocks | list download |
| **Tor exit list** | A | anonymiser context | list download |
| **Feodo Tracker** | A | botnet C2 IPs | no-auth JSON |
| **CISA KEV** | A | CVE is *known-exploited* | no-auth JSON; severity multiplier |
| **Shodan InternetDB** | B | ports, hostnames, `scanner` tag, CPEs, vulns | no key; real attacker returned `tags:['scanner']`, `cpes:[ubuntu, openssh 8.9p1]` |
| **CIRCL hashlookup** | B | NSRL known-good suppression | no auth |

### Tier 1 — free, requires a free signup key

| source | lane | what it adds |
|---|---|---|
| **abuse.ch** (MalwareBazaar / URLhaus / ThreatFox) | B | **malware family attribution**, malware-distribution URLs — the real attribution tier |
| **AbuseIPDB** | B | reputation score; budget-gated to the post-noise set only |

### Tier 2 — paid, strictly optional

VirusTotal / GTI, Censys, CrowdStrike. Overlays only.

---

## 5. `noisefloor` — and the single-sensor requirement

The most valuable zero-cost enrichment is derived from **our own telemetry**:
it produces a classification the public feeds cannot know.

**It must work on a single-sensor install.** That is the open-source default,
and the predecessor's implementation classified by *how many sensors an IP
hit* — which on one sensor returns "1 sensor" for everything and makes the
feature useless for exactly the audience this release targets.

**Therefore the denominator is *surfaces touched*, not sensors hit.** An IP
that touches many distinct honeypot services / destination ports is fanning
out; one that hammers a single service is focused. This works on one sensor
and sharpens with a fleet.

Rules:

- `noise:fleet-scan` — broad fan-out. Suppresses shareability unless overridden
  by concrete malicious evidence (malware, C2, KEV-backed exploit, successful
  auth, campaign linkage).
- `targeted:*` — **only** with substantive activity (auth success, commands,
  malware). Never from a low fan-out count alone: sensor volumes are heavily
  skewed, so "hit one surface" can just mean "hit the loudest one."
- Ambiguous middle cases stay **unlabelled**. Silence is a valid answer.
- Read roll-ups from `state.db` (`attacker_activity`), **not** raw ES. The
  predecessor's equivalent burned ~3.65M redundant document reads per hour.
- Labels must be **revocable**, *or* provably non-contradictory. The
  predecessor's failure was not accretion as such — it was accreting `noise:*`
  and `targeted:*` as **mutually exclusive verdicts** while never removing
  either, so an IP ended up asserting two incompatible states. A module may
  instead define its labels as **orthogonal observations** that can all be
  true at once (an address really did fan out, and really did execute
  commands). Those need no revocation because they never conflict. What is
  forbidden is shipping mutually exclusive labels with no way to retract one.
  `enrich/noisefloor` takes the orthogonal route; see its module docstring.

---

## 6. The enrichment ledger (cache + budget + backlog + health)

Lane B owns **one SQLite ledger**. It is deliberately a single component
because the same table answers four questions.

```sql
enrichment_cache(
  source        TEXT,   -- 'internetdb' | 'circl' | 'abuseipdb' | 'malwarebazaar' | 'vt'
  obs_type      TEXT,   -- 'ipv4' | 'sha256' | 'url' | 'domain'
  value         TEXT,
  status        TEXT,   -- 'found' | 'not_found' | 'error' | 'pending'
  verdict_json  TEXT,   -- NORMALISED minimal verdict, never the raw vendor blob
  fetched_at    TEXT,
  expires_at    TEXT,
  attempt_count INTEGER,
  last_error    TEXT,
  PRIMARY KEY (source, obs_type, value)
)
```

Measured need: attacker IPs repeat at **2.19×** over a 7-day window, so a
cache removes **~54%** of lookups. Caching alone is *not* sufficient — ~16,000
new IPs/day against a 1,000/day free tier is ~6% coverage — which is why the
noise gate (which shrinks the candidate set) and the cache (which removes
repeats) are both required, and why Lane A/C ship before Lane B.

### TTL by class — the asymmetry is the point

| class | TTL | why |
|---|---|---|
| hash → malicious verdict | very long (90d+) | a malicious hash stays malicious |
| hash → known-good (NSRL) | effectively permanent | membership does not change |
| **hash → not found** | **short (1–7d)** | unknown→known transition is the whole point |
| IP reputation | moderate (7–14d) | addresses get reassigned; behaviour drifts |
| IP → not found | short | same |
| URL / domain | moderate | |
| bulk lists | n/a | no per-object call; the *list* refreshes daily |

Negative caching is mandatory (otherwise nonexistent things are re-queried
forever) but must expire faster than positive results.

### The rule that matters most

> **Cache on *confirmed*, never on *attempted*.** Only write a
> `found`/`not_found` entry when the provider returned a valid response **and**
> the OpenCTI write confirmed. Failures get `status='error'` with a short
> backoff and `attempt_count++` — never a clean verdict.

The predecessor cached a verdict when it merely *tried* to write, which masked
dropped writes for weeks. **A cache that hides failure is worse than no cache.**

Two supporting rules: store *normalised* verdicts, not raw vendor JSON (a
legacy store reached 6.4 GB for 949 samples); and the cache is **not** OpenCTI
labels — labels carry no TTL and round-trips are costly. Labels are the
*output*; the ledger is the *cache*.

### Health states

Derived from the same table:

| state | condition | HTTP |
|---|---|---|
| `healthy` | recent successful work | 200 |
| `quiet` | no eligible candidates | 200 |
| `budget-exhausted` | quota spent — **explicitly healthy and distinct** | 200 |
| **`stalled-with-work`** | `backlog > 0 AND budget > 0 AND calls == 0` | **503** |

`budget-exhausted` must be healthy and *named*, or the alarm gets ignored.
`stalled-with-work` is the condition this project has never asserted and is
exactly what two prior silent failures needed. Arm the alarm only **after the
first successful cycle**, so a fresh or genuinely quiet install stays healthy.

---

## 7. Write-back — graph, label, or prose

The predecessor's defining enrichment failure was **"reputation, not graph"**:
rich vendor data was fetched, then flattened into Note prose — neither
queryable nor usable to gate an export. Only 1 of its 7 free connectors
produced graph objects.

**Promote to graph objects:**

| source | becomes |
|---|---|
| InternetDB `hostnames[]` | Domain-Name SCO + `resolves-to` |
| InternetDB `vulns[]` | Vulnerability SDO + `has` |
| Feodo C2 hit | Malware SDO + edge |
| MalwareBazaar **exact hash** | Malware SDO + `indicator --indicates--> malware` |

**Label only, never an SDO:**

- MalwareBazaar **TLSH fuzzy match** — fuzzy attribution is precisely what got
  the predecessor's abuse.ch key banned. Exact hash promotes; fuzzy labels.
- Tor / anonymiser context, broad-list membership.

**Hard rules:**

- **Never emit floating edgeless SDOs.** The predecessor created ~1,600
  Spamhaus Indicators with no relationships — unqueryable clutter, worse than
  a label.
- **Suppression is expressed as labels, never as a lower score.** The
  publisher's cross-cycle merge keeps the *maximum* score
  (`publisher.py`, `object_max_state`), so a score can only ratchet up. Export
  gates must read labels.
- Every module **declares and owns a label namespace** (§8) and writes no
  other module's prefix.
- Enrichment may **raise** a score but must never lower one derived from our
  own first-party honeypot observation. First-party observation outranks
  third-party reputation.
- Exactly one rolling Note per object per source, containing **nothing that is
  not already a graph object or a typed field**.

---

## 8. Label namespace registry

One module owns each prefix. No module writes another's. This is an
inter-module contract; violating it produces contradictory labels on the same
object (a real predecessor failure).

| prefix | owner | meaning |
|---|---|---|
| `noise:*` | `enrich/noisefloor.py` | broad fan-out / mass-scan behaviour |
| `targeted:*` | `enrich/noisefloor.py` | substantive activity — successful auth, executed commands, or a malware drop. **Independent of fan-out:** an address can carry both `noise:*` and `targeted:*`, and 29.7% of suppressed addresses do. |
| `blocklist:*` | `enrich/blocklists.py` | membership of a named list |
| `tor:*` | `enrich/blocklists.py` | anonymiser context |
| `kev:*` | `enrich/blocklists.py` | CVE known-exploited |
| `shodan:*` | `enrich/lookup.py` (internetdb) | ports/tags/CPE context |
| `hashlookup:*` | `enrich/lookup.py` (circl) | known-good suppression |
| `abusech:*` | `enrich/lookup.py` (abusech) | family / distribution evidence |
| `abuseipdb:*` | `enrich/lookup.py` (abuseipdb) | reputation confidence |
| `vt:*` | `enrich/lookup.py` (vt) | VirusTotal verdict (optional tier) |

---

## 9. Configuration

Typed frozen dataclasses in [`config.py`](../tpot2cti/config.py), matching the
existing pattern; env vars in `.env`; opt-in via compose profiles.

> **Governing principle: the no-signup path requires zero configuration.**
> `COMPOSE_PROFILES=enrich` must work with defaults on a fresh install. Only
> Tier 1 and Tier 2 sources ever require a value.

```bash
# ── ENRICHMENT — noise floor (no signup) ──
ENRICH_NOISEFLOOR_INTERVAL=PT1H
ENRICH_NOISEFLOOR_FANOUT_SUPPRESS=3      # distinct surfaces ⇒ mass-scan

# ── ENRICHMENT — blocklists (no signup) ──
ENRICH_BLOCKLIST_SOURCES=firehol,spamhaus,tor,feodo,kev
ENRICH_BLOCKLIST_REFRESH=PT24H

# ── ENRICHMENT — per-object lookups ──
ENRICH_LOOKUP_SOURCES=internetdb,circl   # no-signup defaults
ENRICH_LOOKUP_DAILY_BUDGET=5000
ENRICH_LOOKUP_INTERVAL=PT15M

# ── Optional: free signup ──
ABUSECH_API_KEY=
ABUSEIPDB_API_KEY=

# ── Optional: paid ──
VT_API_KEY=
```

---

## 10. Deliberately not built

- **VT IP reputation** — commodity data; AbuseIPDB provides it free.
- **Per-object calls for anything a bulk list already answers.**
- **A second scoring engine** — scoring stays in CORE.
- **Paid GreyNoise** — `noisefloor` replaces it at zero cost.
- **Raw vendor-JSON storage.**
- **Multi-vendor abstraction layers** — add sources, not frameworks.
- **Any connector whose only output is a Note.**

---

## 11. Phasing

| phase | ships | signup |
|---|---|---|
| **A** | scoring-trap fixes → `noisefloor` → `blocklists` → CISA KEV | **none** |
| **B** | `lookup` lane + ledger: InternetDB, CIRCL hashlookup | **none** |
| **C** | abuse.ch (attribution), AbuseIPDB | free key |
| **D** | VirusTotal/GTI overlay | paid |

Phase A + B is the open-source enrichment story: **meaningful enrichment, no
accounts, no cost.**

### Prerequisites before Phase A

1. `stix/builder.py::_ip_score()` currently **raises** an IP's score for being
   a known scanner (`+12` on `ip_rep` matching scanner/bot/crawler) and again
   for port-sweeping (`+5`). This inflates precisely the population the noise
   ring exists to suppress, and must be reconciled first.
2. `malware` is not yet a publishable type — it must be added to
   `stix/types.py` and the publisher's entity pass, with a partitioning test,
   before any Malware SDO can be emitted.

---

## See also

- [`V1_SPEC.md`](../V1_SPEC.md) — the CORE 1.0 specification (ENRICH is post-1.0)
- [`LESSONS_LEARNED_FROM_V0.md`](LESSONS_LEARNED_FROM_V0.md) — the failure taxonomy this design encodes
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — companion-connector contract
