# Shared-IoC Campaign grouping

`tpot2cti/campaigns.py`

A single scanning IP is a data point. The **same concrete artifact** turning up
from many IPs is intelligence. When ≥2 distinct attacker IPs deliver the same
malware or plant the same SSH key, that shared object is something an actor had
to put there — so we roll them into one STIX **Campaign** node. In OpenCTI you
then see one operation instead of N disconnected indicators.

## Grouping basis — shared concrete IoC only

Deliberately tight (operator decision, 2026-06-03). We do **not** build
behavioural buckets like "everyone scanning cPanel" — that's too loose
(thousands of unrelated bots share targets). A campaign forms only on a shared
**concrete** artifact:

| Artifact | Source field | Artifact key | Links to SCO |
|---|---|---|---|
| Dropped malware | `session.malware_hashes` (sha256) | `malware:<sha256>` | File |
| Planted SSH key | `session.planted_ssh_keys[].fingerprint` | `sshkey:<fp>` | Cryptographic-Key |

### Removed 2026-08-05: HASSH and JA3 are NOT campaign artifacts

A Campaign asserts coordinated activity by an **actor**. A HASSH or JA3
fingerprint identifies the SSH/TLS **library the client was built against** — it
groups software, not actors.

Measured on the live corpus: **217 of 243** generated campaigns clustered on one
of these. For **136 of the 157** JA3 campaigns the hive held *more* distinct IPs
carrying that fingerprint than the campaign claimed — median **4.5×**, worst
**117×**. One campaign asserted *"4 distinct source IPs presented the identical
TLS client fingerprint — the same client toolkit"* for a JA3 that **468** IPs
carried. The three largest HASSH campaigns were stock library defaults: libssh
0.9.x (999 IPs claimed, 1,406 in the hive), a scanner advertising every
algorithm ever defined, and stock OpenSSH 9.x.

Deleting those campaigns would not have helped — they regenerate from
`extract_artifacts()`. The defect was the SDO choice, not the data.

The fingerprints remain valuable and are still emitted as **Cryptographic-Key**
observables with `related-to` edges to the IPs that presented them, which says
*"these hosts run the same tooling"* rather than *"these hosts are one actor"*.

> **Known gap:** within a single cycle `_dedup` returns `None` for an SCO
> already emitted in that bundle, and the edge is nested inside `if ck:` — so k
> IPs sharing a fingerprint in one cycle currently produce **1** edge, not k.
> Edges accrue across cycles as IPs recur. Tracked separately.

### Known unresolved: the threshold is the wrong knob

`MIN_CAMPAIGN_MEMBERS = 2` remains, and raising it would be a mistake. The live
distribution of surviving campaigns is:

```
sha256:  {2:8, 3:12, 4:1, 9:1, 252:1, 485:1}
sshkey:  {4:1, 485:1}
```

Raising the floor to 3 would delete the eight two-IP malware pairs — the *most*
defensible entries, since a SHA-256 identifies an exact build — while leaving
the 485-IP claim untouched. The problem is artifact **popularity**, not small n:
the `mdrfckr` planted SSH key is the most copy-pasted persistence one-liner on
the internet, and its campaign asserts *"the same actor or botnet maintaining
cross-host persistence"* across 485 IPs — a stronger claim than the JA3 sentence
removed above, on a larger population.

The right lever is a popularity guard: compare a campaign's member count against
the hive-wide distinct-IP count for that artifact, and suppress or soften when
the campaign covers only a small fraction of it.

## Why it needs cross-cycle state

The second IP sharing an artifact almost always arrives in a **later cycle** than
the first, so a single cycle can't see the sharing. Every observation is logged
to the `campaign_artifacts` SQLite table (`state.py`). A campaign materialises
only once an `artifact_key` is shared by ≥ `MIN_CAMPAIGN_MEMBERS` (=2) distinct
IPs. This mirrors the `attacker_profile` cross-cycle accumulate-then-emit
pattern.

The `emitted` flag flips to 1 once a member IP's edge is published, so popular
artifacts don't re-emit every member edge every cycle — only the new IP each
time.

## STIX shape

Per materialised campaign:

- **Campaign SDO** — deterministic id `campaign--uuid5("campaign:<key>")`;
  `name`, `objective`, `first_seen`/`last_seen` (min/max across members),
  labels (`shared-ioc` + type-specific).
- **`indicator(ip) → indicates → campaign`** — one per member IP. The IP
  indicator was emitted in the cycle that IP was active; the deterministic id
  makes the edge resolve even across cycles.
- **`campaign → related-to → <artifact SCO>`** — ties the narrative to the
  concrete File / Cryptographic-Key the per-session builders already emit.

Deterministic ids mean re-emission across cycles merges into the same Campaign
node — the wave accumulates over time under one node.

## Pipeline wiring (`main.run_cycle`)

1. Per session: `campaigns.record_session_artifacts(state, session)` logs the
   session's artifacts and returns the touched keys (collected into
   `campaign_keys`).
2. After the build loop: `campaigns.emit_campaigns(state, builder, campaign_keys)`
   materialises/extends campaigns for any key that crossed the threshold this
   cycle, appending the SDO + edges to the bundle.

Both are defensive — they never raise into the cycle loop.

## Tuning

- `MIN_CAMPAIGN_MEMBERS` (campaigns.py) — distinct-IP floor for a campaign.
- `prune_campaign_artifacts(cutoff_days=180)` (state.py) — ledger retention;
  generous so a long-dormant campaign can still re-attribute a returning IP.
