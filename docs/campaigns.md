# Shared-IoC Campaign grouping

`tpot2cti/campaigns.py`

A single scanning IP is a data point. The **same concrete artifact** turning up
from many IPs is intelligence. When ≥2 distinct attacker IPs deliver the same
malware, plant the same SSH key, or present the same client fingerprint, they're
almost certainly the same actor or toolkit — so we roll them into one STIX
**Campaign** node. In OpenCTI you then see one coordinated operation instead of
N disconnected indicators.

## Grouping basis — shared concrete IoC only

Deliberately tight (operator decision, 2026-06-03). We do **not** build
behavioural buckets like "everyone scanning cPanel" — that's too loose
(thousands of unrelated bots share targets). A campaign forms only on a shared
**concrete** artifact:

| Artifact | Source field | Artifact key | Links to SCO |
|---|---|---|---|
| Dropped malware | `session.malware_hashes` (sha256) | `malware:<sha256>` | File |
| Planted SSH key | `session.planted_ssh_keys[].fingerprint` | `sshkey:<fp>` | Cryptographic-Key |
| SSH client fingerprint | `session.hassh` | `hassh:<hash>` | Cryptographic-Key |
| TLS client fingerprint | `session.ja3` | `ja3:<hash>` | Cryptographic-Key |

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
