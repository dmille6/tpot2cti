# blocklists — free bulk lists, matched locally (Lane A)

Downloads a handful of public blocklists and matches attacker IPs against them
**locally**. That costs **zero per-object API calls**, so it scales to any
number of observables — the property that makes the no-signup tier genuinely
useful rather than a crippled demo.

Every source is free and requires no signup. Verified reachable without
authentication on 2026-08-05.

## What it actually buys you

Measured against 14,715 real attacker IPs from the live fleet (2026-08-05),
and independently reproduced by a full dry run of this module:

| source | entries | matched | share |
|---|---:|---:|---:|
| FireHOL level 1 | 4,584 CIDRs | 847 | 5.8% |
| Spamhaus DROP | 1,665 CIDRs | 365 | 2.5% |
| Tor exit list | 1,401 | 65 | 0.4% |
| Feodo Tracker | 1 online | 0 | ~0% |
| **union** | | **912** | **6.2%** |

**This is a context source, not a detector.** Three things follow from the
numbers, and all three are easy to get wrong:

1. **Spamhaus DROP adds no coverage.** Every one of its 365 hits was already
   matched by FireHOL level 1 — a strict subset. It is kept for its distinct
   *attribution* ("this netblock is hijacked or wholly malicious"), not for
   reach. Do not present it as independent corroboration.
2. **Feodo Tracker has effectively wound down** — 5 entries total, 4 of them
   `status: offline`, the oldest last seen in March. It is kept because a hit
   is high value, not because it is a meaningful source.
3. **The real contribution is where it lands.** 550 of the 912 hits are on
   addresses `noisefloor` left unlabelled — for those, a blocklist is the only
   signal we have. Membership barely correlates with our own behavioural
   classification (9.6% of fan-out addresses, 7.7% of substantive ones, 5.2%
   of unlabelled ones), which is exactly the argument *for* it: independent
   evidence rather than a restatement of what we already knew.

> An earlier version of `docs/ENRICHMENT.md` claimed FireHOL matched **24.5%**.
> That was wrong by roughly 4×; the measured figure is 5.8%.

## Labels

| label | meaning |
|---|---|
| `blocklist:firehol-level1` | listed on FireHOL level 1 |
| `blocklist:spamhaus-drop` | inside a Spamhaus DROP netblock |
| `tor:exit-node` | a published Tor exit node |
| `blocklist:feodo-c2` | an **online** botnet C2 on Feodo Tracker |

A Feodo hit with a named family also promotes to a **Malware SDO plus the edge
tying it to the address** — never a floating SDO. The predecessor created
~1,600 edgeless Spamhaus Indicators: unqueryable clutter, worse than a label.

## Staleness is this lane's entire health question

Lane A's failure mode is not "the API is down" — it is **"the list is old"**.
A runner that stops refreshing keeps matching happily against a frozen list and
looks perfectly healthy while its answers rot. So:

- A source older than `ENRICH_BLOCKLIST_MAX_AGE_HOURS` (72h, two missed daily
  refreshes) is **dropped from matching**.
- If *every* source is stale or missing, the cycle **fails** and `/health` goes
  unhealthy. Refusing to match is correct, but it must never be recorded as a
  successful cycle — otherwise a runner that stopped refreshing months ago
  reads exactly like one with nothing to match.
- **Unknown age fails closed.** A missing or unparseable fetch timestamp is
  treated as stale, not as "zero hours old".

## Why the sources live in one file

`docs/ENRICHMENT.md` originally sketched `sources/firehol.py`,
`sources/spamhaus.py`, and so on. Each source differs only in a URL, a parse
mode and a label, so that layout would produce five near-identical files — the
duplication this project keeps warning about — for no isolation benefit, since
they share one fetch path and one matcher. Adding a source is one entry in the
`SOURCES` table in `tpot2cti/enrich/sources.py`.

## Configuration

| variable | default | meaning |
|---|---|---|
| `ENRICH_BLOCKLIST_SOURCES` | `firehol,spamhaus,tor,feodo` | which sources to use; an unknown name is a hard error, never a silent skip |
| `ENRICH_BLOCKLIST_REFRESH` | `PT24H` | how often to re-download |
| `ENRICH_BLOCKLIST_INTERVAL` | `PT1H` | cycle interval |
| `ENRICH_BLOCKLIST_MAX_AGE_HOURS` | `72` | refuse to match a list older than this |
| `ENRICH_BLOCKLIST_ACTIVE_WITHIN_HOURS` | `168` | how recently an IP must have been active |
| `ENRICH_BLOCKLIST_MAX_PER_CYCLE` | `2000` | sweep page size |
| `ENRICH_BLOCKLIST_STUCK_PAGE_ALERT` | `3` | failed publishes at one cursor before the wedge is named |
| `ENRICH_BLOCKLIST_FETCH_TIMEOUT` | `60` | per-source download timeout, seconds |
| `ENRICH_BLOCKLIST_STATE_DB` | `<data>/blocklists.db` | own state |

## Operational notes

- **Own state DB**, never CORE's — this module writes heartbeats and
  `cycle_log` rows, exactly what CORE's `/health` reads.
- **Shares the sweep** with `noisefloor` via `enrich/sweep.py`: same cursor,
  same "a failed read raises", same "a bad page stalls rather than skips".
  One copy, because the predecessor reimplemented its shared write path 21+
  times and each fix landed in one copy while the other twenty kept the bug.
- **Per-`(ip, source)` marks**, so an address already matched on one list can
  still earn another later.
- **Non-addresses are counted, not silently dropped.** CORE's telemetry
  contains rows whose `src_ip` is not an address — 16 in the live window, all
  obfuscated Log4Shell JNDI payloads stored by H0neytr4p. They are skipped and
  reported as `malformed`, so they never masquerade as "matched no list".
- **A failing source cannot starve the others.** The next fetch covers the
  failures *plus* anything due on its own age. Retrying only the failures
  would collapse the working set to a permanently-broken source and never
  expand back — measured at defaults with FireHOL failing permanently, every
  source was stale and every cycle failed by day 10, from one dead URL.
- **A failed source keeps its previous copy**, and keeps its old fetch
  timestamp, so it ages toward the staleness cliff and is eventually refused
  rather than answering forever from stale data. Only the failed sources are
  retried, after `min(refresh, max(interval, 300s))` rather than a full day.
- **A short parse is refused.** These feeds are plain text over HTTP, so a
  captive portal or rate-limit page parses to zero networks perfectly happily.
  Each source declares a floor; parsing below it raises rather than quietly
  un-labelling the internet.

## Not included, and why

**CISA KEV is deferred.** It keys on **CVE**, and CORE's `attacker_activity`
roll-up has no structured CVE field — only 46 incidental matches inside command
and credential text. Wiring KEV in today would either be a no-op or require
scraping CVEs out of payload strings, which is a feature in its own right (and
belongs next to Suricata signature handling), not a list download.
