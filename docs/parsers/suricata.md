# Suricata parser — network IDS alerts.

Suricata is T-Pot's network IDS — it inspects every packet against a
big rule corpus (ET Open + community rules) and emits an alert
document for each rule that fires.  Unlike Cowrie, there is no
multi-event "session" to correlate: each alert is the discrete unit
of substance.  We map one ES doc → one ParsedEvent → one AttackSession,
and every session is substantive (the alert itself is the signal).

Per the V0 parser-vs-builder separation rule, this parser stays pure (model-only):
parse() + correlate() only.  The per-protocol STIX
shape — AttackPattern selection, Vulnerability emission, Domain-Name
resolves-to relationships — lives in
``STIXBuilder.build_suricata_alert``.

Per V1_SPEC.md §5.2:

  T-Pot doc fields used:
    src_ip, dest_ip, src_port, dest_port, proto,
    alert.signature, alert.signature_id, alert.category, alert.severity,
    alert.metadata.mitre_*, flow_id, hostname, http.*, tls.*

  Event correlation:
    each alert is a discrete event — we do NOT group by flow_id.
    Multiple alerts on the same flow each become their own Sighting.

  STIX emitted per alert (by the builder):
    IPv4-Addr, Location, AutonomousSystem (via build_attacker_context)
    Indicator (IP-based), Sighting,
    Domain-Name (if TLS SNI or HTTP host present),
    URL (if http.url present),
    AttackPattern (from alert.metadata.mitre_technique_id),
    Vulnerability (if a CVE id appears in the signature name).

## Alert-only query scope (2026-08-05)

Suricata is ~60% of everything CORE reads, and ~89% of its documents carry no
`alert` object at all — they are `flow`, `http`, `tls`, `dns`, `ssh` records.
The parser's first statement is:

```python
alert = doc.get("alert")
if not isinstance(alert, dict):
    return None
```

so those documents are **provably never parsed into anything** today. CORE was
fetching them, decoding them and discarding them: measured at **1,816,522 of
3,399,134 documents per day — 53.4% of all read volume.**

`TPOT2CTI_SURICATA_ALERT_ONLY=1` (default) excludes them in the Elasticsearch
query. Verified against live data: **zero alert-bearing Suricata documents were
lost** — 217,748 before the filter and 217,748 after.

### This is a scope decision, not a verdict on the data

Non-alert Suricata records are plausible future intelligence. Its `tls` records
carry JA3 fingerprints measured to have **zero overlap** with FATT's, and
`fileinfo`, `http` and `dns` are candidate enrichment sources. If the parser is
widened to use any of them, **this filter must widen in the same change** —
`tests/test_suricata_alert_only_query.py` asserts the equivalence and fails the
moment the parser starts extracting value from a document the query excludes.

### Why a query-side filter is otherwise dangerous, and what makes this one safe

A query-side exclusion removes documents *before* any parser or counter sees
them — data that vanishes with nothing to show it existed, which is this
project's defining failure mode. Two things guard it:

1. **It is counted.** One extra count query per cycle establishes what the
   cycle would have read, and the difference is reported as `query_excluded` in
   the cycle summary and persisted to state. The invariant is
   `events_read + query_excluded == raw_count_after_ignore_types`.
2. **`exists` is not `isinstance(dict)`.** Elasticsearch can only cheaply test
   whether `alert` is present, while the parser requires it to be a dict. A
   document with a *malformed* `alert` is therefore **not** excluded — it still
   arrives and is still counted as parser `unparsed`, which is correct: that
   case must stay visible.

## `unparsed` is attributed by source

`unparsed` ran at ~172,000 events per cycle as a single opaque pile. A parser
that silently broke — because a honeypot changed its log format — would have
been invisible inside it. It is now broken down by sensor `type`, with Suricata
split further by `event_type` since it multiplexes many record kinds under one
type. Never by signature, which is unbounded cardinality.

Reported as `unparsed_by_source` in the cycle summary and persisted to
`last_cycle_unparsed_by_source`.
