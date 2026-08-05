# H0neytr4p parser — HTTP/HTTPS web application honeypot.

H0neytr4p (a.k.a. ``h0neytr4p``) emulates vulnerable web applications:
exposed config endpoints, Spring actuators, PHP shells, dot-env leaks,
log4j-style ``${jndi:...}`` triggers — the long tail of HTTP exploit
attempts.  T-Pot wires it onto port 80/443 (and assorted alternative
HTTP ports) and emits one ES document per HTTP request.

Per V1_SPEC.md §5.7:

  T-Pot doc fields used:
    src_ip,
    request.method, request.uri, request.body, request.user_agent,
    host_header

  STIX emitted (later, by the orchestrator):
    IPv4-Addr,
    URL (full URI requested),
    Domain-Name (host header),
    Sighting,
    Note with method + body if non-trivial,
    AttackPattern("web-application-attack") if request body contains
      exploit signatures.

  Event correlation: each HTTP request is its own event.  We inherit
  the default one-event-per-session correlator.

Substance filter (per docs/LESSONS_LEARNED_FROM_V0.md §2):

  Drive-by HTTP probes — Censys, Shodan, Mirai-style ``GET /`` health
  checks — are most of the volume.  A bare ``GET /`` from a scanner
  generates a flood of Sightings that V0 over-promoted to full SDO
  graphs; we now only promote a session if at least one of the
  following holds:

    - request.method is anything other than GET (POST / PUT / DELETE /
      PATCH / CONNECT all signal "the attacker is sending content")
    - request.body has more than 8 bytes
    - request.uri matches a tight list of exploit hints
      (:data:`_WEB_EXPLOIT_HINTS`)
    - request.user_agent matches a known exploit-tool UA signature

  The hint list is *deliberately tight*.  Plain ``GET /`` and
  ``GET /favicon.ico`` are noise; ``GET /.env`` and
  ``GET /actuator/env`` are substance.

Per-session promotions to the AttackSession:

  - ``session.urls``     ← reconstructed full URL from host_header + uri
  - ``session.domains``  ← host_header (FQDN form only)
  - ``session.meta``     ← request method / uri / body (truncated) /
                            user_agent / host_header / matched_hints

---

## 2026-08-04 — ES field-name audit, spoofed src_ip, Log4Shell salvage

Three defects found together while chasing 30 rows in the live state DB
whose ``src_ip`` was an obfuscated Log4Shell payload rather than an
address. All three were confirmed against live Elasticsearch, not
inferred from the spec.

### 1. Two ES schemas ship concurrently

The V1_SPEC §5.7 shape (``request.method``, ``request.uri``,
``request.body``, ``request.user_agent``, ``host_header``) **has never
existed in this hive's data**. A field-presence census over 34k docs/24h
found two flat schemas instead:

| what we want | modern (~99.6% of docs) | legacy (~0.4%: two sensors) |
|---|---|---|
| method       | `method`            | `request_method` |
| URI          | `request_uri`       | `request_uri` |
| user agent   | `http_user_agent`   | `user-agent`, `header_user-agent` |
| host header  | `http_host`         | *(absent)* |
| headers      | *(absent)*          | `header_<name>` (one field per header) |
| extras       | `sni`, `status`, `request_time`, `http_referer` | `protocol`, `trapped` |

The parser previously read the legacy names only, so on live traffic:

* `method` and `user_agent` were `None` for ~99.6% of events — the
  exploit-tool User-Agent signatures were effectively dead code;
* `host_header` was `None` for **100%** of events, because *neither*
  schema ships `host_header`/`header_host`. URL reconstruction needs
  host + URI, so `session.urls` was never populated: measured **0 URLs
  and 0 domains across all 12,860 H0neytr4p rows**, against 1,072/1,072
  for Tanner. The URL observable promised by V1_SPEC §5.7 had never
  once been emitted.

Reads are now modern-first, legacy-fallback, nested-last, with `sni` as
a final host fallback. Post-fix on 333 real live docs: method 332/333,
user_agent 332/333, host_header 297/333, 37 distinct URLs reconstructed.

**No h0neytr4p build ships a request body.** `BODY_LENGTH_THRESHOLD`
therefore never fires on real data; substance rests on the URI and
header hint lists. The body reads are kept for forks that do emit one.

### 2. `src_ip` is the X-Forwarded-For header

h0neytr4p reports the attacker-controlled `X-Forwarded-For` header **as
the client address**: `src_ip` is byte-identical to
`header_x-forwarded-for` in 33/33 documents that carry that header.
Nothing in the document preserves the real TCP peer — `t-pot_ip_ext`,
`hostname` and `host` are all the sensor's own addresses.

This is honeypot behaviour, not a field-read error on our side, and it
has two consequences:

* **Visible:** Log4Shell scanners spray their payload into every header
  including XFF, so `src_ip` arrives holding an obfuscated JNDI blob.
  These are self-evidently unusable and are now rejected and counted
  (`drop_reasons.src_ip_rejected`, visible in `/health`).
* **Quiet:** an XFF holding a *plausible* IP is indistinguishable from
  real attribution. None has been observed in the retained window, so
  the parser flags it (`meta.src_ip_from_xff`) rather than dropping it.
  If that ever starts happening, the flag is the evidence.

`state.upsert_attacker_activity` independently rejects and canonicalizes
non-address keys, and `prune_malformed_attacker_activity` cleans rows
written before the gate existed.

### 3. The payload was the intelligence

A Log4Shell probe's JNDI endpoint is live attacker infrastructure and is
worth more than the spoofable address it rode in on. It was previously
discarded entirely: the `${jndi:` hint regex greps for the literal
string, which an obfuscated payload never matches, and nothing scanned
the headers or `src_ip` for it.

`tpot2cti/log4shell.py` now resolves the `${x:y:-c}` per-character
obfuscation (all 30 live payloads decode) and recovers the endpoint.
Events that fail the source-address gate but carry a payload are routed
to `STIXBuilder.build_unattributed_payload_objects`, which emits a
**sensor-anchored** graph — URL, Domain-Name, `CVE-2021-44228`, `T1190`,
a Sighting and an explanatory Note — and deliberately emits **no**
IPv4-Addr and **no** Indicator, because asserting a source we do not
have would be fabricated attribution.

Grouping is by C2 *host*, not URL: the observed scanner encodes which
header it probed into the callback's leading label (`XFl0c-` for
X-Forwarded-For, `REl0c-` for Referer, …), so one probe yields ~12
distinct URLs sharing one zone. The zone is the durable pivot; the
variants are listed in the Note.

Runtime lookups with no default (`${sys:java.version}`) are left
literal — they are the exfil template the attacker wants the victim to
fill in, and preserving them keeps the recovered URL faithful.
