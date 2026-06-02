# ElasticPot parser — fake Elasticsearch HTTP API honeypot.

ElasticPot emulates an open Elasticsearch node and captures the HTTP
requests attackers send at it.  Internet background-radiation scanners
constantly poke port 9200 with a `GET /` looking for an unauthenticated
ES banner; the substantive traffic we actually care about is the
small-but-toxic subset that tries to exploit historical Elasticsearch
RCE chains — chiefly CVE-2014-3120 (Groovy dynamic scripting) and
CVE-2015-1427 (search-template Groovy sandbox bypass) — or that submits
a non-GET request with a body (a script/search payload rather than a
plain probe).

Per V1_SPEC.md §5.11:

  T-Pot doc fields used:
    src_ip, request_url, request_method, request_body

  Event correlation:
    one ES doc → one ParsedEvent → one AttackSession (default
    one-event-per-session correlator, since ElasticPot has no native
    multi-request session concept in the T-Pot index).

  STIX emitted:
    - IPv4-Addr
    - URL
    - Sighting
    - AttackPattern("api-exploitation") if body contains CVE-2014-3120
      or similar known ES exploit patterns

  Substance filter (per LESSONS_LEARNED_FROM_V0.md §2):
    A session is substantive iff
      - request_body contains a known ES exploit signature
        (currently CVE-2014-3120 + CVE-2015-1427 search-template
        script-injection patterns), OR
      - request_method != GET (any write/script request is interesting
        on a honeypot that has no real data), OR
      - the URL targets /_search and carries a non-empty body
        (search-template injection vector).
    Everything else — plain `GET /`, `GET /_cluster/health`, etc. —
    is drive-by noise and routed to the one-Sighting drive-by path.
