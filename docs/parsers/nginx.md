# NGINX parser — custom nginx access logs from persona HTTP fronts.

T-Pot can run a persona-specific NGINX in front of one of its HTTP
honeypots; that NGINX emits a structured access-log document per
request (`type:"NGINX"` in the T-Pot index).  Compared to a generic
web honeypot we have less semantic information per request, but the
raw access-log triple (URI, method, status, UA) is rich enough to
distinguish scan/exploit attempts from background crawling.

Per V1_SPEC.md §5.21:

  T-Pot doc fields used:
    src_ip, request_uri, request_method, status_code, user_agent

  Event correlation:
    one ES doc → one ParsedEvent → one AttackSession (default
    one-event-per-session correlator — each access-log line is its
    own event).

  Substance filter (per docs/LESSONS_LEARNED_FROM_V0.md §2):
    A request is substantive iff EITHER
      - the response status_code is 4xx or 5xx (the server rejected
        the request — typically because the attacker probed a path
        that doesn't exist, which by definition is scanning), OR
      - the request_uri matches one of `_NGINX_SCAN_SIGNALS` (well-
        known scan/exploit fingerprints like /.git/, /.env, /wp-,
        /admin/, /api/, /cgi-bin/, etc.), OR
      - the user_agent matches one of the known scanner UAs
        (sqlmap, ZmEu, Nikto, Nuclei, …).

    Plain GETs of `/` from a normal-looking UA route to the drive-by
    Sighting path — they're indistinguishable from internet
    background radiation.

  STIX emitted (by the orchestrator from session state):
    - IPv4-Addr
    - URL (when request_uri non-empty)
    - Sighting
