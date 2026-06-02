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
