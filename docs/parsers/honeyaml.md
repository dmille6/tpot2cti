# Honeyaml parser — YAML / IaC config-probe honeypot.

Honeyaml is a low-interaction HTTP honeypot whose entire purpose is
to capture attackers fishing for leaked Infrastructure-as-Code files:
`/.kube/config`, `/docker-compose.yml`, `/config.yaml`,
`/.aws/credentials`, etc.  Every request Honeyaml records is an
attempted credential / configuration leak — there is no "drive-by"
on this honeypot.

Per V1_SPEC.md §5.22:

  T-Pot doc fields used:
    src_ip, request_path, request_body

  Event correlation:
    one ES doc → one ParsedEvent → one AttackSession (default
    one-event-per-session correlator — each request is its own
    config-probe).

  Substance filter:
    Always substantive.  Honeyaml only listens for IaC config paths;
    by the time a request hits its log, the attacker has already
    declared scanning intent, so every Honeyaml session is treated as
    substantive. (Emission is gated centrally by `_is_bare_scan()` in
    the orchestrator, not per-parser.)

  STIX emitted (by the orchestrator from session state):
    - IPv4-Addr
    - Sighting
    - Note with the attempted config path and any request_body
      (truncated — see `REQUEST_BODY_CAP` below).
