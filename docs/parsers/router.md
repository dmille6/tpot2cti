# Router parser — honeypot-router (Telnet console) emulator.

The "Router" honeypot emulates the Telnet management console of a
consumer-grade home router (Linksys / TP-Link / Mikrotik clones —
the same gear Mirai-class botnets target on port 23).  Attackers
authenticate (usually with default creds out of a worm's word-list)
and then run commands against the fake CLI.  We capture those
commands and treat any session that ran one or more as substantive.

Per V1_SPEC.md §5.23:

  T-Pot doc fields used:
    src_ip, session_id (when present), commands, dst_port

  Event correlation:
    Prefer `correlate_by_session_id` when the router emits a
    `session` / `session_id` field; fall back to
    `correlate_by_window` (300s) for events that lack one.  The
    fallback mirrors the V0 importer's max_gap_seconds: 300 per
    docs/LESSONS_LEARNED_FROM_V0.md §6.

  Substance filter:
    Substantive iff the session ran at least one command.  V1_SPEC
    §5.23 literally says "Process(joined commands) if any commands
    run"; the inverse — no commands — is a pure connect/auth probe
    and routes to the drive-by Sighting path.

  STIX emitted (by the orchestrator from session state):
    - IPv4-Addr (via builder.build_attacker_context)
    - Sighting
    - Process(joined commands) if `session.commands` is non-empty.

Notes on the `type` registration:
  V1_SPEC §5.23 phrases the T-Pot type as `"Router" or similar`,
  acknowledging that T-Pot has shipped the router honeypot under
  different type names across versions ("Router", "Routerpot", or
  a custom logstash mapping).  We register this parser as "Router"
  — the most common name and the spec's primary form.  If the
  installed T-Pot uses a different exact type string, the fallback
  parser (§5.24) catches it and we never silently drop the doc.
