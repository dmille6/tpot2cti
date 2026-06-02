# Cowrie parser — SSH and Telnet honeypot sessions.

Cowrie is the richest T-Pot honeypot — high-interaction shell on
ports 22, 23, 2222.  It emits multiple event types per session
(connect, login attempt, command input, file download, disconnect)
all sharing a `session` field.  We correlate by that field and
build per-session STIX that captures the full attacker interaction.

Per the V0 parser-vs-builder separation rule ("Honeypot-specific IoC extraction belongs in the
STIX builder, not the parser"), this parser stays pure (model-only):
parse() + correlate() + has_substance() only.  The per-protocol STIX
shape lives in ``STIXBuilder.build_cowrie_session`` — see
``tpot2cti/stix/builder.py``.

Per V1_SPEC.md §5.1:

  T-Pot doc fields used:
    session, src_ip, src_port, dst_ip, dst_port, eventid,
    username, password, input, shasum/sha256, url, version,
    hassh, kex_algs, duration

  Substance filter: Cowrie sessions with no commands, no downloads,
  and no successful login are emitted as a Sighting only.  Pure
  probe-and-leave noise gets one-line representation rather than
  full SDO graph.
