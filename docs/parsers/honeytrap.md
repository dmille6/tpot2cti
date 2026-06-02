# Honeytrap parser — TCP/UDP catchall honeypot.

Honeytrap is T-Pot's default-route catchall: anything that hits a
port no other honeypot is listening on lands here.  Most of what we
see is one-packet probes from internet background radiation — a SYN,
a banner grab, an empty UDP packet — but occasionally an attacker
actually sends an exploit payload to a non-honeypotted port and that
payload is worth preserving.

Per the V0 parser-vs-builder separation rule, this parser stays pure (model-only):
parse() + has_substance() only.  The per-protocol STIX shape lives in
``STIXBuilder.build_honeytrap_probe``.

Per V1_SPEC.md §5.4:

  T-Pot doc fields used:
    src_ip, dst_port, proto, payload_hex, payload_printable,
    attack_connection (metadata)

  Event correlation: each TCP connection or UDP datagram is one event.
  We use the default one-event-per-session correlator.

  STIX emitted (by the builder):
    - IPv4-Addr (via builder.build_attacker_context)
    - Sighting (probe of port N) with payload summary in description

  Substance filter: empty-payload probes get a minimal Sighting only.
  Sessions with > 8 bytes of printable payload get the full graph with
  a Sighting description that preserves the captured bytes.
