# ConPot parser — ICS/SCADA protocol honeypot.

ConPot emulates a handful of industrial-control protocols (Modbus,
S7comm, IEC-60870-5-104, IPMI, etc.).  Any probe against these
protocols on the open internet is, by itself, interesting — there is
no legitimate reason for a stranger to be speaking Modbus to a random
IP on TCP/502 — so every ConPot document we receive becomes a
substantive AttackSession.  No drive-by filter applies.

Per V1_SPEC.md §5.6:

  T-Pot doc fields used:
    src_ip, dst_port, protocol (modbus / s7comm / iec104 / ipmi / ...),
    request (varies by protocol — function code, register read blob,
    raw application-layer bytes, etc.)

  Event correlation:
    each ES doc is a discrete probe.  We use the default
    one-event-per-session correlator (BaseParser.correlate).

  STIX emitted per session (built downstream by the publisher):
    IPv4-Addr, AutonomousSystem, Location (via build_attacker_context),
    Indicator(ip), Sighting,
    Note with the protocol-specific request details,
    AttackPattern("industrial-protocol-recon") via Indicator.

  Relationships:
    Indicator → indicates → AttackPattern.

Emission (per docs/LESSONS_LEARNED_FROM_V0.md §2):
    "Drive-by probes get one Sighting; substantive sessions get the
     full SDO graph."  For ConPot every probe is worth emitting —
     these protocols are so rare on the open internet that even an
     empty connection has signal worth a Note and an ATT&CK link.
     Parsers no longer gate emission; the drive-by vs. full-graph
     decision is centralized in `_is_bare_scan()` (`tpot2cti/main.py`),
     and ConPot is not routed through the bare-scan drop path.

This parser only `parse()`s and supplies session metadata; the publisher
reaches into `session.meta` / `session.commands` / `events[0].meta` to
construct the
STIX bundle.  We do NOT call STIXBuilder methods here — that lives in
the publisher layer (see tpot2cti/stix/builder.py).
