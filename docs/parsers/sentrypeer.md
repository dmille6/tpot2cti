# SentryPeer parser — SIP / VoIP honeypot.

SentryPeer impersonates a SIP server and records the REGISTER / INVITE /
OPTIONS traffic that arrives from the open internet.  The interesting
signal is who is probing the SIP port (5060 udp/tcp), what SIP method
they're using, and — for INVITEs — the dialed number, which is a strong
toll-fraud indicator when it looks international.

Per V1_SPEC.md §5.19:

  T-Pot doc fields used:
    src_ip, sip_method, called_number, caller

  Event correlation:
    each ES doc is a discrete SIP transaction; default one-event-per-
    session correlator applies.

  STIX emitted per session (built downstream by the publisher):
    IPv4-Addr, AutonomousSystem, Location (via build_attacker_context),
    Indicator(ip), Sighting,
    Note with the SIP method + dialed number.

Per docs/LESSONS_LEARNED_FROM_V0.md §2 (substance filter):
    Internet-exposed SIP traffic from strangers is by definition
    anomalous — every probe is signal.  `has_substance()` always
    returns True.

This parser only `parse()`s and `correlate()`s; the STIX bundle is
built by the publisher (tpot2cti/stix/builder.py) using the metadata
we populate on the session.
