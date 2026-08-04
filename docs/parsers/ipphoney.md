# Ipphoney parser — Internet Printing Protocol (IPP) honeypot.

IppHoney emulates an IPP server (TCP/631) — the protocol CUPS and
modern network printers use.  Most internet-exposed printers have
been the subject of public defacement and PII-leak incidents over
the years, so any IPP probe from the open internet is worth a full
STIX bundle even though the probe traffic itself is small.

Per V1_SPEC.md §5.15:

  T-Pot doc fields used:
    src_ip, request_attributes

  Event correlation:
    each ES doc is a discrete IPP request; default one-event-per-
    session correlator applies.

  STIX emitted per session (built downstream by the publisher):
    IPv4-Addr, AutonomousSystem, Location (via build_attacker_context),
    Indicator(ip), Sighting.
    (No Note SDO is mandated by V1_SPEC §5.15, but the publisher may
     choose to emit one when request_attributes is interesting — we
     mirror the attributes onto session.meta to make that possible
     without parser changes.)

Emission (per docs/LESSONS_LEARNED_FROM_V0.md §2):
    IPP probes are rare enough that every one is worth recording.
    Parsers no longer gate emission; the drive-by vs. full-graph
    decision lives in `_is_bare_scan()` (`tpot2cti/main.py`), and
    IPPhoney sessions are not routed through the bare-scan drop path.

This parser only `parse()`s and `correlate()`s; the STIX bundle is
built by the publisher (tpot2cti/stix/builder.py) using the metadata
we populate on the session.
