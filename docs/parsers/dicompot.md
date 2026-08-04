# Dicompot parser — DICOM medical-imaging honeypot.

Dicompot emulates a DICOM Application Entity on TCP/11112, the
standard port for medical-imaging endpoints (PACS servers, CT/MRI
modalities, viewer workstations).  Like the ICS protocols handled by
ConPot, DICOM has no legitimate reason to be touched by random
internet hosts — every probe is signal.

Per V1_SPEC.md §5.8:

  T-Pot doc fields used:
    src_ip, aet_called, aet_calling, command_type

  Event correlation:
    each ES doc is a discrete DICOM probe; default one-event-per-
    session correlator applies.

  STIX emitted per session (built downstream by the publisher):
    IPv4-Addr, AutonomousSystem, Location (via build_attacker_context),
    Indicator(ip), Sighting,
    Note with DICOM command details (C-STORE, C-FIND, ...),
    AttackPattern("medical-imaging-probe") via Indicator.

  Relationships:
    Indicator → indicates → AttackPattern.

Emission (per docs/LESSONS_LEARNED_FROM_V0.md §2):
    DICOM probes are rare enough that every one is interesting.
    Parsers no longer gate emission; the drive-by vs. full-graph
    decision lives in `_is_bare_scan()` (`tpot2cti/main.py`), and
    Dicompot sessions are not routed through the bare-scan drop path.

This parser only `parse()`s and `correlate()`s; the STIX bundle is
built by the publisher (tpot2cti/stix/builder.py) using the metadata
we populate on the session.
