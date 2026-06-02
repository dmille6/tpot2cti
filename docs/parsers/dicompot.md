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

Per docs/LESSONS_LEARNED_FROM_V0.md §2 (substance filter):
    DICOM probes are rare enough that every one is interesting.
    `has_substance()` is overridden to always return True.

This parser only `parse()`s and `correlate()`s; the STIX bundle is
built by the publisher (tpot2cti/stix/builder.py) using the metadata
we populate on the session.
