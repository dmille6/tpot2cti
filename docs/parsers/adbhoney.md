# ADBhoney parser — Android Debug Bridge honeypot (port 5555).

ADB on port 5555 is supposed to be a developer-only debugging interface
for plugged-in Android devices.  When it ends up exposed to the open
internet — typically by accident on a misconfigured handset or by
design on a vulnerable IoT device — it offers attackers an unauth root
shell and arbitrary file upload.  Mirai-style worms have been
exploiting this for years; the entire connection volume on port 5555
is malicious by construction.

Per V1_SPEC.md §5.14:

  T-Pot doc fields used:
    src_ip, command, data_sha256

  STIX emitted (later, by the orchestrator):
    IPv4-Addr,
    StixFile (if data captured),
    Sighting,
    AttackPattern("android-adb-abuse") via Indicator.

  Event correlation: each ADB connection is its own event.  We inherit
  the default one-event-per-session correlator.

Emission (per docs/LESSONS_LEARNED_FROM_V0.md §2):

  *All ADBhoney sessions are worth emitting.*  Port 5555 ADB connections
  are inherently malicious — there is no legitimate reason for one to
  land on an open-internet honeypot — so every event warrants the full
  STIX SDO graph.  This is the rare case where LESSONS §2's "drive-by
  probes get one Sighting only" rule does NOT apply: the probe itself is
  the substance.

  Parsers no longer gate emission.  The drive-by vs. full-graph decision
  is centralized in `_is_bare_scan()` (`tpot2cti/main.py`), and ADBhoney
  is not routed through the bare-scan drop path.

Per-session promotions to the AttackSession:

  - ``session.malware_hashes`` ← ``data_sha256`` (if present)
  - ``session.commands``       ← ``command``    (if present)
  - ``session.meta``           ← command, data_sha256, device_* fields
