# FATT parser — passive TLS/SSH fingerprint observations.

FATT (Fingerprint All The Things) is T-Pot's passive fingerprinting
collector — it watches the traffic that hits other honeypots and
emits a separate document per observed JA3 / JA3S / HASSH / HASSHServer
fingerprint.  Because it is purely an observer, FATT doesn't have its
own sessions: it produces a burst of near-identical fingerprint events
for the same attacker IP as their TLS/SSH handshakes complete.  We
correlate those bursts into a single AttackSession using the time-
window correlator (default 300s, mirroring the V0 importer per
docs/LESSONS_LEARNED_FROM_V0.md §6).

Per V1_SPEC.md §5.20:

  T-Pot doc fields used:
    src_ip, dst_ip, dst_port,
    fatt.ja3, fatt.ja3s, fatt.hassh, fatt.hasshServer,
    fatt.tlsClient, fatt.tlsServer

  Event correlation:
    `correlate_by_window` with a 300s gap — FATT fires once per
    handshake observed, but a single attacker often produces multiple
    handshakes (retries, multi-port scans, parallel connects) in
    quick succession.  Grouping them into one AttackSession lets the
    downstream STIX builder emit one Cryptographic-Key per unique
    fingerprint per attacker, not one per redundant emission.

  Substance filter:
    Substantive iff ANY fingerprint field (ja3, ja3s, hassh,
    hasshServer) is non-empty on at least one event in the session.
    A FATT doc with all four fingerprint fields blank carries no
    information beyond what the upstream honeypot already gives us,
    so it routes to the drive-by Sighting path.

  Aggregator policy:
    We keep the FIRST non-empty value seen across the window for
    each of ja3 / ja3s / hassh / hasshServer.  FATT often re-emits
    the same fingerprint repeatedly (one doc per connection in the
    burst); the first observation is sufficient and additional ones
    would be duplicates.  The corresponding session fields
    (`session.ja3`, `session.ja3s`, `session.hassh`) are populated
    directly; `hasshServer` and the human-readable `tlsClient` /
    `tlsServer` strings live on `session.meta`.

  STIX emitted (by the orchestrator from session state):
    - IPv4-Addr (via builder.build_attacker_context)
    - Cryptographic-Key per unique fingerprint (JA3, JA3S, HASSH,
      HASSHServer) — see docs/LESSONS_LEARNED_FROM_V0.md §8.4 for
      the correct STIX type slug ("cryptographic-key", NOT
      "x-opencti-cryptographic-key")
    - Sighting on the IP Indicator
