# Suricata parser — network IDS alerts.

Suricata is T-Pot's network IDS — it inspects every packet against a
big rule corpus (ET Open + community rules) and emits an alert
document for each rule that fires.  Unlike Cowrie, there is no
multi-event "session" to correlate: each alert is the discrete unit
of substance.  We map one ES doc → one ParsedEvent → one AttackSession,
and every session is substantive (the alert itself is the signal).

Per the V0 parser-vs-builder separation rule, this parser stays pure (model-only):
parse() + correlate() + has_substance() only.  The per-protocol STIX
shape — AttackPattern selection, Vulnerability emission, Domain-Name
resolves-to relationships — lives in
``STIXBuilder.build_suricata_alert``.

Per V1_SPEC.md §5.2:

  T-Pot doc fields used:
    src_ip, dest_ip, src_port, dest_port, proto,
    alert.signature, alert.signature_id, alert.category, alert.severity,
    alert.metadata.mitre_*, flow_id, hostname, http.*, tls.*

  Event correlation:
    each alert is a discrete event — we do NOT group by flow_id.
    Multiple alerts on the same flow each become their own Sighting.

  STIX emitted per alert (by the builder):
    IPv4-Addr, Location, AutonomousSystem (via build_attacker_context)
    Indicator (IP-based), Sighting,
    Domain-Name (if TLS SNI or HTTP host present),
    URL (if http.url present),
    AttackPattern (from alert.metadata.mitre_technique_id),
    Vulnerability (if a CVE id appears in the signature name).
