# Medpot — HL7 medical-messaging honeypot

Medpot emulates a Health Level 7 (HL7) v2 messaging endpoint — the MLLP-framed
text protocol that hospital information systems use to exchange ADT
(admit/discharge/transfer), ORM (order), ORU (result) and similar clinical
messages. Internet-exposed HL7 endpoints are not supposed to exist; every probe
is worth recording in full.

**T-Pot doc fields used:** `src_ip`, `dst_port`, `msg_type`.

**Event correlation:** each ES doc is a discrete HL7 message; the default
one-event-per-session correlator applies. The HL7 message type (`ADT^A01`,
`ORM^O01`, …) is mirrored onto `session.meta["msg_type"]` so the builder
doesn't have to peek into `events[0].meta`. Some Medpot builds emit just the
family (`ADT`) with no trigger; we preserve whatever the doc carries.

**STIX emitted per session** (built downstream by the publisher): IPv4-Addr,
AutonomousSystem, Location (via `build_attacker_context`), Indicator(ip),
Sighting, and a Note with the HL7 message type.

**Substance:** `has_substance()` always returns `True` — HL7 traffic from
random internet hosts is anomalous by definition, so each Medpot doc warrants
the full STIX graph (V1_SPEC §5.9).

**Default port:** 2575 (conventional HL7 MLLP listener).
