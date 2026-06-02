# CiscoASA parser — Cisco ASA emulator (CVE-2018-0101 and friends).

The Cisco ASA honeypot listens on the WebVPN/AnyConnect port (443) and
records the crafted XML payloads attackers send hunting for known
SSL-VPN vulnerabilities — most famously CVE-2018-0101 (a SOAP/XML
double-free in the WebVPN endpoint that yields unauthenticated RCE
against ASA software 9.x).  Because attackers don't probe a fake ASA
casually — internet background-radiation scanners are mostly looking
at much lower-hanging fruit on port 443 — every event captured here
is meaningful and substantive.  We do not apply a substance filter:
each probe gets the full STIX graph downstream.

Per V1_SPEC.md §5.13:

  T-Pot doc fields used:
    src_ip, payload

  Event correlation:
    one ES doc → one ParsedEvent → one AttackSession (the default
    one-event-per-session correlator; each TLS connection carrying a
    crafted payload is its own discrete attack record).

  Substance filter:
    Always substantive — every probe of a Cisco ASA emulator is
    worth recording (port 443 with crafted payload).

CVE-2018-0101 detection (per V1_SPEC.md §5.13):
    The published exploit POSTs a SOAP envelope containing a
    `<host>` element and a `<key>` element to the WebVPN endpoint;
    the malformed XML triggers the double-free.  We match
    conservatively on the conjunction of three substrings:
    `<host>`, `<key>`, and `webvpn` (case-insensitive).  We also
    accept payloads that begin with `tcp_test` — a fingerprint of one
    publicly-circulated PoC tool's connectivity probe.  When matched,
    we stash `matched_cve = "CVE-2018-0101"` in event.meta; otherwise
    we leave the field unset (downstream emits a generic
    AttackPattern instead of a CVE-tagged one).
