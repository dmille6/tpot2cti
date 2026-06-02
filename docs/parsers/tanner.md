# Tanner parser — SNARE/TANNER web-application honeypot.

SNARE serves cloned web pages and forwards each HTTP request to
TANNER, which classifies the request and writes a verdict into
Elasticsearch with an `attack_type` field: `sqli`, `rfi`, `lfi`,
`xss`, `cmd_exec`, `php_object_injection`, `crlf`, `xxe`, `template`,
or `unknown` when nothing fires.  Unlike Suricata (which alerts on
network signatures), TANNER's verdict is itself an HTTP-application
classification, so we map each attack_type directly onto a MITRE
ATT&CK technique.

Per V1_SPEC.md §5.17:

  T-Pot doc fields used:
    src_ip, url, attack_type (sqli, rfi, xss, etc.)

  Event correlation:
    one ES doc → one ParsedEvent → one AttackSession (default
    one-event-per-session correlator).  TANNER writes one verdict per
    HTTP request; there is no native cross-request session to merge.

  STIX emitted:
    - IPv4-Addr
    - URL
    - Sighting
    - AttackPattern matching attack_type (e.g. T1190 for sqli)

  Substance filter (per LESSONS_LEARNED_FROM_V0.md §2):
    A session is substantive iff `attack_type` is set to anything other
    than ``"unknown"`` or the empty string.  Mass scanners hitting `/`
    on a SNARE clone produce `attack_type: "unknown"` verdicts and are
    pure drive-by; classified attacks (sqli, rfi, lfi, xss, cmd_exec,
    php_object_injection, etc.) are substance.
