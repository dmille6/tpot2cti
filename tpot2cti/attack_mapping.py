"""tpot2cti — behaviour-driven MITRE ATT&CK technique mapping.

Only two of the honeypot parsers (Suricata via rule metadata, Tanner/web via
``attack_type``) used to emit ATT&CK techniques. Yet every parser normalises
the *same* substance signals onto ``AttackSession`` — credentials, successful
auth, executed commands, dropped malware, planted SSH keys, port sweeps. This
module maps those uniform signals to ATT&CK techniques so all 32 honeypots
light up the matrix, with each mapping backed by real observed evidence
(behaviour-only — a bare connect with no activity gets no technique).

The returned techniques are emitted as AttackPattern SDOs carrying
``x_mitre_id`` (see ``STIXBuilder.build_attack_pattern``), which makes OpenCTI
MERGE them into the canonical ATT&CK technique nodes from the bundled MITRE
connector — so the native ATT&CK Navigator reflects honeypot activity and each
technique node lists the attacker IPs that exhibited it.

Pure module (no project imports beyond the dataclass type) — unit-testable and
free of circular-import risk. See docs/attack-mapping.md.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid a runtime import cycle (builder imports this module)
    from tpot2cti.parsers.base import AttackSession


#: id → canonical ATT&CK technique name. Names match the MITRE library exactly
#: so ``x_mitre_id`` + name merge cleanly with the bundled connector's nodes.
#: This is the single source of truth — the STIX builder imports it for the
#: Suricata rule-id → name lookup too.
TECHNIQUES: dict[str, str] = {
    "T1021": "Remote Services",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.004": "SSH",
    "T1046": "Network Service Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1059.004": "Unix Shell",
    "T1068": "Exploitation for Privilege Escalation",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1078": "Valid Accounts",
    "T1090": "Proxy",
    "T1095": "Non-Application Layer Protocol",
    "T1098": "Account Manipulation",
    "T1098.004": "SSH Authorized Keys",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1133": "External Remote Services",
    "T1190": "Exploit Public-Facing Application",
    "T1203": "Exploitation for Client Execution",
    "T1210": "Exploitation of Remote Services",
    "T1505": "Server Software Component",
    "T1505.003": "Web Shell",
    "T1566": "Phishing",
    "T1572": "Protocol Tunneling",
    "T1595": "Active Scanning",
    "T1595.001": "Scanning IP Blocks",
    "T1595.002": "Vulnerability Scanning",
}

#: Parsers whose ``commands`` are genuinely a Unix shell (→ T1059.004). Others
#: that carry commands (Redis, SMTP/Mailoney, ConPot/Modbus) only get the
#: generic T1059 parent — they are not unix shells.
_UNIX_SHELL_TYPES = frozenset({"Cowrie", "Adbhoney", "Beelzebub", "Router"})

#: Distinct-port threshold for treating a burst as Active Scanning (matches
#: HoneytrapParser.SUBSTANCE_PORT_THRESHOLD).
_SCAN_PORT_THRESHOLD = 3


def techniques_for_session(session: "AttackSession") -> list[tuple[str, str]]:
    """Return ``[(mitre_id, name), …]`` for the techniques the session's
    observed behaviour evidences. Behaviour-only: no signal → no technique.
    De-duplicated, order-stable.
    """
    ids: list[str] = []

    def add(tid: str) -> None:
        if tid in TECHNIQUES and tid not in ids:
            ids.append(tid)

    # Credential brute force / password guessing.
    if session.credentials_tried:
        add("T1110")
        if len(session.credentials_tried) > 1:
            add("T1110.001")
    # A working login (default/guessed creds accepted) = Valid Accounts.
    if session.auth_success:
        add("T1078")

    # Command execution.
    if session.commands:
        add("T1059")
        if session.event_type in _UNIX_SHELL_TYPES:
            add("T1059.004")

    # Tool/malware delivery.
    if session.malware_hashes or session.downloads:
        add("T1105")

    # Persistence via dropped SSH key.
    if session.planted_ssh_keys:
        add("T1098")
        add("T1098.004")

    # Port sweep across distinct destination ports = Active Scanning.
    if len(session.dst_ports) >= _SCAN_PORT_THRESHOLD:
        add("T1595")
        add("T1595.001")

    return [(tid, TECHNIQUES[tid]) for tid in ids]
