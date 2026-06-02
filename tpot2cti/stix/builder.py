"""tpot2cti — STIX 2.1 object builder.

See docs/stix/builder.md for design notes.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from tpot2cti.config import Config
from tpot2cti.parsers.base import AttackSession, ParsedEvent
from tpot2cti.stix.rendering import (
    render_cowrie_session_note_body,
    render_cowrie_sighting_description,
    render_fallback_no_ip_note_body,
    render_fallback_sighting_description,
    render_honeytrap_sighting_description,
)
from tpot2cti.stix.external_refs import (
    for_autonomous_system as _refs_for_as,
    for_domain as _refs_for_domain,
    for_file_sha256 as _refs_for_file,
    for_ipv4 as _refs_for_ipv4,
    for_url as _refs_for_url,
)
from tpot2cti.stix_ids import (
    generate_attack_pattern_id,
    generate_autonomous_system_id,
    generate_city_location_id,
    generate_country_location_id,
    generate_cryptographic_key_id,
    generate_daily_creds_note_id,
    generate_domain_id,
    generate_file_id,
    generate_file_indicator_id,
    generate_identity_id,
    generate_infrastructure_id_for_sensor,
    generate_ip_indicator_id,
    generate_ipv4_id,
    generate_marking_definition_id,
    generate_process_id,
    generate_relationship_id,
    generate_sensor_id,
    generate_session_note_id,
    generate_sighting_id,
    generate_url_id,
    generate_vulnerability_id,
    sensor_infra_name,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Note bodies are capped per LESSONS §13 to keep bundles under
# OpenCTI's ~1 MB worker limit.  64 KB is generous for any reasonable
# session summary.
MAX_NOTE_BODY_BYTES = 64 * 1024

# Process command_line cap (matches PoC convention)
MAX_COMMANDS_PER_PROCESS = 50

# Simple IPv4 / IPv6 sanity regexes (we accept what logstash gave us,
# but reject obviously malformed strings before building observables).
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# ---------------------------------------------------------------------------
# Suricata MITRE technique allowlist
# ---------------------------------------------------------------------------
# A conservative, expandable catalogue of MITRE technique ids we recognize.
# Anything outside this set is logged at DEBUG and skipped rather than
# emitted as a noisy / unverified AttackPattern in build_suricata_alert.
# Extend as we observe new ids in the wild.
_KNOWN_MITRE_TECHNIQUES: dict[str, str] = {
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


# ---------------------------------------------------------------------------
# Parser-aware enrichment vocabulary (port of PoC's `source_labels` pattern
# from tsec-tpot-connectors/tsec-tpot-hp-connector/src/stix/
# observables.py + indicators.py).
#
# Every observable/indicator emitted on behalf of a session gets:
#   - 'honeypot' (always)
#   - the parser's slug (e.g. 'cowrie', 'suricata')
#   - a protocol-family slug (e.g. 'ssh-telnet', 'network-ids')
#
# Analyst impact: Indicator/Observable "Labels" column in OpenCTI shows
# WHICH honeypot caught this attacker, enabling filter-by-source queries
# without needing custom dashboards.
# ---------------------------------------------------------------------------

#: Maps each parser's type_name (== event_type on AttackSession) to a
#: tuple of (parser_slug, protocol_family_slug). Add a row whenever a
#: new parser is added; missing entries fall back to the parser name
#: lowercased.
_PARSER_LABEL_VOCAB: dict[str, tuple[str, str]] = {
    "Cowrie":        ("cowrie",        "ssh-telnet"),
    "Suricata":      ("suricata",      "network-ids"),
    "Honeytrap":     ("honeytrap",     "tcp-catchall"),
    "Dionaea":       ("dionaea",       "malware-capture"),
    "Heralding":     ("heralding",     "credential-capture"),
    "Mailoney":      ("mailoney",      "smtp"),
    "ConPot":        ("conpot",        "ics-scada"),
    "Dicompot":      ("dicompot",      "dicom-medical"),
    "Medpot":        ("medpot",        "hl7-medical"),
    "ElasticPot":    ("elasticpot",    "elasticsearch"),
    "Redishoneypot": ("redishoneypot", "redis"),
    "Ciscoasa":      ("ciscoasa",      "cisco-asa"),
    "Adbhoney":      ("adbhoney",      "android-adb"),
    "Ipphoney":      ("ipphoney",      "ipp-printer"),
    "Miniprint":     ("miniprint",     "printer"),
    "Tanner":        ("tanner",        "web-app"),
    "Wordpot":       ("wordpot",       "wordpress"),
    "Sentrypeer":    ("sentrypeer",    "sip-voip"),
    "Fatt":          ("fatt",          "tls-fingerprint"),
    "NGINX":         ("nginx",         "web"),
    "Honeyaml":      ("honeyaml",      "iac-config"),
    "Router":        ("router",        "telnet"),
    "H0neytr4p":     ("h0neytr4p",     "web-app"),
    "Beelzebub":     ("beelzebub",     "ssh-llm"),
    "Galah":         ("galah",         "web-llm"),
    # Galah internal-type aliases — see galah.py for the reason these
    # exist. Same labels as "Galah" because event.event_type is set to
    # "Galah" inside parse(); these entries only exist to satisfy the
    # parser-registry parity check.
    "contentGenerationError": ("galah", "web-llm"),
    "emptyLLMResponse":       ("galah", "web-llm"),
    "failedResponse":         ("galah", "web-llm"),
    "successfulResponse":     ("galah", "web-llm"),
    "cacheHit":               ("galah", "web-llm"),
    "__fallback__":  ("fallback",      "unknown-type"),
}


def parser_labels_for(event_type: Optional[str]) -> list[str]:
    """Return base labels [`honeypot`, <parser>, <protocol_family>] for a
    given parser type_name. Unknown parsers fall back to the type name
    lowercased so we never have an unlabelled object."""
    if not event_type:
        return ["honeypot"]
    pair = _PARSER_LABEL_VOCAB.get(event_type)
    if pair is None:
        return ["honeypot", event_type.lower()]
    return ["honeypot", pair[0], pair[1]]


#: Indicator name templates. {ip} and {n} are substituted; {n} is the
#: session count for IP indicators. Missing entries fall back to a
#: generic template.
_INDICATOR_NAME_TEMPLATES: dict[str, str] = {
    # Coverage MUST match _PARSER_LABEL_VOCAB. The 2026-05-22 spot-check
    # found 40 "fallback" indicators that were actually CiscoASA / FATT /
    # SentryPeer / IppHoney / Honeyaml / Dicompot / Miniprint emissions
    # falling through to the generic "Honeypot Attacker" name because
    # they had no template here. Keep this dict in sync with vocab.
    "Cowrie":        "Cowrie SSH/Telnet Attack - {ip} ({n} session{s})",
    "Suricata":      "Suricata Alert - {ip} ({n} alert{s})",
    "Honeytrap":     "Honeytrap Probe - {ip} ({n} probe{s})",
    "Dionaea":       "Dionaea Malware Drop - {ip} ({n} drop{s})",
    "Heralding":     "Heralding Credential Attack - {ip} ({n} session{s})",
    "Mailoney":      "Mailoney SMTP Abuse - {ip} ({n} session{s})",
    "ConPot":        "ConPot ICS Probe - {ip} ({n} probe{s})",
    "Dicompot":      "Dicompot DICOM Probe - {ip} ({n} probe{s})",
    "Medpot":        "Medpot HL7 Probe - {ip} ({n} probe{s})",
    "ElasticPot":    "ElasticPot ES API Abuse - {ip} ({n} session{s})",
    "Redishoneypot": "RedisHoneypot Probe - {ip} ({n} session{s})",
    "Ciscoasa":      "CiscoASA Probe - {ip} ({n} probe{s})",
    "Adbhoney":      "ADBhoney Android Debug Bridge Abuse - {ip} ({n} session{s})",
    "Ipphoney":      "IppHoney Printer Probe - {ip} ({n} probe{s})",
    "Miniprint":     "Miniprint Printer Probe - {ip} ({n} probe{s})",
    "Tanner":        "Tanner Web Attack - {ip} ({n} session{s})",
    "Wordpot":       "Wordpot WordPress Probe - {ip} ({n} probe{s})",
    "Sentrypeer":    "SentryPeer SIP/VoIP Abuse - {ip} ({n} session{s})",
    "Fatt":          "FATT Fingerprint Observation - {ip} ({n} burst{s})",
    "NGINX":         "NGINX Web Probe - {ip} ({n} session{s})",
    "Honeyaml":      "Honeyaml IaC Config Probe - {ip} ({n} probe{s})",
    "Router":        "Router Telnet Abuse - {ip} ({n} session{s})",
    "H0neytr4p":     "H0neytr4p Web Probe - {ip} ({n} probe{s})",
    "Beelzebub":     "Beelzebub LLM SSH Session - {ip} ({n} session{s})",
    "Galah":         "Galah LLM Web Probe - {ip} ({n} probe{s})",
    # Galah internal-type aliases — see galah.py.
    "contentGenerationError": "Galah LLM Web Probe - {ip} ({n} probe{s})",
    "emptyLLMResponse":       "Galah LLM Web Probe - {ip} ({n} probe{s})",
    "failedResponse":         "Galah LLM Web Probe - {ip} ({n} probe{s})",
    "successfulResponse":     "Galah LLM Web Probe - {ip} ({n} probe{s})",
    "cacheHit":               "Galah LLM Web Probe - {ip} ({n} probe{s})",
    "__fallback__":  "Honeypot Activity (unknown type) - {ip} ({n} event{s})",
}


def _format_indicator_name(event_type: Optional[str], ip: str, n: int) -> str:
    tmpl = _INDICATOR_NAME_TEMPLATES.get(
        event_type or "",
        "Honeypot Attacker - {ip} ({n} event{s})"
    )
    return tmpl.format(ip=ip, n=n, s="s" if n != 1 else "")


# ---------------------------------------------------------------------------
# Scoring (lightweight; PoC's tsec_scoring.py is enrichment-owned, we own it
# directly since we don't ship enrichment connectors).
# ---------------------------------------------------------------------------

#: Default baseline score for a freshly-observed honeypot attacker IP.
#: PoC convention; tuned to leave headroom for enrichment to push up or
#: pull down. We don't have enrichment so this is the actual score
#: analysts see — picked at the middle of the 0-100 range to read as
#: "we know they probed but no enrichment confirms classification."
BASELINE_INDICATOR_SCORE = 50


def _signal_score(session: Optional[AttackSession]) -> int:
    """Compute a STIX score for an IP indicator from the session's
    substance signals. Mirrors PoC `tsec_scoring.LABEL_WEIGHTS` for the
    honeypot-side signals only (we have no enrichment labels).

    Returns a score in [10, 100]. Substantive sessions score higher than
    drive-bys. Single-shot probes from unknown IPs land at the baseline.
    """
    if session is None:
        return BASELINE_INDICATOR_SCORE
    score = BASELINE_INDICATOR_SCORE
    if session.auth_success:
        score += 30
    if session.commands:
        score += 25
    if session.malware_hashes:
        score += 35
    if session.credentials_tried:
        # +5 per attempt up to a cap (mirrors PoC's auth:failed weight
        # applied per-attempt with a small ceiling so a single brute-force
        # session can't max the score on its own).
        score += min(15, len(session.credentials_tried) * 5)
    # Cap to [10, 100].
    return max(10, min(100, score))


#: How long an Indicator stays "valid_from" → "valid_until" before
#: OpenCTI considers it stale. 60 days matches the PoC default; can be
#: overridden via config when we wire a knob.
DEFAULT_INDICATOR_VALIDITY_DAYS = 60


# ---------------------------------------------------------------------------
# STIXBuilder
# ---------------------------------------------------------------------------

class STIXBuilder:
    """Build STIX 2.1 objects for a single cycle's bundle.

    Per V1_SPEC.md §4 — every emitted object is stamped with
    `created_by_ref`, `object_marking_refs`, and a sensible `confidence`.
    Per-bundle dedup caches prevent emitting the same foundation
    object twice within one bundle (OpenCTI deduplicates server-side
    via standard_id anyway; this just trims bundle size).
    """

    def __init__(self, config: Config, sensor_dicts: Optional[list[dict]] = None):
        """Construct a per-bundle builder.

        `sensor_dicts` is the list of sensor configs (currently unused for
        v1.0 — sensor Identity is derived from the event's hostname — but
        plumbed for future use when multi-sensor metadata enrichment
        lands).
        """
        self.config = config
        self.sensor_dicts = sensor_dicts or []
        self._now_iso = datetime.now(timezone.utc).isoformat()

        # Stable IDs for the operator + TLP marking — referenced everywhere
        self.operator_identity_id = generate_identity_id(
            config.operator.org_name, "organization"
        )
        self.tlp_marking_id = generate_marking_definition_id(config.operator.default_tlp)

        # Per-bundle dedup caches
        self._emitted_ids: set[str] = set()

    # ──────────────────────────────────────────────────────────────────
    # Object stamping (created_by_ref + markings + confidence + timestamps)
    # ──────────────────────────────────────────────────────────────────

    def _stamp(self, obj: dict, *, add_confidence: bool = True) -> dict:
        """Add the common provenance/marking/timestamp fields.

        Idempotent — safe to call on an object that already has these
        fields (we don't overwrite existing values).
        """
        obj.setdefault("spec_version", "2.1")
        obj.setdefault("created", self._now_iso)
        obj.setdefault("modified", self._now_iso)
        obj.setdefault("created_by_ref", self.operator_identity_id)
        obj.setdefault("object_marking_refs", [self.tlp_marking_id])
        if add_confidence:
            obj.setdefault("confidence", self.config.operator.default_confidence)
        return obj

    def _dedup(self, obj: dict) -> Optional[dict]:
        """Return obj if its id hasn't been emitted in this bundle, else None.

        Foundation objects (operator identity, TLP marking) are emitted
        once per bundle; per-session entities (IPv4-Addr, Process, etc.)
        also dedupe naturally because deterministic IDs collapse them.
        """
        oid = obj.get("id")
        if not oid:
            return obj  # let the publisher's validator complain later
        if oid in self._emitted_ids:
            return None
        self._emitted_ids.add(oid)
        return obj

    # ──────────────────────────────────────────────────────────────────
    # Foundation objects
    # ──────────────────────────────────────────────────────────────────

    def build_operator_identity(self) -> dict:
        obj = {
            "type": "identity",
            "id": self.operator_identity_id,
            "name": self.config.operator.org_name,
            "identity_class": "organization",
            "description": "tpot2cti operator — emits all objects in this bundle.",
        }
        return self._stamp(obj, add_confidence=False)

    def build_tlp_marking(self) -> dict:
        """STIX 2.1 standard TLP marking-definition.

        We use the deterministic id from stix_ids.generate_marking_definition_id
        which maps to STIX's published TLP marking IDs (those are the canonical
        statics the rest of the threat-intel ecosystem references).
        """
        tlp = self.config.operator.default_tlp
        obj = {
            "type": "marking-definition",
            "id": self.tlp_marking_id,
            "definition_type": "tlp",
            "definition": {"tlp": tlp.lower().replace("+strict", "")},
            "name": f"TLP:{tlp}",
        }
        # Marking definitions don't carry created_by_ref or object_marking_refs
        # per STIX 2.1 — strip them after _stamp() would have added them.
        # Cleaner: just don't call _stamp.
        obj.setdefault("spec_version", "2.1")
        obj.setdefault("created", self._now_iso)
        return obj

    def build_sensor_identity(self, sensor_hostname: str) -> Optional[dict]:
        if not sensor_hostname:
            return None
        sid = generate_sensor_id(sensor_hostname)
        obj = {
            "type": "identity",
            "id": sid,
            "name": sensor_hostname,
            "identity_class": "system",
            "description": f"T-Pot sensor: {sensor_hostname}",
        }
        return self._dedup(self._stamp(obj, add_confidence=False))

    def build_country_location(
        self,
        country_code: str,
        country_name: Optional[str] = None,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        """Country-level Location SDO.

        Per 2026-05-22 audit #6: accepts an optional ``session`` like the
        other observable-style builders so the Location page in OpenCTI
        gets a context description + parser-derived labels + the actual
        first-seen timestamp.  Geographic browse views in particular
        benefit — a bare ``"RO"`` is far less useful than ``"RO — sourcing
        Cowrie SSH attacks via node2"``.
        """
        if not country_code:
            return None
        cc = country_code.upper()
        obj = {
            "type": "location",
            "id": generate_country_location_id(cc),
            "country": cc,
            "name": country_name or cc,
        }
        if session is not None:
            cname = country_name or cc
            obj["x_opencti_description"] = (
                f"Country observed sourcing honeypot attacks: {cname} ({cc}). "
                f"Recent activity: {session.src_ip} via {session.event_type} "
                f"on sensor {session.sensor_hostname!r}."
            )
            obj["x_opencti_labels"] = sorted(set(
                parser_labels_for(session.event_type) + ["attacker-country"]
            ))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        return self._dedup(self._stamp(obj, add_confidence=False))

    def build_city_location(
        self,
        country_code: str,
        city: str,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        """City-level Location SDO.

        See :meth:`build_country_location` for the ``session`` rationale —
        same shape, scoped to the (country, city) pair.
        """
        if not (country_code and city):
            return None
        cc = country_code.upper()
        obj = {
            "type": "location",
            "id": generate_city_location_id(cc, city),
            "city": city,
            "country": cc,
            "name": f"{city}, {cc}",
        }
        if session is not None:
            obj["x_opencti_description"] = (
                f"City observed sourcing honeypot attacks: {city}, {cc}. "
                f"Recent activity: {session.src_ip} via {session.event_type} "
                f"on sensor {session.sensor_hostname!r}."
            )
            obj["x_opencti_labels"] = sorted(set(
                parser_labels_for(session.event_type) + ["attacker-city"]
            ))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        return self._dedup(self._stamp(obj, add_confidence=False))

    def build_autonomous_system(
        self,
        asn: int,
        organization: Optional[str] = None,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        if asn is None:
            return None
        obj = {
            "type": "autonomous-system",
            "id": generate_autonomous_system_id(asn),
            "number": int(asn),
        }
        if organization:
            obj["name"] = organization
        if session is not None:
            obj["x_opencti_description"] = (
                f"AS{int(asn)}"
                + (f" — {organization}" if organization else "")
                + f". Observed sourcing honeypot attacks from "
                + f"{session.src_ip} via {session.event_type}."
            )
            obj["x_opencti_labels"] = sorted(set(
                parser_labels_for(session.event_type) + ["attacker-as"]
            ))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        refs = _refs_for_as(int(asn))
        if refs:
            obj["external_references"] = refs
        return self._dedup(self._stamp(obj, add_confidence=False))

    def build_attack_pattern(
        self,
        name: str,
        mitre_id: Optional[str] = None,
        *,
        session: Optional[AttackSession] = None,
    ) -> dict:
        """AttackPattern SDO (optionally tied to a MITRE ATT&CK technique).

        Per 2026-05-22 audit #6: accepts an optional ``session`` so the
        pattern carries an evidence description + parser labels, mirroring
        the enrichment shape we already apply to Indicator / AS / IP.
        Without ``session`` the bare SDO is still emitted (drive-by path,
        unit tests).
        """
        obj = {
            "type": "attack-pattern",
            "id": generate_attack_pattern_id(name),
            "name": name,
        }
        if mitre_id:
            obj["external_references"] = [{
                "source_name": "mitre-attack",
                "external_id": mitre_id,
                "url": f"https://attack.mitre.org/techniques/{mitre_id}/",
            }]
        if session is not None:
            mitre_str = f" (MITRE {mitre_id})" if mitre_id else ""
            obj["description"] = (
                f"Attack pattern {name!r}{mitre_str} observed in honeypot "
                f"telemetry: {session.src_ip} via {session.event_type} on "
                f"sensor {session.sensor_hostname!r}."
            )
            # AttackPattern is an SDO so it gets canonical objectLabel
            # via labels= rather than x_opencti_labels (the latter is for SCOs).
            obj["labels"] = sorted(set(
                parser_labels_for(session.event_type) + ["attack-pattern"]
            ))
        return self._dedup(self._stamp(obj, add_confidence=False)) or obj

    # ──────────────────────────────────────────────────────────────────
    # SCOs (observables)
    # ──────────────────────────────────────────────────────────────────

    def build_ipv4(
        self,
        ip: str,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        """Build the IPv4-Addr observable for an attacker IP.

        When `session` is provided we attach OpenCTI's `x_opencti_*`
        extensions so the IP page in the UI carries:
          - a human description naming the parser + sensor + counts
          - source labels (honeypot, <parser>, <protocol>)
          - the actual honeypot event timestamp (not the connector run)
          - a pivot menu (AbuseIPDB / VT / Shodan / Censys / GreyNoise)

        Without session, we still emit a minimal observable so the
        publisher's drive-by path (and any unit tests) keep working.
        """
        if not ip or not _IPV4_RE.match(ip):
            return None
        obj = {
            "type": "ipv4-addr",
            "id": generate_ipv4_id(ip),
            "value": ip,
        }
        # OpenCTI extensions — populated when we have session context.
        if session is not None:
            obj["x_opencti_description"] = (
                f"IP {ip} observed attacking T-Pot sensor "
                f"{session.sensor_hostname!r} via {session.event_type} "
                f"({session.event_count} event(s)). "
                f"First seen {session.first_seen.isoformat()}; "
                f"last seen {session.last_seen.isoformat()}."
            )
            obj["x_opencti_labels"] = sorted(
                set(parser_labels_for(session.event_type))
            )
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        # Pivot menu — adds 5 external_references; OpenCTI renders these
        # as buttons on the IP detail page.
        refs = _refs_for_ipv4(ip)
        if refs:
            obj["external_references"] = refs
        return self._dedup(self._stamp(obj))

    def build_file(
        self,
        sha256: str,
        *,
        name: Optional[str] = None,
        size: Optional[int] = None,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        if not sha256:
            return None
        sha256_lc = sha256.lower()
        obj = {
            "type": "file",
            "id": generate_file_id(sha256),
            "hashes": {"SHA-256": sha256_lc},
        }
        if name:
            obj["name"] = name
        if size is not None:
            obj["size"] = int(size)
        if session is not None:
            obj["x_opencti_description"] = (
                f"File sha256:{sha256_lc[:16]}… dropped by attacker "
                f"{session.src_ip} via {session.event_type} on sensor "
                f"{session.sensor_hostname!r}. First seen "
                f"{session.first_seen.isoformat()}."
            )
            obj["x_opencti_labels"] = sorted(set(
                parser_labels_for(session.event_type) + ["malware-sample"]
            ))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        refs = _refs_for_file(sha256_lc)
        if refs:
            obj["external_references"] = refs
        return self._dedup(self._stamp(obj))

    def build_url(
        self,
        url: str,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        if not url:
            return None
        obj = {
            "type": "url",
            "id": generate_url_id(url),
            "value": url,
        }
        if session is not None:
            obj["x_opencti_description"] = (
                f"URL referenced by attacker {session.src_ip} via "
                f"{session.event_type} on sensor "
                f"{session.sensor_hostname!r}."
            )
            obj["x_opencti_labels"] = sorted(set(
                parser_labels_for(session.event_type) + ["attacker-referenced"]
            ))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        refs = _refs_for_url(url)
        if refs:
            obj["external_references"] = refs
        return self._dedup(self._stamp(obj))

    def build_domain(
        self,
        fqdn: str,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        if not fqdn:
            return None
        fqdn_lc = fqdn.lower()
        obj = {
            "type": "domain-name",
            "id": generate_domain_id(fqdn),
            "value": fqdn_lc,
        }
        if session is not None:
            obj["x_opencti_description"] = (
                f"Domain {fqdn_lc} referenced by attacker {session.src_ip} "
                f"via {session.event_type} on sensor "
                f"{session.sensor_hostname!r}."
            )
            obj["x_opencti_labels"] = sorted(set(
                parser_labels_for(session.event_type) + ["attacker-referenced"]
            ))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        refs = _refs_for_domain(fqdn_lc)
        if refs:
            obj["external_references"] = refs
        return self._dedup(self._stamp(obj))

    def build_process(self, session: AttackSession, commands: list[str]) -> Optional[dict]:
        """Process SDO carrying the attacker's command transcript.

        Enriched per the same pattern as build_ipv4 / build_url / etc.
        (port of PoC's observable enrichment): x_opencti_description
        names the attacker + sensor + parser context, x_opencti_labels
        carries the parser-source tags, x_opencti_created_at is the
        actual session timestamp so OpenCTI's "Original Creation Date"
        column reflects when the attack ran (not when the connector
        ingested it). Per the live cycle 16 review — a bare Process
        with just command_line and TLP marking is hard to use; the
        analyst can't tell which sensor/parser the commands came from.
        """
        if not commands:
            return None
        # Cap commands to MAX_COMMANDS_PER_PROCESS for bundle-size sanity
        capped = commands[:MAX_COMMANDS_PER_PROCESS]
        truncated_marker = (
            f"\n... and {len(commands) - MAX_COMMANDS_PER_PROCESS} more"
            if len(commands) > MAX_COMMANDS_PER_PROCESS else ""
        )
        cmd_line = "\n".join(capped) + truncated_marker
        obj = {
            "type": "process",
            "id": generate_process_id(session.sensor_hostname, session.session_id),
            "command_line": cmd_line,
            "x_opencti_description": (
                f"Command sequence executed by attacker {session.src_ip} "
                f"in a {session.event_type} session on sensor "
                f"{session.sensor_hostname!r} "
                f"({len(commands)} command(s), "
                f"first seen {session.first_seen.isoformat()})."
            ),
            "x_opencti_labels": sorted(set(
                parser_labels_for(session.event_type) + ["command-transcript"]
            )),
            "x_opencti_created_at": session.first_seen.isoformat(),
        }
        return self._dedup(self._stamp(obj))

    def build_cryptographic_key(
        self,
        value: str,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        """Cryptographic-Key SCO (HASSH / SSH client fingerprint / etc.).

        Type spelling is critical: `cryptographic-key` per STIX 2.1 and
        LESSONS §8.4. The custom `x-opencti-cryptographic-key` typo gets
        silently dropped by OpenCTI's worker — never use it.

        When `session` is provided, attaches OpenCTI x_opencti_*
        extensions so the HASSH page shows analyst-useful context (which
        attacker IP it came from, which sensor, what SSH client banner).
        Plugged in 2026-05-22 after spot-check showed Cryptographic-Key
        as 100% missing description+labels — same gap Process had until
        commit f66da5c.
        """
        if not value:
            return None
        obj = {
            "type": "cryptographic-key",   # correct type per LESSONS §8.4
            "id": generate_cryptographic_key_id(value),
            "value": value,
        }
        if session is not None:
            ssh_ver = (session.ssh_version or "unknown SSH client").strip() or "unknown SSH client"
            obj["x_opencti_description"] = (
                f"HASSH SSH-client fingerprint {value[:16]}… observed from "
                f"attacker {session.src_ip} via {session.event_type} on "
                f"sensor {session.sensor_hostname!r}. Banner: {ssh_ver}. "
                f"Same fingerprint across different IPs implies same SSH "
                f"client / tool — useful for campaign correlation."
            )
            obj["x_opencti_labels"] = sorted(set(
                parser_labels_for(session.event_type) + ["ssh-fingerprint", "hassh"]
            ))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        return self._dedup(self._stamp(obj))

    def build_planted_ssh_key(
        self,
        key_info: dict,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        """Cryptographic-Key SCO for an attacker-planted SSH public key.

        Distinct from :meth:`build_cryptographic_key` (which models a
        HASSH SSH-client hash) — this one represents the public key
        material the attacker dropped into the victim's
        ``~/.ssh/authorized_keys``.  The observable value is the SHA256
        fingerprint of the key blob (matching OpenSSH ``ssh-keygen
        -lf`` semantics minus the ``SHA256:`` prefix and base64
        encoding); the full key + type + comment go in the description
        so operators can copy/paste it into a hunt.

        Every attacker IP that planted the SAME key produces the SAME
        UUID5 here, so OpenCTI dedups them onto one SCO.  Each IP's
        Cowrie session adds a ``related-to`` edge to that one SCO —
        and clicking the SCO in OpenCTI's UI walks those edges back to
        the entire campaign footprint.  This is the operator-pivot
        we couldn't get from HASSH alone (HASSH groups by client
        tool; a planted key groups by C&C identity).
        """
        if not isinstance(key_info, dict):
            return None
        fingerprint = key_info.get("fingerprint")
        key_blob = key_info.get("key")
        key_type = key_info.get("type") or "ssh-rsa"
        comment = key_info.get("comment") or ""
        if not fingerprint or not key_blob:
            return None

        # Compose a copy-paste-ready authorized_keys line for the desc.
        full_line = f"{key_type} {key_blob}"
        if comment:
            full_line += f" {comment}"

        obj = {
            "type": "cryptographic-key",
            "id": generate_cryptographic_key_id(fingerprint),
            # The visible "value" is the SHA256 fingerprint — short,
            # uniquely identifying, copy-pasteable. Operators wanting
            # the full key material read the description.
            "value": f"SHA256:{fingerprint}",
        }
        comment_disp = comment or "∅ (no comment)"
        desc_lines = [
            f"Attacker-planted SSH public key (campaign IoC).",
            f"",
            f"Key type:      {key_type}",
            f"SHA256 fp:     {fingerprint}",
            f"Comment:       {comment_disp}",
            f"",
            f"authorized_keys line (verbatim):",
            f"    {full_line}",
            f"",
            f"Every attacker IP that planted this key links to this "
            f"SCO via `related-to`. Click 'Related entities' to see "
            f"the campaign footprint.",
        ]
        if session is not None:
            desc_lines.insert(
                1,
                f"First observed: {session.first_seen.isoformat()} from "
                f"{session.src_ip} via Cowrie on "
                f"sensor {session.sensor_hostname!r}.",
            )
        obj["x_opencti_description"] = "\n".join(desc_lines)

        labels = ["ssh-key", "planted-key", "campaign-ioc", key_type]
        if comment:
            # Comment is often a botnet tag ("mdrfckr" for Outlaw,
            # "JenX" for that family, etc.) — make it a label for
            # quick filtering.
            tag = re.sub(r'[^A-Za-z0-9._-]', '', comment.lower())[:32]
            if tag:
                labels.append(f"comment:{tag}")
        if session is not None:
            labels.extend(parser_labels_for(session.event_type))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        obj["x_opencti_labels"] = sorted(set(labels))
        # Confidence/score: a planted-key SCO is one of the highest-
        # signal IoCs we emit. Score it at 85 so it stands out vs the
        # routine SCO-50 baseline.
        obj["x_opencti_score"] = 85
        return self._dedup(self._stamp(obj))

    # ──────────────────────────────────────────────────────────────────
    # SDOs (indicators, notes, vulnerabilities)
    # ──────────────────────────────────────────────────────────────────

    def build_ip_indicator(
        self,
        ip: str,
        *,
        session: Optional[AttackSession] = None,
        session_count: int = 1,
    ) -> Optional[dict]:
        """Build a STIX Indicator for an attacker IP.

        Per the PoC pattern (
        tsec-tpot-connectors/tsec-tpot-hp-connector/src/stix/indicators.py
        ): rich `name` template, multi-paragraph `description` with
        session/event counts + date range + severity context, source
        labels, computed score, valid_until from validity_days.

        When `session` is None, falls back to a minimal indicator —
        keeps backward compat with the few smoke tests that build
        bare indicators.
        """
        if not ip or not _IPV4_RE.match(ip):
            return None

        event_type = session.event_type if session else None
        n = session_count if session_count is not None else (
            session.event_count if session else 1
        )

        # Score + valid_from/valid_until
        score = _signal_score(session)
        first_seen = session.first_seen if session else datetime.now(timezone.utc)
        last_seen = session.last_seen if session else datetime.now(timezone.utc)
        valid_until = last_seen + timedelta(days=DEFAULT_INDICATOR_VALIDITY_DAYS)

        # Description — multi-paragraph context (PoC pattern). Skip when no
        # session info available (smoke tests + edge cases).
        description: Optional[str] = None
        if session is not None:
            start_date = session.first_seen.strftime("%Y-%m-%d %H:%M")
            end_date = session.last_seen.strftime("%Y-%m-%d %H:%M")
            bits: list[str] = [
                f"Malicious IP {ip} observed via {event_type} on sensor "
                f"{session.sensor_hostname!r} in {n} correlated session"
                f"{'s' if n != 1 else ''} ({session.event_count} total "
                f"event{'s' if session.event_count != 1 else ''}). "
                f"Activity between {start_date} and {end_date} UTC."
            ]
            # Substance-signal hints — what made this session score high.
            sig_bits: list[str] = []
            if session.auth_success:
                sig_bits.append("successful authentication")
            if session.commands:
                sig_bits.append(f"{len(session.commands)} command(s) executed")
            if session.malware_hashes:
                sig_bits.append(
                    f"{len(session.malware_hashes)} file(s) dropped"
                )
            if session.credentials_tried:
                sig_bits.append(
                    f"{len(session.credentials_tried)} credential attempt(s)"
                )
            if sig_bits:
                bits.append("Substance signals: " + ", ".join(sig_bits) + ".")
            # Severity blurb tuned to the score band.
            if score >= 80:
                bits.append(
                    "High threat score: sophisticated attack patterns "
                    "(successful auth, command execution, or malware "
                    "delivery). Consider sharing as actor IoC."
                )
            elif score >= 60:
                bits.append(
                    "Medium threat score: active attack attempts with "
                    "multiple authentication tries or reconnaissance "
                    "activity."
                )
            else:
                bits.append(
                    "Baseline-or-low score: drive-by probe behavior. "
                    "Useful for noise/scanner correlation, not actor "
                    "attribution."
                )
            description = " ".join(bits)

        obj = {
            "type": "indicator",
            "id": generate_ip_indicator_id(ip),
            "name": _format_indicator_name(event_type, ip, n),
            "pattern_type": "stix",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "valid_from": first_seen.isoformat(),
            "valid_until": valid_until.isoformat(),
            "indicator_types": ["malicious-activity"],
            "labels": sorted(set(parser_labels_for(event_type))),
            # OpenCTI custom properties (the dashboard widgets read these).
            "x_opencti_score": score,
            "x_opencti_main_observable_type": "IPv4-Addr",
        }
        if description:
            obj["description"] = description
        # Pivot menu on the indicator too — duplicates the SCO's refs but
        # an analyst on the indicator page wants the same one-click options.
        refs = _refs_for_ipv4(ip)
        if refs:
            obj["external_references"] = refs
        return self._dedup(self._stamp(obj))

    def build_file_indicator(
        self,
        sha256: str,
        *,
        name: Optional[str] = None,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        if not sha256:
            return None
        sha_lc = sha256.lower()
        n = session.event_count if session else 1
        score = _signal_score(session)
        first_seen = session.first_seen if session else datetime.now(timezone.utc)
        last_seen = session.last_seen if session else datetime.now(timezone.utc)
        valid_until = last_seen + timedelta(days=DEFAULT_INDICATOR_VALIDITY_DAYS)

        description: Optional[str] = None
        if session is not None:
            description = (
                f"File sha256:{sha_lc} dropped/downloaded by attacker "
                f"{session.src_ip} via {session.event_type} on sensor "
                f"{session.sensor_hostname!r}. First seen "
                f"{session.first_seen.strftime('%Y-%m-%d %H:%M')} UTC. "
                f"Honeypot sample — bytes available via the malware-vault "
                f"sidecar if enabled."
            )

        obj = {
            "type": "indicator",
            "id": generate_file_indicator_id(sha256),
            "name": name or f"Honeypot file SHA256 {sha_lc[:16]}…",
            "pattern_type": "stix",
            "pattern": f"[file:hashes.'SHA-256' = '{sha_lc}']",
            "valid_from": first_seen.isoformat(),
            "valid_until": valid_until.isoformat(),
            "indicator_types": ["malicious-activity"],
            "labels": sorted(set(
                parser_labels_for(session.event_type if session else None)
                + ["malware-sample"]
            )),
            "x_opencti_score": score,
            "x_opencti_main_observable_type": "StixFile",
        }
        if description:
            obj["description"] = description
        refs = _refs_for_file(sha_lc)
        if refs:
            obj["external_references"] = refs
        return self._dedup(self._stamp(obj))

    def build_session_note(
        self,
        session: AttackSession,
        body_md: str,
        abstract: Optional[str] = None,
        object_refs: Optional[list[str]] = None,
    ) -> Optional[dict]:
        """Per-session Note SDO.

        WARNING: per LESSONS §7.1 we do NOT emit a per-IP per-cycle
        Activity Report.  Use this only for genuinely-per-session content
        (a Cowrie command transcript, a Honeytrap payload hexdump that's
        worth preserving).  For aggregated content use
        `build_daily_credentials_note()` or skip the Note entirely and
        let the per-event Sighting carry the signal.
        """
        if not body_md:
            return None
        # Cap to MAX_NOTE_BODY_BYTES
        if len(body_md.encode("utf-8")) > MAX_NOTE_BODY_BYTES:
            body_md = body_md[:MAX_NOTE_BODY_BYTES] + "\n... [truncated]"
        obj = {
            "type": "note",
            "id": generate_session_note_id(session.sensor_hostname, session.session_id),
            "abstract": abstract or f"Session {session.session_id[:16]}… from {session.src_ip}",
            "content": body_md,
            "object_refs": object_refs or [],
        }
        return self._dedup(self._stamp(obj))

    def build_daily_credentials_note(
        self,
        sensor_hostname: str,
        utc_date: str,        # YYYY-MM-DD
        body_md: str,
        object_refs: Optional[list[str]] = None,
    ) -> Optional[dict]:
        """Per V1_SPEC §6 — one Note per sensor per UTC day with top-100 creds.

        Idempotent: same (sensor, utc_date) → same UUID, OpenCTI upserts.
        """
        if not body_md:
            return None
        if len(body_md.encode("utf-8")) > MAX_NOTE_BODY_BYTES:
            body_md = body_md[:MAX_NOTE_BODY_BYTES] + "\n... [truncated]"
        obj = {
            "type": "note",
            "id": generate_daily_creds_note_id(sensor_hostname, utc_date),
            "abstract": f"Top 100 credential attempts — {utc_date} (UTC) — sensor: {sensor_hostname}",
            "content": body_md,
            "object_refs": object_refs or [generate_sensor_id(sensor_hostname)],
        }
        return self._dedup(self._stamp(obj))

    def build_vulnerability(self, cve_id: str, *, description: Optional[str] = None) -> Optional[dict]:
        if not cve_id:
            return None
        obj = {
            "type": "vulnerability",
            "id": generate_vulnerability_id(cve_id),
            "name": cve_id,
            "external_references": [{
                "source_name": "cve",
                "external_id": cve_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }],
        }
        if description:
            obj["description"] = description
        return self._dedup(self._stamp(obj))

    # ──────────────────────────────────────────────────────────────────
    # Relationships and Sightings
    # ──────────────────────────────────────────────────────────────────

    def build_relationship(
        self,
        src_id: str,
        relationship_type: str,
        dst_id: str,
        *,
        description: Optional[str] = None,
    ) -> Optional[dict]:
        if not (src_id and dst_id and relationship_type) or src_id == dst_id:
            return None
        obj = {
            "type": "relationship",
            "id": generate_relationship_id(src_id, dst_id, relationship_type),
            "relationship_type": relationship_type,
            "source_ref": src_id,
            "target_ref": dst_id,
        }
        if description:
            obj["description"] = description
        return self._dedup(self._stamp(obj))

    def build_sighting(
        self,
        target_ref: str,
        sensor_hostname: str,
        session: AttackSession,
        *,
        count: int = 1,
        description: Optional[str] = None,
        id_discriminator: str = "",
    ) -> Optional[dict]:
        """Sighting SDO — per V1_SPEC §4 'sighting target=Indicator,
        where=sensor Identity'.

        ``target_ref`` is the STIX id this Sighting refers to.  In
        STIX 2.1 the spec says ``sighting_of_ref`` SHOULD be an SDO
        (typically an Indicator), but the field accepts any SDO/SCO id.
        We exploit that to emit *two* Sightings per session (see
        :meth:`build_dual_sighting`): one on the IP Indicator and one
        directly on the IPv4-Addr observable, so OpenCTI's "Sightings"
        tab populates on both pages.  The optional ``id_discriminator``
        threads through to :func:`generate_sighting_id` so the two
        Sightings get distinct deterministic IDs.

        Per LESSONS §7.1: putting per-session activity summaries
        in the Sighting `description` is the preferred place for
        low-signal-per-event protocols (Honeytrap probe payload, Fallback
        unknown-type blurb). Beats spewing 50k+ Notes/day that nobody
        reads. Cowrie/SSH sessions still get their own Notes — those
        are the genuinely-per-session content the lesson called out
        as the carve-out.
        """
        if not (target_ref and sensor_hostname):
            return None
        sensor_id = generate_sensor_id(sensor_hostname)
        obj = {
            "type": "sighting",
            "id": generate_sighting_id(
                sensor_hostname, session.session_id, id_discriminator,
            ),
            "sighting_of_ref": target_ref,
            "where_sighted_refs": [sensor_id],
            "first_seen": session.first_seen.isoformat(),
            "last_seen": session.last_seen.isoformat(),
            "count": count,
        }
        if description:
            obj["description"] = description
        return self._dedup(self._stamp(obj))

    def build_dual_sighting(
        self,
        indicator_id: str,
        ipv4_id: Optional[str],
        sensor_hostname: str,
        session: AttackSession,
        *,
        count: int = 1,
        description: Optional[str] = None,
    ) -> list[dict]:
        """Emit Sightings on BOTH the IP Indicator and the IPv4-Addr.

        STIX 2.1 §4.13 says ``sighting_of_ref`` SHOULD be an SDO; OpenCTI's
        Observable→Sightings tab only walks Sightings whose
        ``sighting_of_ref`` is the observable itself (it does NOT follow
        the ``based-on`` edge from Indicator to Observable).  Operators
        clicking through to an IP page therefore see an empty Sightings
        tab — confusing and easy to misread as "we have no telemetry".

        To fix that without losing the STIX-correct Indicator sighting,
        we emit BOTH:

          1. Indicator-side Sighting — preserved ID family
             (``sighting:<sensor>:<session>``).  This is the canonical
             Sighting and is what cross-cycle preservation keys off.
          2. Observable-side Sighting — distinct ID family
             (``sighting:<sensor>:<session>:ipv4``).  Same first/last
             seen, same count, same description, same sensor identity.

        Callers pass the already-resolved ``indicator_id`` and
        ``ipv4_id``; if either is None that side is skipped.
        """
        out: list[dict] = []
        if indicator_id:
            sighting = self.build_sighting(
                indicator_id, sensor_hostname, session,
                count=count, description=description,
            )
            if sighting:
                out.append(sighting)
        if ipv4_id:
            obs_sighting = self.build_sighting(
                ipv4_id, sensor_hostname, session,
                count=count, description=description,
                id_discriminator="ipv4",
            )
            if obs_sighting:
                out.append(obs_sighting)
        return out

    # ──────────────────────────────────────────────────────────────────
    # High-level convenience: build the common entity bundle for one
    # session, regardless of substance.  Parsers can then layer their
    # protocol-specific extras on top.
    # ──────────────────────────────────────────────────────────────────

    # ──────────────────────────────────────────────────────────────────
    # Per-parser session builders (the V0 parser-vs-builder separation rule — STIX-shape decisions
    # live here, not in parsers).  Each method consumes one AttackSession
    # and returns the full per-protocol STIX object list.  The orchestrator
    # (main.run_cycle) dispatches to the right method via _PARSER_DISPATCH.
    # ──────────────────────────────────────────────────────────────────

    def build_cowrie_session(self, session: AttackSession) -> list[dict]:
        """Build the full Cowrie session STIX graph.

        Caller is expected to have already determined has_substance() is
        True.  For drive-by sessions the caller invokes
        `self.build_driveby_session(session)` instead.

        Emits: sensor + attacker context + IP Indicator + (HASSH key) +
        (Process) + (File + File Indicator) + URLs + Domains + Sighting +
        per-session transcript Note.
        """
        out: list[dict] = []
        if not session.events:
            return out

        # Foundation: sensor + attacker context (IPv4 + geo + AS)
        out.extend(self.build_sensor_context(session.sensor_hostname))
        out.extend(self.build_attacker_context(session.events[0], session=session))

        ipv4_id = generate_ipv4_id(session.src_ip)

        # IP Indicator + based-on → IPv4
        ip_ind = self.build_ip_indicator(session.src_ip, session=session)
        if ip_ind:
            out.append(ip_ind)
            if rel := self.build_relationship(
                ip_ind["id"], "based-on", ipv4_id,
                description=f"IP indicator for {session.src_ip}",
            ):
                out.append(rel)

        # HASSH fingerprint → Cryptographic-Key
        if session.hassh:
            ck = self.build_cryptographic_key(session.hassh, session=session)
            if ck:
                out.append(ck)
                if rel := self.build_relationship(
                    ck["id"], "related-to", ipv4_id,
                    description=f"HASSH fingerprint observed from {session.src_ip}",
                ):
                    out.append(rel)

        # Planted SSH public keys → Cryptographic-Key SCOs (campaign IoC).
        # Each unique fingerprint becomes one observable, and every
        # attacker IP that planted that key links to it via `related-to`.
        # Operator pivot: click the key in OpenCTI → see every src_ip
        # that planted it = the full campaign footprint.  Outlaw is the
        # canonical example (470+ src_ips, one key) but this catches any
        # actor doing `echo "ssh-rsa AAA..." >> authorized_keys` style
        # persistence.
        for key_info in (session.planted_ssh_keys or []):
            fp = key_info.get("fingerprint")
            if not fp:
                continue
            ck = self.build_planted_ssh_key(key_info, session=session)
            if not ck:
                continue
            out.append(ck)
            # IP observable → key (so the key's "Related Entities" tab
            # shows every IP that planted it — the campaign view).
            if rel := self.build_relationship(
                ipv4_id, "related-to", ck["id"],
                description=(
                    f"Planted SSH key (type={key_info.get('type')}, "
                    f"comment={key_info.get('comment') or '∅'!r}) "
                    f"installed by attacker {session.src_ip}"
                ),
            ):
                out.append(rel)
            # IP Indicator → key (so the indicator-side knowledge tab
            # also shows the campaign pivot).
            if ip_ind:
                if rel := self.build_relationship(
                    ip_ind["id"], "related-to", ck["id"],
                    description=f"Indicator for IP that planted SSH key {fp[:12]}…",
                ):
                    out.append(rel)

        # Process (commands)
        process_id: Optional[str] = None
        if session.commands:
            proc = self.build_process(session, session.commands)
            if proc:
                out.append(proc)
                process_id = proc["id"]
                if rel := self.build_relationship(
                    proc["id"], "related-to", ipv4_id,
                    description=f"Commands run by {session.src_ip} in Cowrie session",
                ):
                    out.append(rel)

        # File downloads → StixFile + Indicator + URL/Domain
        for sha256 in session.malware_hashes:
            f = self.build_file(sha256, session=session)
            if f:
                out.append(f)
                if rel := self.build_relationship(
                    f["id"], "related-to", ipv4_id,
                    description=f"File {sha256[:16]}… downloaded by {session.src_ip}",
                ):
                    out.append(rel)
                # File Indicator + based-on
                f_ind = self.build_file_indicator(sha256, session=session)
                if f_ind:
                    out.append(f_ind)
                    if rel := self.build_relationship(
                        f_ind["id"], "based-on", f["id"],
                        description=f"Honeypot-captured file {sha256[:16]}…",
                    ):
                        out.append(rel)

        # URLs (download sources + URLs in commands)
        for url in session.urls:
            url_obj = self.build_url(url, session=session)
            if url_obj:
                out.append(url_obj)
                if rel := self.build_relationship(
                    url_obj["id"], "related-to", ipv4_id,
                    description=f"URL referenced by {session.src_ip}",
                ):
                    out.append(rel)

        # Domains derived from URLs
        for fqdn in session.domains:
            d = self.build_domain(fqdn, session=session)
            if d:
                out.append(d)

        # Dual sighting (Indicator + Observable) — see build_dual_sighting
        # docstring for the OpenCTI UX rationale.
        if ip_ind:
            out.extend(self.build_dual_sighting(
                ip_ind["id"], ipv4_id, session.sensor_hostname, session,
                count=session.event_count,
                description=render_cowrie_sighting_description(session),
            ))

        # Per-session Notes replaced by attacker-profile Notes emitted from
        # main.run_cycle (see tpot2cti/attacker_profile.py); per-session
        # command transcripts are preserved in the Process SDO's
        # command_line field. Per the V0 "don't emit 50K Notes/day" finding + the 2026-05-21 user
        # decision: ONE rolling Note per attacker IP scales; 50 per-session
        # Notes per attacker do not.
        _ = process_id  # referenced above; kept for future per-session links

        return out

    def build_suricata_alert(self, session: AttackSession) -> list[dict]:
        """Build the STIX graph for one Suricata alert.

        Because each session wraps a single alert (one_event_per_session),
        we pull metadata directly from the lone event rather than from
        any pre-aggregated session fields.
        """
        out: list[dict] = []
        if not session.events:
            return out
        event = session.events[0]
        meta = event.meta

        # Mirror the alert metadata onto session.meta so downstream
        # consumers can introspect without reaching into events[0].
        for k, v in meta.items():
            session.meta.setdefault(k, v)

        # Foundation: sensor + attacker context (IPv4 + geo + AS)
        out.extend(self.build_sensor_context(session.sensor_hostname))
        out.extend(self.build_attacker_context(event, session=session))

        ipv4_id = generate_ipv4_id(session.src_ip)

        # IP Indicator + based-on → IPv4
        ip_ind = self.build_ip_indicator(session.src_ip, session=session)
        if ip_ind:
            out.append(ip_ind)
            if rel := self.build_relationship(
                ip_ind["id"], "based-on", ipv4_id,
                description=f"IP indicator for {session.src_ip}",
            ):
                out.append(rel)

        # ── AttackPattern(s) from MITRE technique metadata ────────────
        attack_pattern_ids: list[str] = []
        techniques: list[str] = meta.get("mitre_techniques") or []
        for tid in techniques:
            name = _KNOWN_MITRE_TECHNIQUES.get(tid)
            if not name:
                logger.debug(
                    f"suricata: unknown MITRE technique id {tid!r} in signature "
                    f"{meta.get('signature')!r}; skipping AttackPattern emission"
                )
                continue
            ap = self.build_attack_pattern(name=name, mitre_id=tid, session=session)
            if ap:
                out.append(ap)
                attack_pattern_ids.append(ap["id"])

        # Fallback: if no recognized MITRE technique attached, emit a
        # generic "Network Attack" AttackPattern so we always have an
        # indicates-target per V1_SPEC §5.2.
        if ip_ind and not attack_pattern_ids:
            generic = self.build_attack_pattern(name="Network Attack", session=session)
            if generic:
                out.append(generic)
                attack_pattern_ids.append(generic["id"])

        # Indicator → indicates → AttackPattern(s)
        if ip_ind:
            for ap_id in attack_pattern_ids:
                if rel := self.build_relationship(
                    ip_ind["id"], "indicates", ap_id,
                    description=(
                        f"Suricata rule {meta.get('signature_id') or '?'}: "
                        f"{meta.get('signature') or 'alert'}"
                    ),
                ):
                    out.append(rel)

        # ── Vulnerabilities (CVE refs from signature name) ────────────
        for cve in meta.get("cves") or []:
            vuln = self.build_vulnerability(
                cve,
                description=f"Referenced by Suricata signature: {meta.get('signature')!r}",
            )
            if vuln:
                out.append(vuln)
                if ip_ind:
                    if rel := self.build_relationship(
                        ip_ind["id"], "indicates", vuln["id"],
                        description=(
                            f"{session.src_ip} attempted exploit of {cve} "
                            f"(Suricata SID {meta.get('signature_id') or '?'})"
                        ),
                    ):
                        out.append(rel)

        # ── Domain-Name (TLS SNI or HTTP host) ────────────────────────
        # Collect candidate domains, dedup, build Domain-Name observables.
        domain_candidates: list[str] = []
        if sni := meta.get("tls_sni"):
            domain_candidates.append(sni)
        if host := meta.get("http_host"):
            if host not in domain_candidates:
                domain_candidates.append(host)

        for fqdn in domain_candidates:
            d = self.build_domain(fqdn, session=session)
            if d:
                out.append(d)
                # Domain-Name → resolves-to → IPv4-Addr (dst_ip preferred,
                # since the SNI/host refers to the destination the
                # attacker is trying to reach; if no dst_ip, fall back to
                # the alert's src_ip per V1_SPEC §5.2 phrasing).
                target_ip = event.dst_ip or session.src_ip
                if target_ip:
                    target_ipv4_id = generate_ipv4_id(target_ip)
                    if rel := self.build_relationship(
                        d["id"], "resolves-to", target_ipv4_id,
                        description=f"{fqdn} resolved-to {target_ip} per honeypot observation",
                    ):
                        out.append(rel)

        # ── URL observable (if HTTP request URL captured) ─────────────
        if (url := meta.get("http_url")) and (host := meta.get("http_host")):
            full_url = url if url.startswith("http") else f"http://{host}{url}"
            url_obj = self.build_url(full_url, session=session)
            if url_obj:
                out.append(url_obj)
                if rel := self.build_relationship(
                    url_obj["id"], "related-to", ipv4_id,
                    description=f"URL requested by {session.src_ip}",
                ):
                    out.append(rel)

        # ── Dual sighting (Indicator + IPv4 observable) ───────────────
        if ip_ind:
            out.extend(self.build_dual_sighting(
                ip_ind["id"], ipv4_id, session.sensor_hostname, session,
                count=1,
            ))

        return out

    def build_honeytrap_probe(self, session: AttackSession) -> list[dict]:
        """Build the STIX graph for a substantive Honeytrap session.

        The caller (orchestrator) is expected to have already checked
        `has_substance()` and routed drive-by sessions to
        `self.build_driveby_session()` instead.  This method assumes
        substance and always emits a Sighting with the captured payload
        summary in its `description`.
        """
        out: list[dict] = []
        if not session.events:
            return out

        event = session.events[0]

        # Foundation: sensor + attacker context (IPv4 + GeoIP + AS)
        out.extend(self.build_sensor_context(session.sensor_hostname))
        out.extend(self.build_attacker_context(event, session=session))

        ipv4_id = generate_ipv4_id(session.src_ip)

        # IP Indicator + based-on → IPv4 observable
        ip_ind = self.build_ip_indicator(session.src_ip, session=session)
        if ip_ind:
            out.append(ip_ind)
            if rel := self.build_relationship(
                ip_ind["id"], "based-on", ipv4_id,
                description=f"IP indicator for {session.src_ip}",
            ):
                out.append(rel)

            # Dual sighting (Indicator + IPv4 observable) — per-probe
            # summary lives on the Sighting `description` (LESSONS_LEARNED
            # §7.1: per-session Notes at hive scale produce 50k+/day that
            # nobody reads; condense into the Sighting).
            out.extend(self.build_dual_sighting(
                ip_ind["id"], ipv4_id, session.sensor_hostname, session,
                count=session.event_count,
                description=render_honeytrap_sighting_description(session, event),
            ))

        return out

    def build_fallback_event(self, session: AttackSession) -> list[dict]:
        """Build STIX for one unknown-type (fallback) session.

        Always emits a Note describing the unknown event when src_ip is
        missing.  When ``src_ip`` is present, emits IPv4-Addr +
        IP-Indicator + Sighting + sensor context with the per-event
        summary on the Sighting.description (no Note — per
        LESSONS §7.1).
        """
        out: list[dict] = []
        if not session.events:
            return out

        first = session.events[0]
        unknown_type = first.event_type

        # Sensor identity is foundation — emit even when there's no IP
        # so the Note can hang off the sensor.
        out.extend(self.build_sensor_context(session.sensor_hostname))

        ipv4_id: Optional[str] = None

        if first.src_ip:
            # Attacker context (IPv4 + GeoIP + AS + located-at / belongs-to)
            attacker_objs = self.build_attacker_context(first, session=session)
            out.extend(attacker_objs)
            if attacker_objs:
                ipv4_id = generate_ipv4_id(first.src_ip)

            # IP Indicator + based-on → IPv4
            ip_ind = self.build_ip_indicator(first.src_ip, session=session)
            if ip_ind:
                out.append(ip_ind)
                if ipv4_id:
                    if rel := self.build_relationship(
                        ip_ind["id"], "based-on", ipv4_id,
                        description=f"IP indicator for {first.src_ip}",
                    ):
                        out.append(rel)

                # Dual sighting on Indicator + IPv4 observable — per-event
                # summary (unknown_type + dst_port) lives on the Sighting
                # `description` field. Per LESSONS §7.1 we do NOT
                # emit a separate Note per event for high-volume / low-
                # signal protocols. If a maintainer wants per-event
                # forensics, the raw doc is preserved on T-Pot's ES.
                out.extend(self.build_dual_sighting(
                    ip_ind["id"], ipv4_id, session.sensor_hostname, session,
                    count=session.event_count,
                    description=render_fallback_sighting_description(first, unknown_type),
                ))
        else:
            # Edge case: unknown-type event has no src_ip.  Without an IP
            # there is no Sighting to attach a description to — emit a
            # single free-floating Note so the event isn't silently lost.
            # This is the ONE remaining Note-emission path in the fallback
            # builder (LESSONS §7.1 carve-out: per-event Notes for
            # the IP-bearing common case are dropped; the rare no-IP case
            # keeps a Note as the only signal we can surface).
            body = render_fallback_no_ip_note_body(first, unknown_type)
            note = self.build_session_note(
                session,
                body_md=body,
                abstract=f"Unrecognized T-Pot event: {unknown_type} (no src_ip)",
                object_refs=[generate_sensor_id(session.sensor_hostname)],
            )
            if note:
                out.append(note)

        return out

    def build_attacker_context(
        self,
        event: ParsedEvent,
        *,
        session: Optional[AttackSession] = None,
    ) -> list[dict]:
        """Build the IPv4 + Location + AutonomousSystem + relationships
        triple for one event's source.

        Returns a list of STIX dicts (skipping anything already-emitted
        within this bundle).  Used by both the driveby and substantive
        code paths.

        When `session` is provided, observables get the OpenCTI x_opencti_*
        enrichment + pivot menu external_references.
        """
        out: list[dict] = []
        ipv4 = self.build_ipv4(event.src_ip, session=session)
        if not ipv4:
            return out
        out.append(ipv4)

        # GeoIP (logstash-enriched)
        if event.src_country_code:
            country = self.build_country_location(
                event.src_country_code, event.src_country_name, session=session,
            )
            if country:
                out.append(country)
                rel = self.build_relationship(
                    ipv4["id"], "located-at", country["id"],
                    description=f"{event.src_ip} geolocated to {event.src_country_code}",
                )
                if rel:
                    out.append(rel)
            if event.src_city:
                city = self.build_city_location(
                    event.src_country_code, event.src_city, session=session,
                )
                if city:
                    out.append(city)
                    rel = self.build_relationship(
                        ipv4["id"], "located-at", city["id"],
                        description=f"{event.src_ip} geolocated to {event.src_city}",
                    )
                    if rel:
                        out.append(rel)

        if event.src_asn:
            asn = self.build_autonomous_system(
                event.src_asn, event.src_as_org, session=session,
            )
            if asn:
                out.append(asn)
                # Use the canonical STIX "belongs-to" for IPv4 → AS
                rel = self.build_relationship(
                    ipv4["id"], "belongs-to", asn["id"],
                    description=f"{event.src_ip} belongs to AS{event.src_asn}",
                )
                if rel:
                    out.append(rel)

        return out

    def build_sensor_context(self, sensor_hostname: str) -> list[dict]:
        """Sensor Identity (foundation, emitted once per bundle per sensor)."""
        out = []
        sensor = self.build_sensor_identity(sensor_hostname)
        if sensor:
            out.append(sensor)
        return out

    def build_driveby_session(self, session: AttackSession) -> list[dict]:
        """Minimal STIX for a probe-and-leave session per LESSONS §2.

        Emits: IPv4 observable + GeoIP + AS + IP Indicator + Sighting.
        NO Process, Note, AttackPattern, malware artifacts, etc.

        Total typical objects per drive-by session: 4-7
        (vs ~30 for the full treatment).
        """
        if not session.events:
            return []
        first = session.events[0]
        out: list[dict] = []
        out.extend(self.build_sensor_context(session.sensor_hostname))
        out.extend(self.build_attacker_context(first, session=session))

        # IP Indicator + Sighting
        ip_ind = self.build_ip_indicator(session.src_ip, session=session)
        if ip_ind:
            out.append(ip_ind)
            # based-on → IPv4 observable (already emitted above)
            ipv4_id = generate_ipv4_id(session.src_ip)
            rel = self.build_relationship(
                ip_ind["id"], "based-on", ipv4_id,
                description=f"IP indicator for {session.src_ip}",
            )
            if rel:
                out.append(rel)
            # Dual sighting (Indicator + IPv4 observable)
            out.extend(self.build_dual_sighting(
                ip_ind["id"], ipv4_id, session.sensor_hostname, session,
                count=session.event_count,
            ))

        return out
