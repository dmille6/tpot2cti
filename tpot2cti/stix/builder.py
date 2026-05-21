"""tpot2cti — STIX 2.1 object builder.

The builder is stateful per-bundle: a new STIXBuilder instance is
created at the start of each cycle, accumulates per-bundle dedup
state (which Identities / Infrastructures / Locations have already
been emitted in THIS bundle), and produces a list of STIX object
dicts ready for the publisher.

Per V1_SPEC.md §4 (STIX object model) the builder emits:

  Foundation:    Identity (operator + sensor), Marking-Definition,
                 Location, Autonomous-System, AttackPattern
  Entities:      IPv4-Addr, StixFile, URL, Domain-Name, Process,
                 Cryptographic-Key, Indicator, Note, Vulnerability
  Relationships: Relationship, Sighting

Every emitted object:
  - has a deterministic id from `tpot2cti.stix_ids`
  - is stamped with `created_by_ref` pointing at the operator Identity
  - is stamped with `object_marking_refs` referencing the default TLP
  - has `created` + `modified` timestamps in ISO 8601 UTC
  - has `confidence` set from config

The substance-filter pattern lives in `BaseParser.has_substance()` —
the builder doesn't decide what to emit; it only knows HOW to emit
the things the parser asked for.  The caller pattern is:

    parser = get_parser(doc['type'])
    for session in parser.correlate(events):
        if parser.has_substance(session):
            stix_objects = builder.build_full_session(session)
        else:
            stix_objects = builder.build_driveby_session(session)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from tpot2cti.config import Config
from tpot2cti.parsers.base import AttackSession, ParsedEvent
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

# Note bodies are capped per LESSONS_LEARNED §13 to keep bundles under
# OpenCTI's ~1 MB worker limit.  64 KB is generous for any reasonable
# session summary.
MAX_NOTE_BODY_BYTES = 64 * 1024

# Process command_line cap (matches PoC convention)
MAX_COMMANDS_PER_PROCESS = 50

# Simple IPv4 / IPv6 sanity regexes (we accept what logstash gave us,
# but reject obviously malformed strings before building observables).
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# ---------------------------------------------------------------------------
# Parser-aware enrichment vocabulary (port of PoC's `source_labels` pattern
# from /home/mike/poc/tsec-tpot-connectors/tsec-tpot-hp-connector/src/stix/
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
    "Cowrie":     "Cowrie SSH/Telnet Attack - {ip} ({n} session{s})",
    "Suricata":   "Suricata Alert - {ip} ({n} alert{s})",
    "Honeytrap":  "Honeytrap Probe - {ip} ({n} probe{s})",
    "Dionaea":    "Dionaea Malware Drop - {ip} ({n} drop{s})",
    "Heralding":  "Heralding Credential Attack - {ip} ({n} session{s})",
    "Mailoney":   "Mailoney SMTP Abuse - {ip} ({n} session{s})",
    "ConPot":     "ConPot ICS Probe - {ip} ({n} probe{s})",
    "Tanner":     "Tanner Web Attack - {ip} ({n} session{s})",
    "H0neytr4p":  "H0neytr4p Web Probe - {ip} ({n} probe{s})",
    "__fallback__": "Honeypot Activity (unknown type) - {ip} ({n} event{s})",
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
    ) -> Optional[dict]:
        if not country_code:
            return None
        cc = country_code.upper()
        obj = {
            "type": "location",
            "id": generate_country_location_id(cc),
            "country": cc,
            "name": country_name or cc,
        }
        return self._dedup(self._stamp(obj, add_confidence=False))

    def build_city_location(
        self,
        country_code: str,
        city: str,
    ) -> Optional[dict]:
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

    def build_attack_pattern(self, name: str, mitre_id: Optional[str] = None) -> dict:
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
        }
        return self._dedup(self._stamp(obj))

    def build_cryptographic_key(self, value: str) -> Optional[dict]:
        if not value:
            return None
        obj = {
            "type": "cryptographic-key",   # correct type per LESSONS §8.4
            "id": generate_cryptographic_key_id(value),
            "value": value,
        }
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
        /home/mike/poc/tsec-tpot-connectors/tsec-tpot-hp-connector/src/stix/indicators.py
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

        WARNING: per LESSONS_LEARNED §7.1 we do NOT emit a per-IP per-cycle
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
        indicator_id: str,
        sensor_hostname: str,
        session: AttackSession,
        *,
        count: int = 1,
        description: Optional[str] = None,
    ) -> Optional[dict]:
        """Sighting SDO — per V1_SPEC §4 'sighting target=Indicator,
        where=sensor Identity'.

        Per LESSONS_LEARNED §7.1: putting per-session activity summaries
        in the Sighting `description` is the preferred place for
        low-signal-per-event protocols (Honeytrap probe payload, Fallback
        unknown-type blurb). Beats spewing 50k+ Notes/day that nobody
        reads. Cowrie/SSH sessions still get their own Notes — those
        are the genuinely-per-session content the lesson called out
        as the carve-out.
        """
        if not (indicator_id and sensor_hostname):
            return None
        sensor_id = generate_sensor_id(sensor_hostname)
        obj = {
            "type": "sighting",
            "id": generate_sighting_id(sensor_hostname, session.session_id),
            "sighting_of_ref": indicator_id,
            "where_sighted_refs": [sensor_id],
            "first_seen": session.first_seen.isoformat(),
            "last_seen": session.last_seen.isoformat(),
            "count": count,
        }
        if description:
            obj["description"] = description
        return self._dedup(self._stamp(obj))

    # ──────────────────────────────────────────────────────────────────
    # High-level convenience: build the common entity bundle for one
    # session, regardless of substance.  Parsers can then layer their
    # protocol-specific extras on top.
    # ──────────────────────────────────────────────────────────────────

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
            country = self.build_country_location(event.src_country_code, event.src_country_name)
            if country:
                out.append(country)
                rel = self.build_relationship(
                    ipv4["id"], "located-at", country["id"],
                    description=f"{event.src_ip} geolocated to {event.src_country_code}",
                )
                if rel:
                    out.append(rel)
            if event.src_city:
                city = self.build_city_location(event.src_country_code, event.src_city)
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
            # Sighting
            sighting = self.build_sighting(
                ip_ind["id"], session.sensor_hostname, session, count=session.event_count,
            )
            if sighting:
                out.append(sighting)

        return out
