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
from datetime import datetime, timezone
from typing import Optional

from tpot2cti.config import Config
from tpot2cti.parsers.base import AttackSession, ParsedEvent
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

    def build_ipv4(self, ip: str) -> Optional[dict]:
        if not ip or not _IPV4_RE.match(ip):
            return None
        # SCOs don't carry created_by_ref / markings per pure STIX 2.1 spec,
        # but OpenCTI's `x_opencti_*` extensions DO carry these, so we
        # include them (OpenCTI ignores them on pure SCOs without breakage).
        obj = {
            "type": "ipv4-addr",
            "id": generate_ipv4_id(ip),
            "value": ip,
        }
        return self._dedup(self._stamp(obj))

    def build_file(self, sha256: str, *, name: Optional[str] = None,
                    size: Optional[int] = None) -> Optional[dict]:
        if not sha256:
            return None
        obj = {
            "type": "file",
            "id": generate_file_id(sha256),
            "hashes": {"SHA-256": sha256.lower()},
        }
        if name:
            obj["name"] = name
        if size is not None:
            obj["size"] = int(size)
        return self._dedup(self._stamp(obj))

    def build_url(self, url: str) -> Optional[dict]:
        if not url:
            return None
        obj = {
            "type": "url",
            "id": generate_url_id(url),
            "value": url,
        }
        return self._dedup(self._stamp(obj))

    def build_domain(self, fqdn: str) -> Optional[dict]:
        if not fqdn:
            return None
        obj = {
            "type": "domain-name",
            "id": generate_domain_id(fqdn),
            "value": fqdn.lower(),
        }
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

    def build_ip_indicator(self, ip: str) -> Optional[dict]:
        if not ip or not _IPV4_RE.match(ip):
            return None
        obj = {
            "type": "indicator",
            "id": generate_ip_indicator_id(ip),
            "name": f"Honeypot attacker IP: {ip}",
            "pattern_type": "stix",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "valid_from": self._now_iso,
            "indicator_types": ["malicious-activity"],
        }
        return self._dedup(self._stamp(obj))

    def build_file_indicator(self, sha256: str, *, name: Optional[str] = None) -> Optional[dict]:
        if not sha256:
            return None
        obj = {
            "type": "indicator",
            "id": generate_file_indicator_id(sha256),
            "name": name or f"Honeypot file: {sha256[:16]}…",
            "pattern_type": "stix",
            "pattern": f"[file:hashes.'SHA-256' = '{sha256.lower()}']",
            "valid_from": self._now_iso,
            "indicator_types": ["malicious-activity"],
        }
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

    def build_attacker_context(self, event: ParsedEvent) -> list[dict]:
        """Build the IPv4 + Location + AutonomousSystem + relationships
        triple for one event's source.

        Returns a list of STIX dicts (skipping anything already-emitted
        within this bundle).  Used by both the driveby and substantive
        code paths.
        """
        out: list[dict] = []
        ipv4 = self.build_ipv4(event.src_ip)
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
            asn = self.build_autonomous_system(event.src_asn, event.src_as_org)
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
        out.extend(self.build_attacker_context(first))

        # IP Indicator + Sighting
        ip_ind = self.build_ip_indicator(session.src_ip)
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
