"""Ipphoney parser — Internet Printing Protocol (IPP) honeypot.

IppHoney emulates an IPP server (TCP/631) — the protocol CUPS and
modern network printers use.  Most internet-exposed printers have
been the subject of public defacement and PII-leak incidents over
the years, so any IPP probe from the open internet is worth a full
STIX bundle even though the probe traffic itself is small.

Per V1_SPEC.md §5.15:

  T-Pot doc fields used:
    src_ip, request_attributes

  Event correlation:
    each ES doc is a discrete IPP request; default one-event-per-
    session correlator applies.

  STIX emitted per session (built downstream by the publisher):
    IPv4-Addr, AutonomousSystem, Location (via build_attacker_context),
    Indicator(ip), Sighting.
    (No Note SDO is mandated by V1_SPEC §5.15, but the publisher may
     choose to emit one when request_attributes is interesting — we
     mirror the attributes onto session.meta to make that possible
     without parser changes.)

Per docs/LESSONS_LEARNED_FROM_V0.md §2 (substance filter):
    IPP probes are rare enough that every one is worth recording.
    `has_substance()` always returns True.

This parser only `parse()`s and `correlate()`s; the STIX bundle is
built by the publisher (tpot2cti/stix/builder.py) using the metadata
we populate on the session.
"""

from __future__ import annotations

import logging
from typing import Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: T-Pot type field value this parser handles.
TYPE_NAME = "Ipphoney"

#: Conventional IPP listening port.
DEFAULT_IPP_PORT = 631

#: Hard cap on the rendered length of the `request_attributes` blob
#: preserved in meta — prevents one outlier from blowing up a STIX
#: bundle.  Cf. docs/LESSONS_LEARNED_FROM_V0.md §6 on bundle size.
ATTRIBUTES_BLOB_CAP = 2048


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class IppHoneyParser(BaseParser):
    """Parser for T-Pot's IppHoney IPP honeypot.

    Per V1_SPEC §5.15 every IPP probe is substantive (IPP probes are
    rare → each one worth recording in full).  We use the default
    one-event-per-session correlator and override `has_substance()` to
    always return True.
    """

    type_name = TYPE_NAME

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert one IppHoney ES doc into a ParsedEvent.

        Captures the IPP request attributes blob in
        `event.meta["request_attributes"]`.  The blob can be a dict
        (parsed IPP attribute groups) or a string (raw textual
        rendering) depending on the T-Pot mapping version; we
        normalize structured forms to a deterministic JSON string and
        cap the length at `ATTRIBUTES_BLOB_CAP`.

        Tolerates missing fields gracefully — logs at DEBUG and skips
        rather than raising (per V1_SPEC §7).
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("ipphoney: doc missing src_ip; skipping")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("ipphoney: doc missing/unparseable @timestamp; skipping")
            return None

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or doc.get("hostname")
                or "unknown"
            ),
            event_type=TYPE_NAME,
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int(doc.get("dst_port") or doc.get("dest_port"))
                     or DEFAULT_IPP_PORT,
            dst_ip=doc.get("dst_ip") or doc.get("dest_ip"),
            protocol="ipp",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── IPP request attributes ─────────────────────────────────────
        raw_attrs = doc.get("request_attributes")
        if raw_attrs is not None:
            if isinstance(raw_attrs, (dict, list)):
                # Render structured forms deterministically so the
                # downstream Note body / dedup hash is stable across
                # importer runs.
                try:
                    import json
                    attrs_str = json.dumps(raw_attrs, sort_keys=True, default=str)
                except (TypeError, ValueError) as e:
                    logger.debug(f"ipphoney: could not json-render request_attributes: {e}")
                    attrs_str = str(raw_attrs)
            else:
                attrs_str = str(raw_attrs)

            if len(attrs_str) > ATTRIBUTES_BLOB_CAP:
                event.meta["request_attributes_truncated"] = True
                attrs_str = attrs_str[:ATTRIBUTES_BLOB_CAP]
            event.meta["request_attributes"] = attrs_str

        # Optional session id (rare in Ipphoney)
        if (sid := doc.get("session") or doc.get("session_id")):
            event.session_id = str(sid)

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — default one-event-per-session, with session.meta
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events):
        """One-event-per-session; mirror request_attributes onto session.

        The publisher's Note builder consumes `session.meta` directly;
        mirroring here keeps the builder protocol-agnostic.
        """
        sessions: list[AttackSession] = []
        for ev in events:
            s = AttackSession.from_event(ev)
            if attrs := ev.meta.get("request_attributes"):
                s.meta.setdefault("request_attributes", attrs)
            if ev.meta.get("request_attributes_truncated"):
                s.meta["request_attributes_truncated"] = True
            sessions.append(s)
        return sessions

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — ALWAYS True for Ipphoney
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Every IPP probe is substantive.

        Per V1_SPEC §5.15 and the Phase-4 instructions: IPP traffic
        from random internet hosts is rare and worth recording in
        full (IPv4 + AS + Location + Indicator + Sighting).

        See docs/LESSONS_LEARNED_FROM_V0.md §2: per-parser substance
        decisions, not a global rule.  For Ipphoney the answer is
        always yes.
        """
        return True

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


# Register on import
register(IppHoneyParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = IppHoneyParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: Get-Printer-Attributes probe with structured attrs ─────
    get_attrs_doc = {
        "@timestamp": now.isoformat(),
        "type": "Ipphoney",
        "src_ip": "203.0.113.91",
        "src_port": 53000,
        "dst_port": 631,
        "t-pot_hostname": "node1",
        "request_attributes": {
            "operation-id": "0x000B",
            "attributes-charset": "utf-8",
            "attributes-natural-language": "en-us",
            "printer-uri": "ipp://victim.example.com:631/printers/main",
        },
        "geoip": {
            "country_iso_code": "BR",
            "country_name": "Brazil",
            "asn": 7738,
            "organization": "Telemar Norte Leste",
        },
    }

    # ── Case 2: minimal probe with no request_attributes ───────────────
    minimal_doc = {
        "@timestamp": now.isoformat(),
        "type": "Ipphoney",
        "src_ip": "198.51.100.55",
        "dst_port": 631,
    }

    # ── Case 3: oversized request_attributes — should truncate ─────────
    big_attrs_doc = {
        "@timestamp": now.isoformat(),
        "type": "Ipphoney",
        "src_ip": "192.0.2.123",
        "request_attributes": "A" * (ATTRIBUTES_BLOB_CAP + 500),
    }

    docs = [get_attrs_doc, minimal_doc, big_attrs_doc]
    events = [parser.parse(d) for d in docs]
    assert all(e is not None for e in events), "parse() returned None unexpectedly"
    print(f"parsed {len(events)} Ipphoney events")
    for e in events:
        attrs = e.meta.get("request_attributes")
        attrs_repr = (attrs[:60] + "...") if attrs and len(attrs) > 60 else attrs
        print(
            f"  src_ip={e.src_ip:<16} dst_port={e.dst_port} "
            f"attrs={attrs_repr!r}"
        )

    # The oversized doc should have been truncated at the cap.
    assert events[2].meta.get("request_attributes_truncated") is True
    assert len(events[2].meta["request_attributes"]) == ATTRIBUTES_BLOB_CAP

    sessions = parser.correlate(events)
    assert len(sessions) == 3, f"expected 3 sessions, got {len(sessions)}"
    print(f"\ncorrelated into {len(sessions)} session(s)")

    for s in sessions:
        sub = parser.has_substance(s)
        has_attrs = "request_attributes" in s.meta
        print(
            f"  session src_ip={s.src_ip:<16} "
            f"has_attrs={has_attrs} "
            f"has_substance={sub}"
        )
        # Every Ipphoney session is substantive per V1_SPEC §5.15.
        assert sub is True, f"Ipphoney session {s.src_ip} not substantive!"

    # First session must carry the IPP attributes on session.meta.
    assert "request_attributes" in sessions[0].meta
    # Truncation flag carries through correlate().
    assert sessions[2].meta.get("request_attributes_truncated") is True

    # Malformed docs return None
    assert parser.parse({}) is None
    assert parser.parse({"src_ip": "1.2.3.4"}) is None

    print("\nOK")
