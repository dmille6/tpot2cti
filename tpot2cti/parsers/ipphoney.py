"""Ipphoney parser — Internet Printing Protocol (IPP) honeypot.

See docs/parsers/ipphoney.md for protocol/ES-field/STIX/substance notes.
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
