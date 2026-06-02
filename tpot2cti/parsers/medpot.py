"""Medpot parser — HL7 medical-messaging honeypot.

Parses T-Pot Medpot docs (HL7 v2 MLLP clinical messages) into ParsedEvents
and one-event-per-session AttackSessions; every probe is substantive. STIX
is built downstream in tpot2cti/stix/builder.py from session.meta.

See docs/PARSERS.md (Medpot) for protocol background, ES fields, the emitted
STIX graph, and substance rationale.
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
TYPE_NAME = "Medpot"

#: Conventional HL7 MLLP listening port.
DEFAULT_HL7_PORT = 2575


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class MedpotParser(BaseParser):
    """Parser for T-Pot's Medpot HL7 medical-messaging honeypot.

    Per V1_SPEC §5.9 every HL7 message hitting an internet-exposed
    Medpot instance is substantive.  We use the default one-event-per-
    session correlator and override `has_substance()` to always return
    True.
    """

    type_name = TYPE_NAME

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert one Medpot ES doc into a ParsedEvent.

        Captures the HL7 message type (e.g. "ADT^A01", "ORM^O01") in
        `event.meta["msg_type"]`.  Tolerates missing fields gracefully
        — logs at DEBUG and skips rather than raising (per V1_SPEC §7).
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("medpot: doc missing src_ip; skipping")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("medpot: doc missing/unparseable @timestamp; skipping")
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
                     or DEFAULT_HL7_PORT,
            dst_ip=doc.get("dst_ip") or doc.get("dest_ip"),
            protocol="hl7",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── HL7 message type ───────────────────────────────────────────
        # The HL7 message type is a string like "ADT^A01" — message type
        # plus event trigger, caret-separated.  Some Medpot builds emit
        # just the family ("ADT") with no trigger; we preserve whatever
        # the doc carries.
        if (mt := doc.get("msg_type")) is not None:
            event.meta["msg_type"] = str(mt)

        # Optional session id (rare in Medpot)
        if (sid := doc.get("session") or doc.get("session_id")):
            event.session_id = str(sid)

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — default one-event-per-session, with session.meta
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events):
        """One-event-per-session; mirror msg_type onto the session.

        The publisher renders a Note from `session.meta["msg_type"]`;
        we put it there so the builder doesn't have to peek into
        events[0].meta.
        """
        sessions: list[AttackSession] = []
        for ev in events:
            s = AttackSession.from_event(ev)
            if msg_type := ev.meta.get("msg_type"):
                s.meta.setdefault("msg_type", msg_type)
            sessions.append(s)
        return sessions

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — ALWAYS True for Medpot
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Always True — internet HL7 traffic is anomalous by definition.

        See docs/PARSERS.md (Medpot).
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
register(MedpotParser())
