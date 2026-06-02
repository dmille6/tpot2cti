"""Dicompot parser — DICOM medical-imaging honeypot.

See docs/parsers/dicompot.md for protocol/ES-field/STIX/substance notes.
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
TYPE_NAME = "Dicompot"

#: Default destination port for DICOM if the doc didn't carry one.
DEFAULT_DICOM_PORT = 11112

#: DICOM command types we expect to see in `command_type`.  Listed
#: here purely for documentation — we pass the value through verbatim
#: regardless.
_KNOWN_DICOM_COMMANDS: frozenset[str] = frozenset({
    "C-ECHO",
    "C-STORE",
    "C-FIND",
    "C-GET",
    "C-MOVE",
    "C-CANCEL",
    "N-EVENT-REPORT",
    "N-GET",
    "N-SET",
    "N-ACTION",
    "N-CREATE",
    "N-DELETE",
})


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class DicompotParser(BaseParser):
    """Parser for T-Pot's Dicompot DICOM medical-imaging honeypot.

    Per V1_SPEC §5.8 every DICOM probe is substantive.  We use the
    default one-event-per-session correlator (each ES doc is a discrete
    DICOM transaction) and override `has_substance()` to always return
    True.
    """

    type_name = TYPE_NAME

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert one Dicompot ES doc into a ParsedEvent.

        Captures the three DICOM-specific fields in `event.meta`:
        - `aet_called`  — the called Application Entity Title (the AET
          the attacker is trying to reach — usually a hard-coded value
          like "ANY-SCP" or a guessed PACS name)
        - `aet_calling` — the calling AET the attacker self-identified
          with
        - `command_type` — the DICOM command (C-ECHO, C-STORE, ...)

        Tolerates missing fields gracefully — logs at DEBUG and skips
        rather than raising.
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("dicompot: doc missing src_ip; skipping")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("dicompot: doc missing/unparseable @timestamp; skipping")
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
                     or DEFAULT_DICOM_PORT,
            dst_ip=doc.get("dst_ip") or doc.get("dest_ip"),
            protocol="dicom",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── DICOM-specific metadata into event.meta ────────────────────
        # All three fields are optional in the wild; we record whatever
        # is present.  Empty-string values are preserved as-is so the
        # publisher's Note can distinguish "field absent" from "field
        # present but empty" — both are diagnostic.
        for field in ("aet_called", "aet_calling", "command_type"):
            if field in doc:
                event.meta[field] = str(doc.get(field) or "")

        # Normalize the command_type to upper-case for downstream
        # comparison (the DICOM spec uses uppercase, but T-Pot mappings
        # vary).
        if cmd := event.meta.get("command_type"):
            event.meta["command_type"] = cmd.upper()

        # Optional session id (some Dicompot builds carry one)
        if (sid := doc.get("session") or doc.get("session_id")):
            event.session_id = str(sid)

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — default one-event-per-session, with session.meta
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events):
        """One-event-per-session; mirror DICOM meta onto the session.

        The publisher needs `command_type` / `aet_called` /
        `aet_calling` on the session itself to build a Note without
        peeking into events[0].meta.  We mirror the three fields onto
        `session.meta` here.
        """
        sessions: list[AttackSession] = []
        for ev in events:
            s = AttackSession.from_event(ev)
            for k in ("aet_called", "aet_calling", "command_type"):
                if v := ev.meta.get(k):
                    s.meta.setdefault(k, v)
            sessions.append(s)
        return sessions

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — ALWAYS True for Dicompot
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Every DICOM probe is substantive.

        Per V1_SPEC §5.8 and the Phase-4 instructions: medical-imaging
        protocol probes are rare on the open internet and each one is
        worth a full STIX SDO graph (IPv4 + AS + Location + Indicator +
        Sighting + Note + AttackPattern("medical-imaging-probe")).

        See docs/LESSONS_LEARNED_FROM_V0.md §2: per-parser substance
        decisions, not a global rule.  For Dicompot the answer is
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
register(DicompotParser())
