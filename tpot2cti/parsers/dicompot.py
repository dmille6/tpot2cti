"""Dicompot parser — DICOM medical-imaging honeypot.

Dicompot emulates a DICOM Application Entity on TCP/11112, the
standard port for medical-imaging endpoints (PACS servers, CT/MRI
modalities, viewer workstations).  Like the ICS protocols handled by
ConPot, DICOM has no legitimate reason to be touched by random
internet hosts — every probe is signal.

Per V1_SPEC.md §5.8:

  T-Pot doc fields used:
    src_ip, aet_called, aet_calling, command_type

  Event correlation:
    each ES doc is a discrete DICOM probe; default one-event-per-
    session correlator applies.

  STIX emitted per session (built downstream by the publisher):
    IPv4-Addr, AutonomousSystem, Location (via build_attacker_context),
    Indicator(ip), Sighting,
    Note with DICOM command details (C-STORE, C-FIND, ...),
    AttackPattern("medical-imaging-probe") via Indicator.

  Relationships:
    Indicator → indicates → AttackPattern.

Per docs/LESSONS_LEARNED_FROM_V0.md §2 (substance filter):
    DICOM probes are rare enough that every one is interesting.
    `has_substance()` is overridden to always return True.

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


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = DicompotParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: C-ECHO ping from a scanner ─────────────────────────────
    echo_doc = {
        "@timestamp": now.isoformat(),
        "type": "Dicompot",
        "src_ip": "203.0.113.50",
        "src_port": 51234,
        "dst_port": 11112,
        "t-pot_hostname": "node1",
        "aet_called": "ANY-SCP",
        "aet_calling": "FINDSCU",
        "command_type": "c-echo",
        "geoip": {
            "country_iso_code": "CN",
            "country_name": "China",
            "asn": 4134,
            "organization": "ChinaNet",
        },
    }

    # ── Case 2: C-FIND query (substantive even if results empty) ───────
    find_doc = {
        "@timestamp": now.isoformat(),
        "type": "Dicompot",
        "src_ip": "198.51.100.20",
        "dst_port": 11112,
        "aet_called": "PACS",
        "aet_calling": "QRSCU",
        "command_type": "C-FIND",
    }

    # ── Case 3: minimal probe — just a connection, no AET ──────────────
    minimal_doc = {
        "@timestamp": now.isoformat(),
        "type": "Dicompot",
        "src_ip": "192.0.2.7",
    }

    docs = [echo_doc, find_doc, minimal_doc]
    events = [parser.parse(d) for d in docs]
    assert all(e is not None for e in events), "parse() returned None unexpectedly"
    print(f"parsed {len(events)} Dicompot events")
    for e in events:
        print(
            f"  src_ip={e.src_ip:<16} command_type={e.meta.get('command_type')!r:<10} "
            f"aet_called={e.meta.get('aet_called')!r}"
        )

    # Confirm command_type was upper-cased
    assert events[0].meta["command_type"] == "C-ECHO", (
        f"command_type should be uppercased; got {events[0].meta['command_type']!r}"
    )

    sessions = parser.correlate(events)
    assert len(sessions) == 3, f"expected 3 sessions, got {len(sessions)}"
    print(f"\ncorrelated into {len(sessions)} session(s)")

    for s in sessions:
        sub = parser.has_substance(s)
        print(
            f"  session src_ip={s.src_ip:<16} "
            f"command_type={s.meta.get('command_type')!r:<10} "
            f"has_substance={sub}"
        )
        # Every Dicompot session is substantive per V1_SPEC §5.8.
        assert sub is True, f"Dicompot session {s.src_ip} not substantive!"

    # Session for echo_doc should carry aet/command on session.meta.
    s0 = sessions[0]
    assert s0.meta.get("command_type") == "C-ECHO"
    assert s0.meta.get("aet_called") == "ANY-SCP"
    assert s0.meta.get("aet_calling") == "FINDSCU"

    # Malformed docs return None
    assert parser.parse({}) is None
    assert parser.parse({"src_ip": "1.2.3.4"}) is None

    print("\nOK")
