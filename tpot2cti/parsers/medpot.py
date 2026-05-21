"""Medpot parser — HL7 medical-messaging honeypot.

Medpot emulates a Health Level 7 (HL7) v2 messaging endpoint —
the MLLP-framed text protocol that hospital information systems use
to exchange ADT (admit/discharge/transfer), ORM (order), ORU (result)
and similar clinical messages.  Internet-exposed HL7 endpoints are
not supposed to exist; every probe is worth recording in full.

Per V1_SPEC.md §5.9:

  T-Pot doc fields used:
    src_ip, dst_port, msg_type

  Event correlation:
    each ES doc is a discrete HL7 message; default one-event-per-
    session correlator applies.

  STIX emitted per session (built downstream by the publisher):
    IPv4-Addr, AutonomousSystem, Location (via build_attacker_context),
    Indicator(ip), Sighting,
    Note with the HL7 message type (ADT^A01, ORM^O01, ...).

Per docs/LESSONS_LEARNED_FROM_V0.md §2 (substance filter):
    HL7 traffic from random internet hosts is by definition
    anomalous.  `has_substance()` always returns True.

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
        """Every Medpot probe is substantive.

        Per V1_SPEC §5.9 and the Phase-4 instructions: HL7 traffic
        from strangers on the internet is by definition anomalous,
        so each Medpot doc warrants the full STIX SDO graph.

        See docs/LESSONS_LEARNED_FROM_V0.md §2: per-parser substance
        decisions, not a global rule.  For Medpot the answer is
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
register(MedpotParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = MedpotParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: ADT^A01 admit message ──────────────────────────────────
    adt_doc = {
        "@timestamp": now.isoformat(),
        "type": "Medpot",
        "src_ip": "203.0.113.77",
        "src_port": 50050,
        "dst_port": 2575,
        "msg_type": "ADT^A01",
        "t-pot_hostname": "node1",
        "geoip": {
            "country_iso_code": "DE",
            "country_name": "Germany",
            "asn": 3320,
            "organization": "Deutsche Telekom AG",
        },
    }

    # ── Case 2: ORM^O01 order message ──────────────────────────────────
    orm_doc = {
        "@timestamp": now.isoformat(),
        "type": "Medpot",
        "src_ip": "198.51.100.31",
        "dst_port": 2575,
        "msg_type": "ORM^O01",
    }

    # ── Case 3: no msg_type — still substantive ────────────────────────
    bare_doc = {
        "@timestamp": now.isoformat(),
        "type": "Medpot",
        "src_ip": "192.0.2.42",
    }

    docs = [adt_doc, orm_doc, bare_doc]
    events = [parser.parse(d) for d in docs]
    assert all(e is not None for e in events), "parse() returned None unexpectedly"
    print(f"parsed {len(events)} Medpot events")
    for e in events:
        print(
            f"  src_ip={e.src_ip:<16} dst_port={e.dst_port} "
            f"msg_type={e.meta.get('msg_type')!r}"
        )

    sessions = parser.correlate(events)
    assert len(sessions) == 3, f"expected 3 sessions, got {len(sessions)}"
    print(f"\ncorrelated into {len(sessions)} session(s)")

    for s in sessions:
        sub = parser.has_substance(s)
        print(
            f"  session src_ip={s.src_ip:<16} "
            f"msg_type={s.meta.get('msg_type')!r:<12} "
            f"has_substance={sub}"
        )
        # Every Medpot session is substantive per V1_SPEC §5.9.
        assert sub is True, f"Medpot session {s.src_ip} not substantive!"

    # First session should carry msg_type on session.meta
    assert sessions[0].meta.get("msg_type") == "ADT^A01"
    assert sessions[1].meta.get("msg_type") == "ORM^O01"
    # bare_doc has no msg_type — meta should not contain it
    assert "msg_type" not in sessions[2].meta

    # Malformed docs return None
    assert parser.parse({}) is None
    assert parser.parse({"src_ip": "1.2.3.4"}) is None

    print("\nOK")
