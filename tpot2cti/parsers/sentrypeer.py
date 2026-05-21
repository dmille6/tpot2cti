"""SentryPeer parser — SIP / VoIP honeypot.

SentryPeer impersonates a SIP server and records the REGISTER / INVITE /
OPTIONS traffic that arrives from the open internet.  The interesting
signal is who is probing the SIP port (5060 udp/tcp), what SIP method
they're using, and — for INVITEs — the dialed number, which is a strong
toll-fraud indicator when it looks international.

Per V1_SPEC.md §5.19:

  T-Pot doc fields used:
    src_ip, sip_method, called_number, caller

  Event correlation:
    each ES doc is a discrete SIP transaction; default one-event-per-
    session correlator applies.

  STIX emitted per session (built downstream by the publisher):
    IPv4-Addr, AutonomousSystem, Location (via build_attacker_context),
    Indicator(ip), Sighting,
    Note with the SIP method + dialed number.

Per docs/LESSONS_LEARNED_FROM_V0.md §2 (substance filter):
    Internet-exposed SIP traffic from strangers is by definition
    anomalous — every probe is signal.  `has_substance()` always
    returns True.

This parser only `parse()`s and `correlate()`s; the STIX bundle is
built by the publisher (tpot2cti/stix/builder.py) using the metadata
we populate on the session.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: T-Pot type field value this parser handles.
TYPE_NAME = "Sentrypeer"

#: Conventional SIP listening port (UDP/TCP).
DEFAULT_SIP_PORT = 5060

#: SIP method values we expect to see.  Used only to canonicalize case;
#: anything outside the set is preserved verbatim.
_KNOWN_SIP_METHODS: frozenset[str] = frozenset({
    "REGISTER", "INVITE", "OPTIONS", "ACK", "BYE", "CANCEL",
    "SUBSCRIBE", "NOTIFY", "PUBLISH", "REFER", "MESSAGE", "INFO",
    "UPDATE", "PRACK",
})

#: A "dialed number" that begins with "+", "00", or a country-code-shaped
#: prefix is treated as an international call and flagged as a toll-fraud
#: indicator on the event meta.  We deliberately keep this conservative —
#: false positives are cheap (just an extra meta flag); the actual STIX
#: shape is the same either way.
_INTL_NUMBER_RE = re.compile(r"^\s*(?:\+|00)\d{4,}")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class SentryPeerParser(BaseParser):
    """Parser for T-Pot's SentryPeer SIP honeypot.

    Per V1_SPEC §5.19 every SIP transaction reaching the honeypot is
    substantive.  We use the default one-event-per-session correlator
    and override `has_substance()` to always return True.
    """

    type_name = TYPE_NAME

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert one SentryPeer ES doc into a ParsedEvent.

        Captures the SIP method (e.g. "REGISTER", "INVITE"), the dialed
        number (called_number), and the caller in `event.meta`.  Sets
        `event.meta["is_intl_dial"] = True` when the called_number
        matches the international-prefix pattern — useful downstream for
        labelling the Sighting as toll-fraud-related.

        Tolerates missing fields gracefully — logs at DEBUG and skips
        rather than raising (per V1_SPEC §7).
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("sentrypeer: doc missing src_ip; skipping")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("sentrypeer: doc missing/unparseable @timestamp; skipping")
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
                     or DEFAULT_SIP_PORT,
            dst_ip=doc.get("dst_ip") or doc.get("dest_ip"),
            protocol="sip",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── SIP method ─────────────────────────────────────────────────
        raw_method = doc.get("sip_method") or doc.get("method")
        if raw_method:
            method = str(raw_method).strip().upper()
            event.meta["sip_method"] = method
            if method not in _KNOWN_SIP_METHODS:
                logger.debug(
                    f"sentrypeer: unrecognized sip_method {method!r} — "
                    f"preserving verbatim"
                )

        # ── Called number / caller ─────────────────────────────────────
        if (cn := doc.get("called_number")) is not None:
            cn_s = str(cn).strip()
            event.meta["called_number"] = cn_s
            if _INTL_NUMBER_RE.match(cn_s):
                event.meta["is_intl_dial"] = True
        if (cr := doc.get("caller")) is not None:
            event.meta["caller"] = str(cr).strip()

        # Optional session id (rare in SentryPeer)
        if (sid := doc.get("session") or doc.get("session_id")):
            event.session_id = str(sid)

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — default one-event-per-session, with session.meta
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events):
        """One-event-per-session; mirror SIP details onto the session.

        The publisher renders a Note from `session.meta`; we put the
        SIP method / called_number / caller / is_intl_dial there so the
        builder doesn't have to peek into events[0].meta.
        """
        sessions: list[AttackSession] = []
        for ev in events:
            s = AttackSession.from_event(ev)
            for k in ("sip_method", "called_number", "caller", "is_intl_dial"):
                if k in ev.meta:
                    s.meta.setdefault(k, ev.meta[k])
            sessions.append(s)
        return sessions

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — ALWAYS True for SentryPeer
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Every SentryPeer probe is substantive.

        Per V1_SPEC §5.19 and the Phase-4 instructions: SIP traffic
        from strangers on the internet is by definition anomalous, so
        each doc warrants the full STIX SDO graph.

        See docs/LESSONS_LEARNED_FROM_V0.md §2: per-parser substance
        decisions, not a global rule.  For SentryPeer the answer is
        always yes — toll-fraud probing and SIP-stack fingerprinting
        are both valuable signals even when no "dial" happens.
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
register(SentryPeerParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = SentryPeerParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: REGISTER probe (no dialed number) ──────────────────────
    register_doc = {
        "@timestamp": now.isoformat(),
        "type": "Sentrypeer",
        "src_ip": "203.0.113.77",
        "src_port": 50050,
        "dst_port": 5060,
        "sip_method": "REGISTER",
        "caller": "1001",
        "t-pot_hostname": "node1",
        "geoip": {
            "country_iso_code": "NL",
            "country_name": "Netherlands",
            "asn": 16276,
            "organization": "OVH",
        },
    }

    # ── Case 2: INVITE to international number (toll-fraud signal) ─────
    invite_intl_doc = {
        "@timestamp": now.isoformat(),
        "type": "Sentrypeer",
        "src_ip": "198.51.100.31",
        "dst_port": 5060,
        "sip_method": "INVITE",
        "called_number": "+447700900123",
        "caller": "9999",
    }

    # ── Case 3: INVITE to domestic number (no intl flag) ───────────────
    invite_local_doc = {
        "@timestamp": now.isoformat(),
        "type": "Sentrypeer",
        "src_ip": "198.51.100.31",
        "dst_port": 5060,
        "sip_method": "INVITE",
        "called_number": "5551234",
    }

    # ── Case 4: bare doc (no method, no number) — still substantive ────
    bare_doc = {
        "@timestamp": now.isoformat(),
        "type": "Sentrypeer",
        "src_ip": "192.0.2.42",
    }

    docs = [register_doc, invite_intl_doc, invite_local_doc, bare_doc]
    events = [parser.parse(d) for d in docs]
    assert all(e is not None for e in events), "parse() returned None unexpectedly"
    print(f"parsed {len(events)} SentryPeer events")
    for e in events:
        print(
            f"  src_ip={e.src_ip:<16} dst_port={e.dst_port} "
            f"method={e.meta.get('sip_method')!r:<10} "
            f"called={e.meta.get('called_number')!r:<18} "
            f"intl={e.meta.get('is_intl_dial')}"
        )

    sessions = parser.correlate(events)
    assert len(sessions) == 4, f"expected 4 sessions, got {len(sessions)}"
    print(f"\ncorrelated into {len(sessions)} session(s)")

    for s in sessions:
        sub = parser.has_substance(s)
        print(
            f"  session src_ip={s.src_ip:<16} "
            f"method={s.meta.get('sip_method')!r:<10} "
            f"has_substance={sub}"
        )
        assert sub is True, f"SentryPeer session {s.src_ip} not substantive!"

    # ── Per-session assertions ─────────────────────────────────────────
    # REGISTER: method present, no called_number, no intl flag
    assert sessions[0].meta.get("sip_method") == "REGISTER"
    assert "called_number" not in sessions[0].meta
    assert sessions[0].meta.get("caller") == "1001"

    # INVITE intl: intl flag set
    assert sessions[1].meta.get("sip_method") == "INVITE"
    assert sessions[1].meta.get("called_number") == "+447700900123"
    assert sessions[1].meta.get("is_intl_dial") is True

    # INVITE local: no intl flag
    assert sessions[2].meta.get("sip_method") == "INVITE"
    assert sessions[2].meta.get("called_number") == "5551234"
    assert "is_intl_dial" not in sessions[2].meta

    # bare doc: no SIP keys on session.meta
    assert "sip_method" not in sessions[3].meta
    assert "called_number" not in sessions[3].meta

    # Method case-normalization
    lowercase_doc = {
        "@timestamp": now.isoformat(),
        "type": "Sentrypeer",
        "src_ip": "192.0.2.99",
        "sip_method": "invite",
    }
    ev_lc = parser.parse(lowercase_doc)
    assert ev_lc is not None
    assert ev_lc.meta.get("sip_method") == "INVITE", \
        f"sip_method not upper-cased: {ev_lc.meta.get('sip_method')!r}"

    # 00-prefix is also treated as international
    intl_00_doc = {
        "@timestamp": now.isoformat(),
        "type": "Sentrypeer",
        "src_ip": "192.0.2.100",
        "sip_method": "INVITE",
        "called_number": "00441234567",
    }
    ev_00 = parser.parse(intl_00_doc)
    assert ev_00 is not None
    assert ev_00.meta.get("is_intl_dial") is True, \
        "00-prefix should be detected as international"

    # Malformed docs return None
    assert parser.parse({}) is None
    assert parser.parse({"src_ip": "1.2.3.4"}) is None  # no @timestamp

    print("\nOK")
