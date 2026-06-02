"""SentryPeer parser — SIP / VoIP honeypot.

See docs/parsers/sentrypeer.md for protocol/ES-field/STIX/substance notes.
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

        # ── SIP fingerprint surface (per 2026-05-22 field-name audit) ──
        # Real SentryPeer data ships `sip_user_agent` + `sip_message` +
        # `transport_type` (UDP/TCP/TLS) on 100% of probes — useful for
        # tool clustering (e.g. sipvicious vs pplsip vs friendly-scanner)
        # and Note enrichment. Pre-audit the parser read none of these.
        if (ua := doc.get("sip_user_agent")) is not None:
            event.meta["sip_user_agent"] = str(ua).strip()
        if (msg := doc.get("sip_message")) is not None:
            # Cap at 1KB so a pathological INVITE doesn't blow up the
            # Note body. Whole-message is useful but bounded.
            msg_s = str(msg).strip()
            if len(msg_s) > 1024:
                msg_s = msg_s[:1024] + "…(truncated)"
            event.meta["sip_message"] = msg_s
        if (tt := doc.get("transport_type")) is not None:
            event.meta["transport_type"] = str(tt).strip().upper()

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
