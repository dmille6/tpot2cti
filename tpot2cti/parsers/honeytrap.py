"""Honeytrap parser — TCP/UDP catchall honeypot.

See docs/parsers/honeytrap.md for protocol/ES-field/STIX/substance notes.
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

#: Threshold (in printable-payload bytes) above which a Honeytrap session
#: is treated as "substantive" and gets the full STIX graph including a
#: Sighting with payload preview in its description.  Per V1_SPEC §5.4.
SUBSTANCE_PAYLOAD_THRESHOLD = 8


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class HoneytrapParser(BaseParser):
    """Parser for T-Pot's Honeytrap TCP/UDP catchall honeypot."""

    type_name = "Honeytrap"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert a Honeytrap ES doc into a ParsedEvent.

        Honeytrap nests most of its useful fields under
        `attack_connection` in some T-Pot versions and at top level in
        others; we look in both places.  Returns None for malformed
        docs (missing src_ip or @timestamp).
        """
        # attack_connection holds the per-connection metadata; some fields
        # are duplicated at the top level — prefer top-level then fall back.
        ac = doc.get("attack_connection") or {}
        if not isinstance(ac, dict):
            ac = {}

        src_ip = doc.get("src_ip") or ac.get("src_ip")
        if not src_ip:
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            return None

        # T-Pot Honeytrap docs use `dest_port` / `dest_ip` (live ES sample
        # 2026-05-22), NOT `dst_port` / `dst_ip`. Earlier parser code
        # missed this and Sighting descriptions showed `tcp/?` for every
        # Honeytrap probe. Accept both spellings + the nested
        # `attack_connection.*` shape for cross-version safety.
        dst_port = self._safe_int(
            doc.get("dest_port")
            or doc.get("dst_port")
            or ac.get("dest_port")
            or ac.get("dst_port")
        )
        dst_ip = (
            doc.get("dest_ip")
            or doc.get("dst_ip")
            or ac.get("dest_ip")
            or ac.get("dst_ip")
        )
        proto = (doc.get("proto") or ac.get("protocol") or "").lower() or None

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or doc.get("host", {}).get("name")
                or "unknown"
            ),
            event_type="Honeytrap",
            src_port=self._safe_int(doc.get("src_port") or ac.get("src_port")),
            dst_port=dst_port,
            dst_ip=dst_ip,
            protocol=proto,
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # Payload bytes — per 2026-05-22 field-name audit vs real ES
        # exports, T-Pot's Honeytrap actually ships:
        #
        #   attack_connection.payload: {
        #     data_hex:    <hex string of raw payload>,
        #     md5_hash:    <md5 of payload>,
        #     sha512_hash: <sha512 of payload>,
        #     length:      <byte count>,
        #   }
        #
        # There is NO `payload_printable` or `payload_hex` field at any
        # level — the pre-audit reads were silently dropping every
        # probe's payload, which meant the substance filter
        # (len(payload_printable) > 8) NEVER fired. The legacy field
        # names are retained as fallbacks for older T-Pot versions.
        payload_obj = ac.get("payload") if isinstance(ac.get("payload"), dict) else {}
        payload_hex = (
            payload_obj.get("data_hex")
            or doc.get("payload_hex")
            or ac.get("payload_hex")
            or ""
        )
        # Derive printable from hex when the printable spelling is
        # absent (true for all current T-Pot versions). Only ASCII
        # printable bytes (0x20–0x7E plus \t \n \r) survive — anything
        # else becomes '.', matching tcpdump-style payload preview.
        payload_printable = (
            doc.get("payload_printable")
            or ac.get("payload_printable")
            or self._hex_to_printable(payload_hex)
        )
        event.meta["payload_printable"] = str(payload_printable)
        event.meta["payload_hex"] = str(payload_hex)
        # Payload-derived hashes are themselves intel — wire to the
        # session aggregator so the builder can emit a File observable
        # for the captured bytes when they're substantive enough.
        if isinstance(ac.get("payload"), dict):
            if md5 := payload_obj.get("md5_hash"):
                event.meta["payload_md5"] = str(md5).lower()
            if sha512 := payload_obj.get("sha512_hash"):
                event.meta["payload_sha512"] = str(sha512).lower()
            if length := payload_obj.get("length"):
                try:
                    event.meta["payload_length"] = int(length)
                except (TypeError, ValueError):
                    pass
        if ac:
            event.meta["attack_connection"] = ac

        return event

    @staticmethod
    def _hex_to_printable(hex_str: str) -> str:
        """Decode a hex string to a tcpdump-style printable preview.

        Non-printable bytes become '.'. Returns empty string on any
        decode failure — Honeytrap docs without payload data should not
        cause a parse failure.
        """
        if not hex_str:
            return ""
        try:
            raw = bytes.fromhex(hex_str)
        except (ValueError, TypeError):
            return ""
        return "".join(
            chr(b) if (0x20 <= b <= 0x7E) or b in (0x09, 0x0A, 0x0D) else "."
            for b in raw
        )

    # ──────────────────────────────────────────────────────────────────
    # correlate() — we use the default (one event per session)
    # ──────────────────────────────────────────────────────────────────
    # Each TCP connection / UDP datagram is a Honeytrap event in its own
    # right; the inherited BaseParser.correlate() wraps each event in a
    # one-event AttackSession, which is exactly what V1_SPEC §5.4 asks
    # for.  No override needed.

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — substance filter per V1_SPEC §5.4
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """A Honeytrap session is substantive iff its single event
        captured more than `SUBSTANCE_PAYLOAD_THRESHOLD` bytes of
        printable payload.

        Empty-payload probes (SYN scans, single-packet UDP touches,
        banner-grab opens with no follow-up) fall through to the
        drive-by code path: IPv4-Addr + GeoIP + AS + IP Indicator +
        Sighting, no payload preview.
        """
        if not session.events:
            return False
        payload = session.events[0].meta.get("payload_printable") or ""
        return len(payload) > SUBSTANCE_PAYLOAD_THRESHOLD

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
register(HoneytrapParser())
