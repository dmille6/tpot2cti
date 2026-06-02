"""CiscoASA parser — Cisco ASA emulator (CVE-2018-0101 and friends).

See docs/parsers/ciscoasa.md for protocol/ES-field/STIX/substance notes.
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

#: Maximum payload length preserved in event.meta — 4 KiB matches the
#: cap V1_SPEC §5.13 implies; longer payloads get truncated with a
#: trailing marker so downstream Note builders don't ship megabytes.
_PAYLOAD_CAP_BYTES: int = 4096
_TRUNCATION_MARKER: str = "...[truncated]"

#: CVE id we report when the high-confidence pattern matches.
_CVE_2018_0101: str = "CVE-2018-0101"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class CiscoasaParser(BaseParser):
    """Parser for T-Pot's CiscoASA honeypot."""

    type_name = "Ciscoasa"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert a CiscoASA ES doc into a normalized ParsedEvent.

        Missing `src_ip` or `@timestamp` aborts parsing.  An absent
        `payload` is tolerated — the IP / port observation alone is
        still substantive (someone touched our fake ASA on 443).
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("ciscoasa: skipping doc with no src_ip")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("ciscoasa: skipping doc with unparseable @timestamp")
            return None

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="Ciscoasa",
            session_id=doc.get("session_id"),
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int((doc.get("dest_port") or doc.get("dst_port")) or 443),
            dst_ip=(doc.get("dest_ip") or doc.get("dst_ip")),
            protocol="https",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── Payload handling ──────────────────────────────────────────
        # `payload_printable` is the canonical T-Pot field (100% of real
        # docs per 2026-05-22 field-name audit). The flat `payload`
        # spelling is kept as a fallback for older T-Pot versions —
        # never appears in current data but cheap to retain.
        # May be str or bytes (older T-Pot indexed bytes before logstash
        # decoded them).  Normalize to str and truncate to
        # _PAYLOAD_CAP_BYTES to keep ParsedEvent.meta small.
        raw_payload = doc.get("payload_printable") or doc.get("payload")
        if isinstance(raw_payload, (bytes, bytearray)):
            try:
                payload = raw_payload.decode("utf-8", errors="replace")
            except Exception:
                payload = ""
        elif isinstance(raw_payload, str):
            payload = raw_payload
        else:
            payload = ""

        if payload:
            if len(payload) > _PAYLOAD_CAP_BYTES:
                event.meta["payload"] = (
                    payload[:_PAYLOAD_CAP_BYTES] + _TRUNCATION_MARKER
                )
                event.meta["payload_truncated"] = True
                event.meta["payload_len_original"] = len(payload)
            else:
                event.meta["payload"] = payload

            # CVE matching is deliberately conservative — we only
            # stash matched_cve on a high-confidence hit so downstream
            # Vulnerability emission is signal, not noise.
            cve = self._match_cve_2018_0101(payload)
            if cve:
                event.meta["matched_cve"] = cve

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — default one-event-per-session is correct here
    # ──────────────────────────────────────────────────────────────────
    # Per V1_SPEC §5.13: each exploit attempt is its own connection.
    # We inherit BaseParser.correlate (one event → one session) — no
    # override needed.

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — always True per V1_SPEC §5.13
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Always substantive — every probe of a fake Cisco ASA is
        meaningful (port 443 with crafted payload is not internet
        background radiation).  Per V1_SPEC §5.13.
        """
        return True

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _match_cve_2018_0101(payload: str) -> Optional[str]:
        """Conservative pattern match for CVE-2018-0101 / known PoCs.

        High-confidence hit when EITHER:
          - the payload contains all three of `<host>`, `<key>`, and
            `webvpn` (case-insensitive) — the classic SOAP-envelope
            shape of the published exploit, OR
          - the payload starts with `tcp_test` — fingerprint of a
            widely-circulated public PoC connectivity probe.

        We deliberately do not match looser shapes (e.g. any XML on
        443) — false positives here would dilute the value of CVE
        Vulnerability emissions downstream.
        """
        if not payload:
            return None

        # Liberal detection at the start-of-payload PoC fingerprint
        stripped = payload.lstrip()
        if stripped.lower().startswith("tcp_test"):
            return _CVE_2018_0101

        lowered = payload.lower()
        if "<host>" in lowered and "<key>" in lowered and "webvpn" in lowered:
            return _CVE_2018_0101

        return None

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


# Register on import
register(CiscoasaParser())
