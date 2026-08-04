"""Honeytrap parser — TCP/UDP catchall honeypot.

See docs/parsers/honeytrap.md for protocol/ES-field/STIX/substance notes.
"""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent
from tpot2cti.session import correlate_by_window

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Threshold (in printable-payload bytes) above which a Honeytrap session
#: is treated as "substantive" and gets the full STIX graph including a
#: Sighting with payload preview in its description.  Per V1_SPEC §5.4.
SUBSTANCE_PAYLOAD_THRESHOLD = 8

#: A vertical-scan threshold: an attacker burst that hits this many distinct
#: destination ports is itself substantive intel (a port sweep), even when
#: every probe carried an empty payload — which is the common case.
SUBSTANCE_PORT_THRESHOLD = 3

#: Burst window (seconds) for `correlate_by_window`. A single attacker's port
#: sweep arrives as dozens of separate TCP connects within a few seconds; we
#: glue them into ONE session so the indicator/sighting reflects the *scan*
#: (its full port set) instead of emitting one thin indicator-touch per port.
HONEYTRAP_WINDOW_SECONDS = 300


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

        # ── T-Pot / Suricata enrichment tags ───────────────────────────
        # The logstash pipeline decorates docs with a `tags` list (CVE ids,
        # category markers, etc.). Cheap, high-signal context for the
        # indicator — carry it through for the aggregator to dedupe.
        tags = doc.get("tags")
        if isinstance(tags, list) and tags:
            event.meta["tags"] = [str(t) for t in tags if t]

        # ── Captured follow-up downloads ───────────────────────────────
        # Honeytrap can pull a binary the probe pointed at; T-Pot records it
        # under `downloads` (+ counters). Rare but pure gold when present —
        # route any sha256/url through the session download chain so the
        # builder emits a File observable + URL→File edge.
        downloads = doc.get("downloads")
        if isinstance(downloads, list) and downloads:
            event.meta["downloads_raw"] = downloads
        if (dl_count := self._safe_int(doc.get("download_count"))):
            event.meta["download_count"] = dl_count

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
    # correlate() — group an attacker's burst into ONE scan session
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events: Iterable[ParsedEvent]) -> list[AttackSession]:
        """Glue an attacker's probe burst into a single port-scan session.

        Honeytrap emits one event per TCP connect / UDP datagram and ships
        no session id, so the same IP sweeping 40 ports used to become 40
        one-event sessions → 40 indicator-touches + 40 Sightings, each
        carrying a single port. `correlate_by_window(300s)` collapses the
        burst into one session whose `dst_ports` set *is* the scan, letting
        the builder surface "swept tcp/2082,2086,2087 → cPanel" on a single
        indicator. Mirrors the FATT / Router parsers (V1_SPEC §5.4).
        """
        return correlate_by_window(
            list(events),
            window_seconds=HONEYTRAP_WINDOW_SECONDS,
            aggregator=self._aggregate_session,
        )

    @staticmethod
    def _aggregate_session(
        session: AttackSession, events: list[ParsedEvent],
    ) -> None:
        """Promote burst-level Honeytrap signals onto the session.

        `dst_ports` / `protocols` are already populated by the correlator;
        here we keep the single most-informative payload across the burst,
        union the enrichment tags, and route any captured download to the
        session download chain so the builder can emit a File observable.
        """
        best_printable, best_hex = "", ""
        md5 = sha512 = None
        payload_length = 0
        tags: list[str] = []
        for e in events:
            printable = str(e.meta.get("payload_printable") or "")
            hex_str = str(e.meta.get("payload_hex") or "")
            # "Best" = richest payload: prefer longer printable, then hex.
            if len(printable) > len(best_printable) or (
                printable and not best_printable
            ):
                best_printable = printable
                best_hex = hex_str
                md5 = e.meta.get("payload_md5")
                sha512 = e.meta.get("payload_sha512")
                payload_length = int(e.meta.get("payload_length") or 0)

            for t in (e.meta.get("tags") or []):
                if t not in tags:
                    tags.append(t)

            # Captured follow-up binary (rare). Accept common hash/url keys.
            for dl in (e.meta.get("downloads_raw") or []):
                if not isinstance(dl, dict):
                    continue
                sha = (dl.get("sha256") or dl.get("sha256_hash") or "").lower() or None
                url = dl.get("url") or dl.get("download_url") or None
                if sha and sha not in session.malware_hashes:
                    session.malware_hashes.append(sha)
                if sha or url:
                    session.downloads.append({"sha256": sha, "url": url})
                if url and url not in session.urls:
                    session.urls.append(url)

        if best_printable or best_hex:
            session.meta["payload_printable"] = best_printable
            session.meta["payload_hex"] = best_hex
            if payload_length:
                session.meta["payload_length"] = payload_length
            if md5:
                session.meta["payload_md5"] = md5
            if sha512:
                session.meta["payload_sha512"] = sha512
        if tags:
            session.meta["tags"] = tags
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
