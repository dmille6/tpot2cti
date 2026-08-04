"""Miniprint parser — line-printer / IPP / PJL honeypot (port 9100).

See docs/parsers/miniprint.md for protocol/ES-field/STIX/substance notes.
"""

from __future__ import annotations

import logging
import re
from typing import Iterable, Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Cap on request_body bytes preserved in ``event.meta`` and the
#: downstream Note.  4 KB is enough to recognize any PJL/PCL/PostScript
#: pattern without blowing past STIXBuilder's per-Note size cap.
REQUEST_BODY_CAP = 4 * 1024

#: Print-job control markers that — when found in ``request_path`` —
#: make a session substantive even if the body is empty.  These are
#: deliberately specific patterns no benign scanner would emit.
_PRINT_PATH_MARKERS: list[re.Pattern] = [
    # HP PJL — Printer Job Language commands start with the ESC sequence
    # followed by ``@PJL``.  T-Pot strips the ESC, so we match ``@PJL``
    # at the start.
    re.compile(r"^@PJL", re.IGNORECASE),
    # IPP-style printer paths
    re.compile(r"/printer/", re.IGNORECASE),
    re.compile(r"/printers/", re.IGNORECASE),
    re.compile(r"/ipp/", re.IGNORECASE),
    # PostScript magic — usually appears in body, but some attackers
    # smuggle the marker into the path.
    re.compile(r"%!PS"),
]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class MiniprintParser(BaseParser):
    """Parser for T-Pot's Miniprint printer honeypot."""

    type_name = "Miniprint"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert a Miniprint ES doc into a normalized :class:`ParsedEvent`.

        Pulls ``request_path`` and ``request_body``, truncates the body
        to :data:`REQUEST_BODY_CAP`, and pre-computes the matched-marker
        list so downstream substance checks are a dict lookup at
        evaluation time.

        Returns ``None`` (logged at DEBUG) for malformed docs.
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("miniprint: skipping doc with no src_ip")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug(
                f"miniprint: skipping doc with unparseable @timestamp "
                f"(_id={doc.get('_id')!r})"
            )
            return None

        # Miniprint default port is 9100; respect the doc's value if set.
        dst_port = self._safe_int((doc.get("dest_port") or doc.get("dst_port"))) or 9100

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="Miniprint",
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=dst_port,
            dst_ip=(doc.get("dest_ip") or doc.get("dst_ip")),
            protocol="raw-print",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── request_path ───────────────────────────────────────────────
        request_path = doc.get("request_path") or ""
        if request_path:
            event.meta["request_path"] = str(request_path)

        # ── request_body — truncate, record original length ────────────
        request_body = doc.get("request_body") or ""
        body_str = str(request_body)
        body_len = len(body_str.encode("utf-8", errors="replace"))
        if body_len > REQUEST_BODY_CAP:
            body_truncated = body_str.encode("utf-8", errors="replace")[
                :REQUEST_BODY_CAP
            ].decode("utf-8", errors="replace")
            event.meta["body_truncated"] = True
        else:
            body_truncated = body_str
            event.meta["body_truncated"] = False
        if body_str:
            event.meta["request_body"] = body_truncated
        event.meta["body_length"] = body_len

        # ── Pre-compute matched print-job markers ──────────────────────
        matched = self._scan_path_markers(str(request_path))
        if matched:
            event.meta["matched_print_markers"] = matched

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — one event per session + mirror meta to session
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events: Iterable[ParsedEvent]) -> list[AttackSession]:
        """Wrap each event in a one-event :class:`AttackSession` and
        mirror Miniprint-specific meta fields to ``session.meta`` so
        the downstream STIX builder reads
        uniformly-populated session fields.
        """
        sessions: list[AttackSession] = []
        for event in events:
            session = AttackSession.from_event(event)
            self._aggregate_session(session, [event])
            sessions.append(session)
        return sessions

    @staticmethod
    def _aggregate_session(
        session: AttackSession, events: list[ParsedEvent],
    ) -> None:
        """Mirror Miniprint per-event meta onto session.meta."""
        if not events:
            return
        first_meta = events[0].meta
        for k in (
            "request_path", "request_body", "body_length", "body_truncated",
            "matched_print_markers",
        ):
            if k in first_meta:
                session.meta.setdefault(k, first_meta[k])
    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _scan_path_markers(request_path: str) -> list[str]:
        """Return the pattern strings (not compiled regexes) of every
        print-job marker that fired against ``request_path``.

        We return strings so the result is JSON-serializable and easy
        to surface in the downstream Note body.
        """
        hits: list[str] = []
        for pat in _PRINT_PATH_MARKERS:
            if pat.search(request_path):
                if pat.pattern not in hits:
                    hits.append(pat.pattern)
        return hits

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


# Register on import
register(MiniprintParser())
