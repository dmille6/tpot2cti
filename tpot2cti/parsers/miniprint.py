"""Miniprint parser — line-printer / IPP / PJL honeypot (port 9100).

Miniprint emulates a small networked printer's raw-print interface
(typically port 9100, the JetDirect/RAW protocol).  Most internet
"printer probes" that hit port 9100 are SHODAN-style banner grabs and
opportunistic scans that send nothing meaningful — but every now and
again an attacker tries to push an actual PJL command, a PostScript
program, or a malformed print job.  The substance filter separates
the two.

Per V1_SPEC.md §5.16:

  T-Pot doc fields used:
    src_ip, request_path, request_body

  STIX emitted (later, by the orchestrator):
    IPv4-Addr,
    Sighting,
    (Note with request_path + request_body when substantive)

  Event correlation: each connection to the fake printer is one event.
  We inherit the default one-event-per-session correlator.

Substance filter (per docs/LESSONS_LEARNED_FROM_V0.md §2):

  A Miniprint session is substantive iff any of:

    - request_body has length > 0   (the attacker actually sent bytes)
    - request_path contains print-job control markers:
        * starts with ``@PJL`` (HP Printer Job Language commands)
        * contains ``/printer/`` (IPP-style paths)
        * contains ``%!PS``     (PostScript magic)

  Bare port-9100 SYN-and-close probes get no body and no path of
  interest, so they fall through to the drive-by code path.

Per-session promotions to the AttackSession:

  - ``session.meta``  ← request_path, request_body (truncated),
                        body_length, body_truncated
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
        list so :meth:`has_substance` is a dict lookup at evaluation
        time.

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
        :meth:`has_substance` and the downstream STIX builder read
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
    # has_substance() — substance filter per V1_SPEC §5.16 + LESSONS §2
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """A Miniprint session is substantive iff:

          - the attacker actually sent a non-empty request_body, OR
          - the request_path matches a known print-job control marker
            (``@PJL``, ``/printer/``, ``%!PS``, etc.).

        Bare TCP-touch probes (SYN, banner grab, immediate close) leave
        both fields empty and fall through to the drive-by code path.
        """
        if not session.events:
            return False

        body_length = session.meta.get("body_length") or 0
        if body_length > 0:
            return True

        matched = session.meta.get("matched_print_markers") or []
        if matched:
            return True

        return False

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


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = MiniprintParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — port-9100 SYN-and-close, empty body / path ──
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Miniprint",
        "src_ip": "203.0.113.17",
        "src_port": 50300,
        "dst_port": 9100,
        "t-pot_hostname": "node1",
        "request_path": "",
        "request_body": "",
        "geoip": {"country_iso_code": "BR", "country_name": "Brazil"},
    }

    # ── Case 2: substantive — PJL job pushed via raw-print ─────────────
    substantive_doc = {
        "@timestamp": now.isoformat(),
        "type": "Miniprint",
        "src_ip": "198.51.100.33",
        "src_port": 33555,
        "dst_port": 9100,
        "t-pot_hostname": "node1",
        "request_path": "@PJL INFO STATUS",
        "request_body": (
            "@PJL ENTER LANGUAGE=POSTSCRIPT\n"
            "%!PS-Adobe-3.0\n"
            "/Helvetica findfont 12 scalefont setfont\n"
            "100 100 moveto (Hacked) show\n"
            "showpage\n"
        ),
        "geoip": {
            "country_iso_code": "CN",
            "country_name": "China",
            "asn": 4134,
            "organization": "ChinaNet",
        },
    }

    drive_event = parser.parse(driveby_doc)
    subs_event = parser.parse(substantive_doc)
    assert drive_event and subs_event, "parse failed"

    drive_session = parser.correlate([drive_event])[0]
    subs_session = parser.correlate([subs_event])[0]

    drive_has = parser.has_substance(drive_session)
    subs_has = parser.has_substance(subs_session)
    print(f"drive-by    has_substance: {drive_has}  (expected False)")
    print(f"substantive has_substance: {subs_has}  (expected True)")
    assert drive_has is False, "empty-path empty-body probe must be non-substantive"
    assert subs_has is True, "PJL job push must be substantive"

    # The substantive session must carry the request_path and body in
    # session.meta so the downstream Note builder can quote them.
    assert subs_session.meta.get("request_path", "").startswith("@PJL"), (
        f"expected @PJL request_path; got "
        f"{subs_session.meta.get('request_path')!r}"
    )
    assert "POSTSCRIPT" in subs_session.meta.get("request_body", ""), (
        "expected PostScript body fragment in session.meta.request_body"
    )
    assert subs_session.meta.get("matched_print_markers"), (
        "expected at least one print-marker hit on @PJL path"
    )

    # Also verify a path-only (empty body) PJL probe is substantive.
    path_only_doc = {
        **driveby_doc,
        "src_ip": "198.51.100.34",
        "request_path": "@PJL INFO ID",
        "request_body": "",
    }
    path_only_event = parser.parse(path_only_doc)
    assert path_only_event is not None
    path_only_session = parser.correlate([path_only_event])[0]
    assert parser.has_substance(path_only_session) is True, (
        "PJL path alone (empty body) should still be substantive"
    )

    print("OK")
