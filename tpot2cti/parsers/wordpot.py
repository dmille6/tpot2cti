"""Wordpot parser — fake WordPress honeypot.

See docs/parsers/wordpot.md for protocol/ES-field/STIX/substance notes.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# WordPress recon path regex
# ---------------------------------------------------------------------------

#: Matches WordPress-specific attack surfaces in a request_path.
#: Per V1_SPEC §5.18:
#:   - /wp-admin/...     (admin login + AJAX endpoints)
#:   - /wp-login.php     (the login form — brute-force target)
#:   - /xmlrpc.php       (xmlrpc-multicall password spraying + pingback abuse)
#:   - /wp-config*       (wp-config.php / wp-config.php.bak disclosure)
#:   - /wp-content/plugins/...   (plugin enumeration + known-CVE probing)
#: We anchor on `/wp-` only at a path boundary (^ or /) so we don't
#: spuriously match paths that contain "wp-" mid-segment.
_WP_RECON_PATHS = re.compile(
    r"(?i)(?:^|/)(?:"
    r"wp-admin(?:/|$)"
    r"|wp-login\.php"
    r"|xmlrpc\.php"
    r"|wp-config(?:\.php)?(?:\.bak|\.old|\.save|\.swp|~)?(?:$|\?)"
    r"|wp-content/plugins/"
    r")"
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class WordpotParser(BaseParser):
    """Parser for T-Pot's Wordpot fake-WordPress honeypot."""

    type_name = "Wordpot"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert a Wordpot ES doc into a ParsedEvent.

        Returns None for malformed docs (missing src_ip or @timestamp).
        Per V1_SPEC §5.18 we consume src_ip + request_path + user_agent;
        the rest of the doc rides along on raw_doc.
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("wordpot: doc missing src_ip; skipping")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("wordpot: doc missing/unparseable @timestamp; skipping")
            return None

        request_path = str(doc.get("request_path") or doc.get("url") or "")
        user_agent = str(
            doc.get("user_agent")
            or doc.get("http_user_agent")
            or (doc.get("http") or {}).get("user_agent")
            or ""
        )

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="Wordpot",
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int(doc.get("dst_port") or doc.get("dest_port") or 80),
            dst_ip=doc.get("dst_ip") or doc.get("dest_ip"),
            protocol="http",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        event.meta["request_path"] = request_path
        event.meta["user_agent"] = user_agent

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — default one-event-per-session, plus session.urls
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events):
        """One-event-per-session, copying request_path onto session.urls
        so the substance filter and the STIX builder can reach the URL
        via the session directly.
        """
        sessions: list[AttackSession] = []
        for e in events:
            s = AttackSession.from_event(e)
            path = e.meta.get("request_path")
            if path:
                s.urls.append(str(path))
            sessions.append(s)
        return sessions
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
register(WordpotParser())
