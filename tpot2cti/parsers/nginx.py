"""NGINX parser — custom nginx access logs from persona HTTP fronts.

See docs/parsers/nginx.md for protocol/ES-field/STIX/substance notes.
"""

from __future__ import annotations

import logging
import re
from typing import Optional, Pattern

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scan / exploit signatures
# ---------------------------------------------------------------------------

#: Regex matching request_uri values we treat as scan / exploit attempts.
#: Intentionally broad — any one of these substrings in the URI tells us
#: the attacker is not browsing, they're hunting.  Case-insensitive.
#:
#: The catalogue covers the highest-signal patterns we observed in V0
#: scan traffic; extend as new patterns appear.  Each entry is anchored
#: so /.git/HEAD matches but /legit/.gitignore-style/paths do not.
_NGINX_SCAN_SIGNALS: Pattern[str] = re.compile(
    r"(?i)"
    r"(?:"
    # version-control leaks
    r"/\.git(?:/|$)"
    r"|/\.svn(?:/|$)"
    r"|/\.hg(?:/|$)"
    # secrets / config leaks
    r"|/\.env(?:[./]|$)"
    r"|/\.aws(?:/|$)"
    r"|/\.ssh(?:/|$)"
    r"|/\.docker(?:/|$)"
    r"|/config\.(?:json|ya?ml|php)"
    r"|/wp-config\.php"
    # WordPress / common CMS scan paths
    r"|/wp-(?:admin|login|content|includes)"
    r"|/xmlrpc\.php"
    # generic admin / api / CGI fishing
    r"|/admin(?:/|$|\.php)"
    r"|/phpmyadmin"
    r"|/api(?:/v\d+)?/"
    r"|/cgi-bin/"
    # backup / dump leakage
    r"|/(?:backup|dump|db|database)\.(?:sql|zip|tar|gz|bak)"
    # shellshock / log4j tells
    r"|\$\{jndi:"
    r"|\(\)\s*\{"
    # generic file-traversal / LFI
    r"|\.\./"
    r"|/etc/passwd"
    r")"
)

#: Regex matching User-Agent strings of known scanners / exploit tools.
#: Case-insensitive substring match against the UA header.
_NGINX_SCANNER_UA: Pattern[str] = re.compile(
    r"(?i)"
    r"(?:"
    r"sqlmap"
    r"|nikto"
    r"|nmap"
    r"|masscan"
    r"|zgrab"
    r"|nuclei"
    r"|zmeu"           # the ZmEu PHP scanner
    r"|gobuster"
    r"|ffuf"
    r"|dirbuster"
    r"|wpscan"
    r"|acunetix"
    r"|netsparker"
    r"|burp"
    r"|metasploit"
    r"|hydra"
    r")"
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class NginxParser(BaseParser):
    """Parser for T-Pot's custom NGINX access-log honeypot front."""

    #: Note: the T-Pot `type` field for this stream is "NGINX" in all
    #: capitals (per V1_SPEC §5.21).  The exact case matters because
    #: the registry dispatch is case-sensitive.
    type_name = "NGINX"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert one NGINX access-log ES doc into a ParsedEvent.

        Returns None for malformed docs (no src_ip or @timestamp), per
        V1_SPEC §7 — the caller logs at DEBUG and continues.  Other
        fields are tolerated as missing; we still produce an event if
        we at least have a source IP and a timestamp.
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("nginx: doc missing src_ip; skipping")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("nginx: doc missing/unparseable @timestamp; skipping")
            return None

        request_uri = str(doc.get("request_uri") or doc.get("request") or "")
        request_method = (
            str(doc.get("request_method") or doc.get("method") or "").upper()
            or "GET"
        )
        status_code = self._safe_int(
            doc.get("status_code") or doc.get("status") or doc.get("response")
        )
        user_agent = str(
            doc.get("user_agent")
            or doc.get("http_user_agent")
            or doc.get("agent")
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
            event_type="NGINX",
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int(
                doc.get("dst_port") or doc.get("dest_port") or 80
            ),
            dst_ip=doc.get("dst_ip") or doc.get("dest_ip"),
            protocol="http",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        event.meta["request_uri"] = request_uri
        event.meta["request_method"] = request_method
        if status_code is not None:
            event.meta["status_code"] = status_code
        if user_agent:
            event.meta["user_agent"] = user_agent

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — one event per session, with session.urls populated
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events):
        """One-event-per-session, with the request_uri added to
        `session.urls` so the substance filter and the STIX builder
        can both reach the URL directly off the session.
        """
        sessions: list[AttackSession] = []
        for e in events:
            s = AttackSession.from_event(e)
            uri = e.meta.get("request_uri")
            if uri:
                s.urls.append(str(uri))
            sessions.append(s)
        return sessions

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — error status, scan URI, or scanner UA
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Return True iff the single request looks like scanning or
        exploitation rather than a generic crawl of `/`.

        Per V1_SPEC §5.21:
          - 4xx / 5xx status → the request hit a path the server
            doesn't have, which is the definition of scanning, OR
          - request_uri matches a known scan/exploit signature, OR
          - user_agent matches a known scanner UA.
        """
        if not session.events:
            return False
        meta = session.events[0].meta

        status = meta.get("status_code")
        if isinstance(status, int) and 400 <= status <= 599:
            return True

        uri = str(meta.get("request_uri") or "")
        if uri and _NGINX_SCAN_SIGNALS.search(uri):
            return True

        ua = str(meta.get("user_agent") or "")
        if ua and _NGINX_SCANNER_UA.search(ua):
            return True

        return False

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
register(NginxParser())
