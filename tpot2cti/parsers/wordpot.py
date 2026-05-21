"""Wordpot parser — fake WordPress honeypot.

Wordpot emulates a WordPress site and captures the HTTP requests
attackers and bots throw at it.  The internet is saturated with
generic web crawlers and vulnerability scanners; the substantive
traffic on a WordPress honeypot is the subset that targets WordPress-
specific surfaces — `/wp-admin`, `/wp-login.php`, `/xmlrpc.php`,
`/wp-config*`, `/wp-content/plugins/*` — i.e. login brute-force,
xmlrpc abuse, config-file disclosure attempts, and plugin enumeration
/ known-CVE plugin probing.

Per V1_SPEC.md §5.18:

  T-Pot doc fields used:
    src_ip, request_path, user_agent

  Event correlation:
    one ES doc → one ParsedEvent → one AttackSession (default
    one-event-per-session correlator).  Wordpot has no native
    multi-request session concept in the T-Pot index — each request
    is its own document.

  STIX emitted:
    - IPv4-Addr
    - URL
    - Sighting
    - AttackPattern("wordpress-recon") if hits /wp-admin, /wp-login.php, etc.

  Substance filter (per LESSONS_LEARNED_FROM_V0.md §2):
    A session is substantive iff request_path matches one of the
    well-known WordPress attack surfaces:
      /wp-admin..., /wp-login.php, /xmlrpc.php, /wp-config*,
      /wp-content/plugins/*
    Anything else (`GET /`, generic 404 spelunking, robots.txt, etc.)
    is drive-by noise.
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
    # has_substance() — strict WordPress-recon filter
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Return True iff request_path matches a WordPress attack
        surface (`/wp-admin`, `/wp-login.php`, `/xmlrpc.php`,
        `/wp-config*`, `/wp-content/plugins/*`).  Per V1_SPEC §5.18
        and LESSONS_LEARNED_FROM_V0.md §2.
        """
        if not session.events:
            return False
        path = str(session.events[0].meta.get("request_path") or "")
        if not path:
            return False
        return bool(_WP_RECON_PATHS.search(path))

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


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = WordpotParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — root probe ─────────────────────────────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Wordpot",
        "src_ip": "203.0.113.40",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_path": "/",
        "user_agent": "Mozilla/5.0 (compatible; SomeBot/1.0)",
        "geoip": {"country_iso_code": "US", "asn": 64500},
    }

    # ── Case 2: substantive — /wp-login.php brute-force ───────────────
    login_doc = {
        "@timestamp": now.isoformat(),
        "type": "Wordpot",
        "src_ip": "198.51.100.40",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_path": "/wp-login.php",
        "user_agent": "wpscan",
    }

    # ── Case 3: substantive — /xmlrpc.php ─────────────────────────────
    xmlrpc_doc = {
        "@timestamp": now.isoformat(),
        "type": "Wordpot",
        "src_ip": "198.51.100.41",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_path": "/xmlrpc.php",
        "user_agent": "curl/8.0",
    }

    # ── Case 4: substantive — plugin enumeration ──────────────────────
    plugin_doc = {
        "@timestamp": now.isoformat(),
        "type": "Wordpot",
        "src_ip": "198.51.100.42",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_path": "/wp-content/plugins/contact-form-7/readme.txt",
        "user_agent": "Mozilla/5.0",
    }

    # ── Case 5: substantive — wp-config disclosure attempt ────────────
    config_doc = {
        "@timestamp": now.isoformat(),
        "type": "Wordpot",
        "src_ip": "198.51.100.43",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_path": "/wp-config.php.bak",
        "user_agent": "Nmap NSE",
    }

    # ── Case 6: drive-by — robots.txt ─────────────────────────────────
    robots_doc = {
        "@timestamp": now.isoformat(),
        "type": "Wordpot",
        "src_ip": "203.0.113.41",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_path": "/robots.txt",
        "user_agent": "Googlebot",
    }

    de = parser.parse(driveby_doc)
    le = parser.parse(login_doc)
    xe = parser.parse(xmlrpc_doc)
    pe = parser.parse(plugin_doc)
    ce = parser.parse(config_doc)
    re_ = parser.parse(robots_doc)
    assert all((de, le, xe, pe, ce, re_)), "parse failed"

    ds = parser.correlate([de])[0]
    ls = parser.correlate([le])[0]
    xs = parser.correlate([xe])[0]
    ps = parser.correlate([pe])[0]
    cs = parser.correlate([ce])[0]
    rs = parser.correlate([re_])[0]

    assert parser.has_substance(ds) is False, "/ must NOT be substantive"
    assert parser.has_substance(ls) is True, "/wp-login.php must be substantive"
    assert parser.has_substance(xs) is True, "/xmlrpc.php must be substantive"
    assert parser.has_substance(ps) is True, "plugins path must be substantive"
    assert parser.has_substance(cs) is True, "wp-config.php.bak must be substantive"
    assert parser.has_substance(rs) is False, "/robots.txt must NOT be substantive"

    # URL mirrored onto the session
    assert ls.urls == ["/wp-login.php"]

    print("OK")
