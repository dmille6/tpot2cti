"""ElasticPot parser — fake Elasticsearch HTTP API honeypot.

See docs/parsers/elasticpot.md for protocol/ES-field/STIX/substance notes.
"""

from __future__ import annotations

import logging
import re
from typing import Optional, Pattern

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known Elasticsearch exploit signatures
# ---------------------------------------------------------------------------

# Each tuple is (CVE id, compiled regex).  The regex matches the
# request_body of an attack attempt.  CVE-2014-3120 is the classic
# Groovy dynamic scripting RCE — bodies contain a `"script":` block
# embedding `java.lang.Runtime` / `getRuntime().exec(...)` / similar.
# CVE-2015-1427 is the search-template sandbox bypass — bodies typically
# wrap the script in `"template":{"inline":` or `"template":{"file":`
# alongside a Groovy expression.  Patterns are intentionally loose
# (case-insensitive substring matches on well-known fingerprints) so we
# catch obfuscated variants too.
_ES_EXPLOIT_PATTERNS: list[tuple[str, Pattern[str]]] = [
    (
        "CVE-2014-3120",
        re.compile(
            r"(?is)"
            r'"script"\s*:.*?'
            r"(?:java\.lang\.Runtime|getRuntime\s*\(\s*\)|"
            r'Runtime\.getRuntime|exec\s*\(|"lang"\s*:\s*"groovy")'
        ),
    ),
    (
        "CVE-2015-1427",
        re.compile(
            r"(?is)"
            r'"template"\s*:\s*\{.*?(?:"inline"|"file"|"id").*?'
            r"(?:Math\.class\.forName|java\.lang|getRuntime|"
            r'"lang"\s*:\s*"groovy")'
        ),
    ),
]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class ElasticPotParser(BaseParser):
    """Parser for T-Pot's ElasticPot fake-Elasticsearch honeypot."""

    type_name = "ElasticPot"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert an ElasticPot ES doc into a ParsedEvent.

        Returns None for malformed docs (missing src_ip or @timestamp).
        Per V1_SPEC §5.11 we only consume src_ip, request_url,
        request_method, request_body; everything else is preserved on
        raw_doc for the builder if it wants more context.
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("elasticpot: doc missing src_ip; skipping")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("elasticpot: doc missing/unparseable @timestamp; skipping")
            return None

        # Per 2026-05-22 field-name audit vs real ES exports: T-Pot ships
        # the URL under the literal-dotted top-level key `"http.url"`
        # (100% of real Elasticpot docs) — this is a single key with a
        # dot in its name, NOT nested `http: {url: ...}`. Python dict
        # access works fine, just spell the key correctly. Legacy
        # `request_url` kept as fallback for older T-Pot versions.
        request_url = str(
            doc.get("http.url")
            or doc.get("request_url")
            or ""
        )
        request_method = str(doc.get("request_method") or "").upper() or "GET"
        request_body = doc.get("request_body")
        # ES request bodies are usually JSON but T-Pot may store them as
        # a string or as a parsed dict; normalize to a string for regex
        # matching either way.
        if request_body is None:
            request_body_str = ""
        elif isinstance(request_body, (dict, list)):
            try:
                import json
                request_body_str = json.dumps(request_body, separators=(",", ":"))
            except (TypeError, ValueError):
                request_body_str = str(request_body)
        else:
            request_body_str = str(request_body)

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="ElasticPot",
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int(doc.get("dst_port") or doc.get("dest_port") or 9200),
            dst_ip=doc.get("dst_ip") or doc.get("dest_ip"),
            protocol="http",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── Stash the request triple in meta for the builder ──────────
        event.meta["request_url"] = request_url
        event.meta["request_method"] = request_method
        event.meta["request_body"] = request_body_str

        # ── Run exploit-signature detection on the body ───────────────
        matched_cve = self._match_es_exploit(request_body_str)
        if matched_cve:
            event.meta["matched_cve"] = matched_cve

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — default one-event-per-session is correct
    # ──────────────────────────────────────────────────────────────────
    # Each HTTP request is its own ElasticPot event; there's no native
    # multi-request session id.  Inherited BaseParser.correlate wraps
    # each event in a one-event AttackSession via AttackSession.from_event,
    # which copies dst_port/dst_ip/protocol onto the session — we then
    # extend it below with the URL.

    def correlate(self, events):
        """One-event-per-session, with session.urls populated from the
        single event's request_url so the substance filter and the STIX
        builder can both reach the URL via the session directly.
        """
        sessions: list[AttackSession] = []
        for e in events:
            s = AttackSession.from_event(e)
            url = e.meta.get("request_url")
            if url:
                s.urls.append(str(url))
            sessions.append(s)
        return sessions
    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _match_es_exploit(body: str) -> Optional[str]:
        """Return the first matching CVE id, or None if no signature
        fires against the body.
        """
        if not body:
            return None
        for cve, pattern in _ES_EXPLOIT_PATTERNS:
            if pattern.search(body):
                return cve
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
register(ElasticPotParser())
