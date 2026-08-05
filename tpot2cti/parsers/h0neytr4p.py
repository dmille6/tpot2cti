"""H0neytr4p parser — HTTP/HTTPS web application honeypot.

See docs/parsers/h0neytr4p.md for protocol/ES-field/STIX/substance notes.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Iterable, Optional

from tpot2cti.log4shell import extract_jndi
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

#: Log4Shell.  A recovered JNDI endpoint is proof of an exploitation
#: attempt against this CVE, so we attach both the Vulnerability and the
#: ATT&CK technique for exploiting an internet-facing service.
LOG4SHELL_CVE = "CVE-2021-44228"
LOG4SHELL_MITRE_ID = "T1190"

#: Cap on distinct JNDI endpoints recovered from one request.  A single
#: Log4Shell probe sprays every header it can reach — and the scanner
#: observed on this hive encodes WHICH header into the callback hostname
#: (``XFl0c-…`` for X-Forwarded-For, ``REl0c-…`` for Referer, …), so one
#: request legitimately yields ~12 distinct URLs sharing one C2 zone.
#: The cap sits above that so normal probes are never truncated; it only
#: bounds a pathological spray.  Truncation is recorded on the event
#: (``jndi_truncated``) rather than dropped silently.
_MAX_JNDI_PER_EVENT = 32

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

        Pulls the request method / URI / body / user-agent / host header
        across both live ES schemas (see the field-order comment below),
        records source-address provenance, salvages any Log4Shell JNDI
        payload, and runs the substance hint list now so the result is
        cached on the event and re-used downstream.

        Returns ``None`` for malformed docs (missing src_ip or
        @timestamp); these are logged at DEBUG and dropped. A ``src_ip``
        that is present but is not an address is NOT dropped here — it is
        flagged in ``meta`` and rejected centrally by ``main.run_cycle``
        so the loss is counted, and so its payload can still be salvaged.
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

        # h0neytr4p ES shape — TWO schemas ship concurrently.
        #
        # Per the 2026-08-04 live-ES field census (34k docs/24h), the
        # hive runs two h0neytr4p builds and their log schemas differ:
        #
        #   "modern" (~99.6% of docs, every sensor but two)
        #       method, request_uri, http_user_agent, http_host,
        #       sni, status, request_time, http_referer
        #   "legacy" (~0.4%, two older sensors)
        #       request_method, request_uri, user-agent,
        #       header_<name> (one field per HTTP header), protocol
        #
        # The original reads targeted the legacy names only (plus a
        # nested `request` dict from V1_SPEC §5.7 that no build has ever
        # emitted), so on live traffic `method` and `user_agent` were
        # None for 99.6% of events and `host_header` was None for
        # *100%* of them — no build ships `host_header`/`header_host` at
        # all. That silently disabled URL reconstruction entirely:
        # measured 0 URLs and 0 domains across all 12,860 H0neytr4p rows
        # in the live state DB, against 1,072/1,072 for Tanner. Order
        # below is modern-first, legacy-fallback, nested-last. Note the
        # hyphenated `user-agent` / `header_user-agent` spellings — dict
        # access works with hyphens, this is not a typo.
        request = doc.get("request") or {}
        if not isinstance(request, dict):
            request = {}

        method = str(
            doc.get("method")
            or doc.get("request_method")
            or request.get("method")
            or ""
        ).upper() or None
        uri = (
            doc.get("request_uri") or request.get("uri") or ""
        )
        # No h0neytr4p build observed ships a request-body field; the
        # reads are kept for forks that do. Consequence: the
        # BODY_LENGTH_THRESHOLD substance rule never fires on live data,
        # so substance rests on the URI/UA hint lists below.
        body = (
            doc.get("request_body") or request.get("body") or ""
        )
        user_agent = (
            doc.get("http_user_agent")
            or doc.get("user-agent")
            or doc.get("header_user-agent")
            or request.get("user_agent")
            or ""
        )
        host_header = (
            doc.get("http_host")
            or doc.get("host_header")
            or doc.get("header_host")
            or request.get("host")
            # TLS SNI is the modern build's only other host signal and is
            # a truthful last resort for HTTPS virtual-host naming.
            or doc.get("sni")
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
        if (status := self._safe_int(doc.get("status"))) is not None:
            event.meta["status"] = status

        # ── src_ip provenance ─────────────────────────────────────────
        # h0neytr4p reports the X-Forwarded-For header AS the client
        # address: measured on live ES, src_ip is byte-identical to
        # header_x-forwarded-for in 33/33 docs that carry that header.
        # This is honeypot behaviour, not a field-read error on our side
        # — and it means an h0neytr4p src_ip is ATTACKER-CONTROLLED
        # whenever XFF is present, because nothing in the document
        # preserves the real TCP peer (t-pot_ip_ext / hostname are the
        # sensor's own addresses).
        #
        # Log4Shell scanners spray their payload into every header, XFF
        # included, so the visible symptom is a src_ip holding an
        # obfuscated JNDI payload — 30 such rows reached the live state
        # DB. Those are self-evidently unusable and CORE rejects them.
        # The quieter risk is an XFF holding a *plausible* IP, which
        # would be indistinguishable from real attribution; none has been
        # observed in the retained window, so we flag rather than drop.
        # main.run_cycle owns the reject-and-count decision (its
        # `src_ip_rejected` drop reason); the parser only records
        # provenance so that decision is auditable.
        raw_src = str(src_ip)
        xff = doc.get("header_x-forwarded-for") or doc.get("http_x_forwarded_for")
        if xff is not None and str(xff) == raw_src:
            event.meta["src_ip_from_xff"] = True
        if not self._is_ip(raw_src):
            event.meta["src_ip_invalid"] = True
            event.meta["src_ip_raw"] = raw_src[:REQUEST_BODY_CAP]

        # ── Log4Shell payload salvage ─────────────────────────────────
        # The JNDI endpoint is the actual intelligence in these events —
        # live attacker C2 / DNS-exfil infrastructure — and it is worth
        # strictly more than the spoofable address it rode in on. It
        # arrives obfuscated and sprayed across many fields at once
        # (src_ip plus ~10 header_* values in the observed sample), so
        # scan them all and dedupe by recovered URL.
        jndi = self._extract_jndi(doc, raw_src, uri, body_truncated, user_agent)
        if jndi:
            event.meta["jndi_payloads"] = [j.to_dict() for j in jndi]
            if len(jndi) >= _MAX_JNDI_PER_EVENT:
                # No silent caps: say so where an operator can see it.
                event.meta["jndi_truncated"] = True
                logger.info(
                    f"h0neytr4p: JNDI extraction hit the per-event cap "
                    f"({_MAX_JNDI_PER_EVENT}) on {event.sensor_hostname}; "
                    f"some endpoint variants not recorded"
                )
            # Feed the keys _build_web_session already consumes, so the
            # Vulnerability + AttackPattern come out of the shared web
            # graph instead of a parallel code path.
            event.meta["matched_cve"] = LOG4SHELL_CVE
            event.meta["attack_type"] = "Log4Shell JNDI injection"
            event.meta["mitre_technique"] = LOG4SHELL_MITRE_ID

        # ── Run the substance hint scan now, cache the matches ─────────
        # We run it once at parse time so downstream substance checks are
        # just a dict lookup. Headers are included because on the legacy
        # schema the exploit rides in the headers, not the URI or body.
        matched_hints = self._scan_hints(
            uri, body_truncated, user_agent, self._header_values(doc),
        )
        if jndi and r"\$\{jndi:" not in matched_hints:
            # The hint list greps for a literal `${jndi:`; an obfuscated
            # payload never matches it, so record substance explicitly.
            matched_hints.append(r"\$\{jndi:")
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

        Promotion at correlate time means the downstream STIX builder
        reads uniformly-populated session fields instead of having to
        reach into ``events[0].meta`` for every entity.
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

            # Recovered Log4Shell C2 endpoints. Promoted to the same
            # session.urls / session.domains the builder already consumes,
            # so the C2 lands in OpenCTI through the existing web-session
            # graph rather than a bespoke path. The URL is emitted even
            # when the host is None (authority still carries an
            # unresolved `${sys:...}` exfil template) — the URL is the
            # IoC; the Domain-Name is only minted for a real FQDN.
            for payload in meta.get("jndi_payloads") or []:
                url = payload.get("url")
                if url and url not in session.urls:
                    session.urls.append(url)
                host = payload.get("host")
                if host and host not in session.domains:
                    session.domains.append(host)

        # Mirror first-event meta onto session.meta for STIX builder use.
        if events:
            first_meta = events[0].meta
            for k in (
                "method", "uri", "body", "body_length", "body_truncated",
                "user_agent", "host_header", "matched_hints", "status",
                "jndi_payloads", "src_ip_invalid", "src_ip_raw",
                "src_ip_from_xff",
            ):
                if k in first_meta:
                    session.meta.setdefault(k, first_meta[k])
    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _scan_hints(
        uri: str, body: str, user_agent: str, headers: str = "",
    ) -> list[str]:
        """Return the list of regex-pattern strings that matched.

        We return the pattern string (``regex.pattern``) rather than the
        compiled regex so the result is JSON-serializable and easy to
        surface in the Note body.
        """
        hits: list[str] = []
        haystack = f"{uri}\n{body}\n{headers}"
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
    def _is_ip(value: str) -> bool:
        """True when ``value`` parses as an IPv4/IPv6 address.

        Mirrors ``stix_ids.canonical_ip``'s accept set; kept local so the
        parser layer stays free of STIX imports.
        """
        try:
            ipaddress.ip_address(value.strip())
        except (ValueError, AttributeError):
            return False
        return True

    @staticmethod
    def _header_values(doc: dict) -> str:
        """Newline-joined values of the legacy schema's ``header_*``
        fields, for hint scanning. Empty on the modern schema, which
        does not break out individual headers."""
        return "\n".join(
            str(v) for k, v in doc.items()
            if k.startswith("header_") and isinstance(v, (str, int, float))
        )

    @classmethod
    def _extract_jndi(
        cls, doc: dict, raw_src: str, uri: str, body: str, user_agent: str,
    ) -> list:
        """Recover distinct JNDI endpoints from every attacker-controlled
        field on the document.

        Deduped by recovered URL and capped: a single request carried the
        same payload in 11 fields in the observed sample, and we want one
        C2 observable out of it, not eleven.
        """
        seen: set[str] = set()
        out: list = []
        candidates = [raw_src, uri, body, str(user_agent)]
        candidates.extend(
            str(v) for k, v in doc.items()
            if k.startswith("header_") and isinstance(v, str)
        )
        for value in candidates:
            if not value or "${" not in value:
                continue
            for payload in extract_jndi(value):
                if payload.url in seen:
                    continue
                seen.add(payload.url)
                out.append(payload)
                if len(out) >= _MAX_JNDI_PER_EVENT:
                    return out
        return out

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
