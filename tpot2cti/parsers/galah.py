"""Galah parser — LLM-driven HTTP/HTTPS web honeypot.

See docs/parsers/galah.md for protocol/ES-field/STIX/substance notes.
"""

from __future__ import annotations

import json as _json
import logging
import re
from typing import Iterable, Optional
from urllib.parse import parse_qs

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent
from tpot2cti.parsers.h0neytr4p import (
    BODY_LENGTH_THRESHOLD,
    REQUEST_BODY_CAP,
    _EXPLOIT_USER_AGENTS,
    _WEB_EXPLOIT_HINTS,
)

logger = logging.getLogger(__name__)

#: Keys we treat as "username" candidates in form bodies and JSON payloads.
_USERNAME_KEYS = ("email", "username", "user", "login", "name", "uid")

#: Keys we treat as "password" candidates.
_PASSWORD_KEYS = ("password", "pass", "pwd", "passwd", "secret")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: HTTP request paths that signal a credential-spray target.  POSTs to
#: these are routed through the daily credentials Note aggregator (when
#: the Phase 6 cred-aggregation hook runs).
_CRED_CAPTURE_PATHS: list[re.Pattern] = [
    re.compile(r"^/(dashboard|login|signin|admin)/(login|auth|submit|signin)$",
               re.IGNORECASE),
    re.compile(r"^/api/v\d+/(login|auth|signin|token)$", re.IGNORECASE),
    re.compile(r"^/(wp-login\.php|blog/wp-login\.php)$", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class GalahParser(BaseParser):
    """Parser for T-Pot's Galah LLM-driven HTTP honeypot."""

    type_name = "Galah"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("galah: skipping doc with no src_ip")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            raw_ts = doc.get("timestamp")
            if raw_ts:
                ts = self._parse_timestamp({"@timestamp": raw_ts})
        if ts is None:
            logger.debug("galah: skipping doc with no parseable timestamp")
            return None

        # Field reads: prefer the flat dotted-key form (logrus default),
        # fall back to nested (in case logstash unflattens).
        method = self._read_request_field(doc, "method") or ""
        uri = self._read_request_field(doc, "requestURI") or ""
        body_raw = self._read_request_field(doc, "body") or ""
        body_sha = self._read_request_field(doc, "bodySha256") or ""
        ua = (
            self._read_request_field(doc, "userAgent")
            or self._read_request_field(doc, "headers.User-Agent")
            or ""
        )
        protocol_http = self._read_request_field(doc, "protocol") or ""

        # Reconstruct URL if Host header is present.
        host_header = (
            self._read_request_field(doc, "headers.Host")
            or self._read_request_field(doc, "host")
            or doc.get("host_header")
        )

        # response.metadata.* tells us if the response came from the LLM
        # or a static rule. Static-rule responses don't have these fields.
        llm_model = (
            self._read_dotted(doc, "response.metadata.model")
            or self._read_dotted(doc, "response", "metadata", "model")
        )
        llm_provider = (
            self._read_dotted(doc, "response.metadata.provider")
            or self._read_dotted(doc, "response", "metadata", "provider")
        )
        response_source = "llm" if llm_model else "static"

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or doc.get("sensorName")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="Galah",
            session_id=(doc.get("session") or None),
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int(doc.get("dest_port") or doc.get("dst_port")),
            dst_ip=(doc.get("dest_ip") or doc.get("dst_ip")),
            protocol="http",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── per-event signals stashed in meta ──────────────────────────
        event.meta["http_method"] = str(method).upper() if method else ""
        event.meta["http_uri"] = str(uri)
        event.meta["http_user_agent"] = str(ua)
        event.meta["http_protocol"] = str(protocol_http)
        event.meta["galah_response_source"] = response_source

        if llm_model:
            event.meta["llm_model"] = str(llm_model)
        if llm_provider:
            event.meta["llm_provider"] = str(llm_provider)

        # Body: cap to REQUEST_BODY_CAP for downstream Note; keep sha for
        # cross-event correlation regardless of cap.
        if body_raw:
            event.meta["http_body"] = str(body_raw)[:REQUEST_BODY_CAP]
            event.meta["http_body_length"] = len(str(body_raw))
        if body_sha:
            event.meta["http_body_sha256"] = str(body_sha)

        # URL reconstruction
        if host_header and uri:
            scheme = "https" if event.dst_port == 443 else "http"
            event.meta["http_url"] = f"{scheme}://{host_header}{uri}"
        if host_header:
            event.meta["http_host"] = str(host_header)

        # ── substance scoring (eval now, cache on meta) ───────────────
        method_upper = event.meta["http_method"]
        is_non_get = bool(method_upper) and method_upper != "GET"
        body_substantive = bool(body_raw) and len(str(body_raw)) > BODY_LENGTH_THRESHOLD
        uri_hint = any(p.search(str(uri)) for p in _WEB_EXPLOIT_HINTS) if uri else False
        ua_hint = any(p.search(str(ua)) for p in _EXPLOIT_USER_AGENTS) if ua else False
        cred_path = any(p.search(str(uri)) for p in _CRED_CAPTURE_PATHS) if uri else False

        substance = is_non_get or body_substantive or uri_hint or ua_hint
        event.meta["galah_substance"] = substance
        event.meta["galah_cred_capture_path"] = cred_path
        event.meta["galah_uri_hint"] = uri_hint
        event.meta["galah_ua_hint"] = ua_hint

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — default (one-event-per-session) plus credential pull
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events: Iterable[ParsedEvent]) -> list[AttackSession]:
        """One event per session (Galah is request-level, not session-
        level) — but we promote captured ``(username, password)`` pairs
        from POST bodies onto ``session.credentials_tried`` so the
        downstream daily-Note aggregator picks them up alongside the
        Heralding/Cowrie creds.

        Bodies parsed:
          - ``application/x-www-form-urlencoded`` (best-effort: looks
            for any ``email|username|user|login|name|uid`` key paired
            with ``password|pass|pwd|passwd|secret``).
          - ``application/json`` (same key heuristic).

        Multiple username/password keys in the same body produce one
        ``(user, pass)`` pair per username × password combination, capped
        at 4 to keep junk bodies from exploding session.credentials_tried.
        Bodies that don't parse cleanly are silently skipped — we already
        captured the raw body + sha in meta for the Note layer.
        """
        sessions = super().correlate(events)  # one-per-event default
        for s in sessions:
            for e in s.events:
                creds = self._extract_credentials(
                    e.meta.get("http_body", ""),
                    e.meta.get("http_method", ""),
                    e.raw_doc.get("request.headers.Content-Type")
                    or self._read_request_field(e.raw_doc, "headers.Content-Type")
                    or "",
                )
                for pair in creds:
                    if pair not in s.credentials_tried:
                        s.credentials_tried.append(pair)
        return sessions

    @classmethod
    def _extract_credentials(
        cls, body: str, method: str, content_type: str
    ) -> list[tuple[str, str]]:
        """Best-effort credential extraction from a POST body.

        Returns up to 4 ``(username, password)`` pairs.  Returns empty
        list for GET requests, empty bodies, or anything we can't parse.
        """
        if not body or method.upper() == "GET":
            return []
        ct = (content_type or "").lower()
        users: list[str] = []
        passwords: list[str] = []

        # JSON body (modern API spray)
        if "json" in ct or body.lstrip().startswith(("{", "[")):
            try:
                payload = _json.loads(body)
                # Top-level dict; walk one level deep into common
                # wrappers like {"data": {...}} or {"user": {...}}.
                candidates = [payload] if isinstance(payload, dict) else []
                if isinstance(payload, dict):
                    for k in ("data", "user", "credentials", "auth"):
                        v = payload.get(k)
                        if isinstance(v, dict):
                            candidates.append(v)
                for c in candidates:
                    for k, v in c.items():
                        if not isinstance(v, str):
                            continue
                        kl = k.lower()
                        if kl in _USERNAME_KEYS and v:
                            users.append(v)
                        elif kl in _PASSWORD_KEYS and v:
                            passwords.append(v)
            except (_json.JSONDecodeError, TypeError, ValueError):
                pass  # fall through to form parse

        # Form-urlencoded (browser/curl/spray-tool default)
        if not users and not passwords:
            try:
                form = parse_qs(body, keep_blank_values=False)
                for k, vs in form.items():
                    kl = k.lower()
                    if kl in _USERNAME_KEYS:
                        users.extend(vs)
                    elif kl in _PASSWORD_KEYS:
                        passwords.extend(vs)
            except (ValueError, TypeError):
                return []

        # Cross-pair, capped to 4 pairs
        pairs: list[tuple[str, str]] = []
        for u in users:
            for p in passwords:
                pair = (str(u), str(p))
                if pair not in pairs:
                    pairs.append(pair)
                    if len(pairs) >= 4:
                        return pairs
        return pairs

    # ──────────────────────────────────────────────────────────────────
    # has_substance()
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """A Galah session is one HTTP request.  Substantive when the
        per-event substance flag is True (see parse()) OR the request
        body yielded captured credentials.
        """
        if not session.events:
            return False
        if session.credentials_tried:
            return True
        return bool(session.events[0].meta.get("galah_substance"))

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

    @staticmethod
    def _read_request_field(doc: dict, key: str):
        """Read a Galah ``request.<key>`` value, handling both the
        flat-dotted form (logrus default — what we see in real T-Pot
        ES) and a nested form (if logstash later un-flattens via ruby).
        """
        # Flat dotted: doc["request.method"]
        flat_key = f"request.{key}"
        if flat_key in doc and doc[flat_key] not in (None, ""):
            return doc[flat_key]
        # Nested: doc["request"]["method"] — and for ``headers.Host``,
        # walk into ``doc["request"]["headers"]["Host"]``.
        node = doc.get("request")
        if not isinstance(node, dict):
            return None
        parts = key.split(".")
        for p in parts:
            if isinstance(node, dict) and p in node:
                node = node[p]
            else:
                return None
        return node if node not in (None, "") else None

    @staticmethod
    def _read_dotted(doc: dict, *path):
        """Read a value that may be flat-dotted at top level OR nested.

        ``_read_dotted(doc, "response.metadata.model")`` first tries
        ``doc["response.metadata.model"]``; ``_read_dotted(doc,
        "response", "metadata", "model")`` walks the nested form.
        """
        if len(path) == 1:
            return doc.get(path[0]) or None
        node = doc
        for p in path:
            if isinstance(node, dict) and p in node:
                node = node[p]
            else:
                return None
        return node if node not in (None, "") else None


# Register on import.
register(GalahParser())

# Galah emits a top-level `type` field in its event log for events
# where the LLM pipeline did anything (success, error, timeout, etc.).
# T-Pot's logstash sets `type => "Galah"` on the file input, but the
# `codec => json` parser overwrites that with whatever the JSON's own
# `type` key holds — so Galah events arrive in ES with type=
# "contentGenerationError" (the most common case — LLM timed out),
# "emptyLLMResponse", etc., instead of "Galah". Static-rule responses
# don't have a `type` field and survive correctly as "Galah".
#
# We register GalahParser under each known internal type so the
# dispatcher routes those events to us. parse() unconditionally sets
# event.event_type = "Galah" so downstream vocab/template lookups
# produce proper labels regardless of which alias was hit.
_GALAH_INTERNAL_TYPES = (
    "contentGenerationError",   # observed in real T-Pot ES: LLM call canceled
    "emptyLLMResponse",         # LLM returned empty body
    "failedResponse",           # generic LLM failure
    "invalidJSONResponse",      # observed 2026-06-02: LLM returned unparseable JSON
    "successfulResponse",       # speculative future case if Galah ever sets it
    "cacheHit",                 # speculative future case
)
for _internal in _GALAH_INTERNAL_TYPES:
    _aliased = GalahParser()
    _aliased.type_name = _internal
    register(_aliased)
