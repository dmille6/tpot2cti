"""Honeyaml parser — YAML / IaC config-probe honeypot.

Honeyaml is a low-interaction HTTP honeypot whose entire purpose is
to capture attackers fishing for leaked Infrastructure-as-Code files:
`/.kube/config`, `/docker-compose.yml`, `/config.yaml`,
`/.aws/credentials`, etc.  Every request Honeyaml records is an
attempted credential / configuration leak — there is no "drive-by"
on this honeypot.

Per V1_SPEC.md §5.22:

  T-Pot doc fields used:
    src_ip, request_path, request_body

  Event correlation:
    one ES doc → one ParsedEvent → one AttackSession (default
    one-event-per-session correlator — each request is its own
    config-probe).

  Substance filter:
    Always substantive.  Honeyaml only listens for IaC config paths;
    by the time a request hits its log, the attacker has already
    declared scanning intent.  Per docs/LESSONS_LEARNED_FROM_V0.md
    §2 we still keep `has_substance()` explicit (returning True from
    a docstring-annotated override is clearer to future maintainers
    than relying on the BaseParser default).

  STIX emitted (by the orchestrator from session state):
    - IPv4-Addr
    - Sighting
    - Note with the attempted config path and any request_body
      (truncated — see `REQUEST_BODY_CAP` below).
"""

from __future__ import annotations

import logging
from typing import Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Maximum number of bytes of `request_body` we preserve in
#: `event.meta["request_body"]`.  Honeyaml probes occasionally carry a
#: large body (a credential POST replay, an exfil dump) — we cap it at
#: 4 KiB per V1_SPEC §5.22 to keep STIX bundles small while still
#: preserving enough context for analysts to identify the attack.
REQUEST_BODY_CAP = 4 * 1024


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class HoneyamlParser(BaseParser):
    """Parser for T-Pot's Honeyaml IaC-config probe honeypot."""

    type_name = "Honeyaml"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert one Honeyaml ES doc into a ParsedEvent.

        Returns None for malformed docs (no src_ip or @timestamp) per
        V1_SPEC §7.  The `request_path` and (truncated) `request_body`
        are stashed in meta for the downstream STIX builder to embed
        in the Note SDO.
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("honeyaml: doc missing src_ip; skipping")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("honeyaml: doc missing/unparseable @timestamp; skipping")
            return None

        request_path = str(
            doc.get("request_path")
            or doc.get("request_uri")
            or doc.get("path")
            or ""
        )

        # request_body may arrive as a string, dict, or list depending on
        # T-Pot version / content-type.  Normalize to a string and cap.
        raw_body = doc.get("request_body")
        if raw_body is None:
            body_str = ""
        elif isinstance(raw_body, (dict, list)):
            try:
                import json
                body_str = json.dumps(raw_body, separators=(",", ":"))
            except (TypeError, ValueError):
                body_str = str(raw_body)
        else:
            body_str = str(raw_body)

        if len(body_str) > REQUEST_BODY_CAP:
            body_str = body_str[:REQUEST_BODY_CAP]

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="Honeyaml",
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int(
                doc.get("dst_port") or doc.get("dest_port") or 80
            ),
            dst_ip=doc.get("dst_ip") or doc.get("dest_ip"),
            protocol="http",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        event.meta["request_path"] = request_path
        event.meta["request_body"] = body_str

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — one event per session, with request_path on urls
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events):
        """One-event-per-session, with `request_path` added to
        `session.urls` so downstream consumers can reach the attempted
        path off the session directly.
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
    # has_substance() — always True for Honeyaml
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Honeyaml probes are inherently substantive.

        Per V1_SPEC §5.22, Honeyaml only logs IaC-config probe attempts
        — there is no benign traffic to filter out.  Every request gets
        the full STIX graph (IPv4-Addr + Sighting + Note).
        """
        return True

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
register(HoneyamlParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = HoneyamlParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: bare config probe — should be substantive ─────────────
    bare_doc = {
        "@timestamp": now.isoformat(),
        "type": "Honeyaml",
        "src_ip": "203.0.113.50",
        "src_port": 50100,
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_path": "/config.yaml",
        "request_body": "",
        "geoip": {"country_iso_code": "US", "asn": 64500},
    }

    # ── Case 2: probe with a body (e.g. credential replay) ────────────
    body_doc = {
        "@timestamp": now.isoformat(),
        "type": "Honeyaml",
        "src_ip": "198.51.100.70",
        "src_port": 50101,
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_path": "/.kube/config",
        "request_body": '{"token":"eyJhbGc..."}',
        "geoip": {"country_iso_code": "RU", "asn": 12345},
    }

    # ── Case 3: oversized body — must be truncated to REQUEST_BODY_CAP
    big_body = "A" * (REQUEST_BODY_CAP + 1000)
    big_doc = {
        "@timestamp": now.isoformat(),
        "type": "Honeyaml",
        "src_ip": "198.51.100.71",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_path": "/docker-compose.yml",
        "request_body": big_body,
    }

    be = parser.parse(bare_doc)
    bo = parser.parse(body_doc)
    bg = parser.parse(big_doc)
    assert be and bo and bg, "parse failed"

    bs = parser.correlate([be])[0]
    bos = parser.correlate([bo])[0]
    bgs = parser.correlate([bg])[0]

    # Honeyaml is always substantive — drive-by AND substantive cases
    # both return True (that IS the contract here).
    assert parser.has_substance(bs) is True, "Honeyaml bare probe must be substantive"
    assert parser.has_substance(bos) is True, "Honeyaml body probe must be substantive"
    assert parser.has_substance(bgs) is True, "Honeyaml big-body probe must be substantive"

    # request_path / urls
    assert bs.urls == ["/config.yaml"]
    assert bos.urls == ["/.kube/config"]

    # truncation enforced
    assert len(bgs.events[0].meta["request_body"]) == REQUEST_BODY_CAP, (
        f"body cap broken: got {len(bgs.events[0].meta['request_body'])}"
    )

    print("OK")
