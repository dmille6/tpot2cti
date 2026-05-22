"""Tanner parser — SNARE/TANNER web-application honeypot.

SNARE serves cloned web pages and forwards each HTTP request to
TANNER, which classifies the request and writes a verdict into
Elasticsearch with an `attack_type` field: `sqli`, `rfi`, `lfi`,
`xss`, `cmd_exec`, `php_object_injection`, `crlf`, `xxe`, `template`,
or `unknown` when nothing fires.  Unlike Suricata (which alerts on
network signatures), TANNER's verdict is itself an HTTP-application
classification, so we map each attack_type directly onto a MITRE
ATT&CK technique.

Per V1_SPEC.md §5.17:

  T-Pot doc fields used:
    src_ip, url, attack_type (sqli, rfi, xss, etc.)

  Event correlation:
    one ES doc → one ParsedEvent → one AttackSession (default
    one-event-per-session correlator).  TANNER writes one verdict per
    HTTP request; there is no native cross-request session to merge.

  STIX emitted:
    - IPv4-Addr
    - URL
    - Sighting
    - AttackPattern matching attack_type (e.g. T1190 for sqli)

  Substance filter (per LESSONS_LEARNED_FROM_V0.md §2):
    A session is substantive iff `attack_type` is set to anything other
    than ``"unknown"`` or the empty string.  Mass scanners hitting `/`
    on a SNARE clone produce `attack_type: "unknown"` verdicts and are
    pure drive-by; classified attacks (sqli, rfi, lfi, xss, cmd_exec,
    php_object_injection, etc.) are substance.
"""

from __future__ import annotations

import logging
from typing import Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TANNER attack_type → MITRE ATT&CK technique mapping
# ---------------------------------------------------------------------------

#: Map TANNER's `attack_type` verdicts onto MITRE ATT&CK techniques.
#: Per V1_SPEC §5.17 the canonical example is ``sqli → T1190``
#: (Exploit Public-Facing Application).  We extend the mapping to the
#: full set of attack_type strings TANNER currently emits.
#:
#: Rationale per technique:
#:   - sqli / rfi / lfi / cmd_exec / php_object_injection / xxe / crlf /
#:     template — server-side exploitation of the public web app, so
#:     T1190 Exploit Public-Facing Application is the right bucket.
#:   - xss — targets the *user* of the public-facing app, not the app
#:     itself, so T1189 Drive-by Compromise is the right bucket.
_TANNER_TO_MITRE: dict[str, tuple[str, str]] = {
    "sqli":                 ("T1190", "Exploit Public-Facing Application"),
    "rfi":                  ("T1190", "Exploit Public-Facing Application"),
    "lfi":                  ("T1190", "Exploit Public-Facing Application"),
    "cmd_exec":             ("T1190", "Exploit Public-Facing Application"),
    "php_object_injection": ("T1190", "Exploit Public-Facing Application"),
    "xxe":                  ("T1190", "Exploit Public-Facing Application"),
    "crlf":                 ("T1190", "Exploit Public-Facing Application"),
    "template":             ("T1190", "Exploit Public-Facing Application"),
    "xss":                  ("T1189", "Drive-by Compromise"),
}

#: TANNER verdicts that are explicitly "no attack" — these get the
#: drive-by code path.  Per V1_SPEC §5.17 and LESSONS §2.
_TANNER_NO_ATTACK: frozenset[str] = frozenset({"", "unknown", "none"})


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class TannerParser(BaseParser):
    """Parser for T-Pot's TANNER web-application honeypot."""

    type_name = "Tanner"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert a TANNER ES doc into a ParsedEvent.

        Returns None for malformed docs (missing src_ip or @timestamp).
        Per V1_SPEC §5.17 we consume src_ip + url + attack_type; the
        rest of the doc rides along on raw_doc.

        T-Pot can express the attack_type either as a top-level string
        or nested under `paths[0].attack_type` depending on TANNER
        version; we look in both places.
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("tanner: doc missing src_ip; skipping")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("tanner: doc missing/unparseable @timestamp; skipping")
            return None

        url = str(doc.get("url") or doc.get("path") or "")
        attack_type = self._extract_attack_type(doc)

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="Tanner",
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int(doc.get("dst_port") or doc.get("dest_port") or 80),
            dst_ip=doc.get("dst_ip") or doc.get("dest_ip"),
            protocol="http",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        event.meta["url"] = url
        event.meta["attack_type"] = attack_type

        # Pre-resolve the MITRE technique so the builder doesn't need to
        # know about _TANNER_TO_MITRE.  Stored as {"id": "T1190",
        # "name": "Exploit Public-Facing Application"} or absent if
        # attack_type isn't classified or isn't in the mapping table.
        if attack_type and attack_type not in _TANNER_NO_ATTACK:
            mapping = _TANNER_TO_MITRE.get(attack_type)
            if mapping:
                event.meta["mitre_technique"] = {
                    "id": mapping[0],
                    "name": mapping[1],
                }
            else:
                logger.debug(
                    f"tanner: unknown attack_type {attack_type!r}; "
                    f"no MITRE technique attached"
                )

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — default one-event-per-session, plus session.urls
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events):
        """One-event-per-session, copying url onto session.urls so the
        substance filter and the STIX builder can reach it via the
        session directly.
        """
        sessions: list[AttackSession] = []
        for e in events:
            s = AttackSession.from_event(e)
            url = e.meta.get("url")
            if url:
                s.urls.append(str(url))
            sessions.append(s)
        return sessions

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — classified-attack filter
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Return True iff attack_type is anything other than
        ``""`` / ``"unknown"`` / ``"none"``.

        Per V1_SPEC §5.17 and LESSONS_LEARNED_FROM_V0.md §2 we want the
        full STIX graph (with AttackPattern) for every classified web
        attack TANNER catches; unclassified hits are drive-by.
        """
        if not session.events:
            return False
        attack_type = str(session.events[0].meta.get("attack_type") or "").lower()
        return attack_type not in _TANNER_NO_ATTACK

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_attack_type(doc: dict) -> str:
        """Pull the attack classification from a Tanner doc.

        Per 2026-05-22 field-name audit vs real ES exports the canonical
        location is

            response_msg.response.message.detection.name   (xss, sqli, ...)

        which is what Tanner's emulator API actually produces (100% of
        current docs). The legacy top-level ``attack_type`` and the
        nested ``paths[].attack_type`` forms are retained as fallbacks
        for older T-Pot versions but never appear in 2026 data.
        Returns "" if nothing is set.
        """
        # ── Modern shape: response_msg.response.message.detection.name ──
        rm = doc.get("response_msg")
        if isinstance(rm, dict):
            det = (
                ((rm.get("response") or {}).get("message") or {}).get("detection")
                or {}
            )
            if isinstance(det, dict):
                name = det.get("name")
                if isinstance(name, str) and name.strip():
                    return name.strip().lower()

        # ── Legacy top-level string form ───────────────────────────────
        top = doc.get("attack_type")
        if isinstance(top, str) and top.strip():
            return top.strip().lower()

        # ── Legacy paths[].attack_type list form ──────────────────────
        # Return the first non-"unknown" if any, else the first one we
        # see (covers all-unknown docs too).
        paths = doc.get("paths")
        if isinstance(paths, list):
            first: str = ""
            for p in paths:
                if not isinstance(p, dict):
                    continue
                at = p.get("attack_type")
                if isinstance(at, str) and at.strip():
                    at_lower = at.strip().lower()
                    if at_lower not in _TANNER_NO_ATTACK:
                        return at_lower
                    if not first:
                        first = at_lower
            if first:
                return first
        return ""

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


# Register on import
register(TannerParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = TannerParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — attack_type unknown ────────────────────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Tanner",
        "src_ip": "203.0.113.50",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "url": "/",
        "attack_type": "unknown",
        "geoip": {"country_iso_code": "US", "asn": 64500},
    }

    # ── Case 2: substantive — SQLi ────────────────────────────────────
    sqli_doc = {
        "@timestamp": now.isoformat(),
        "type": "Tanner",
        "src_ip": "198.51.100.50",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "url": "/index.php?id=1' OR '1'='1",
        "attack_type": "sqli",
    }

    # ── Case 3: substantive — XSS (maps to T1189) ─────────────────────
    xss_doc = {
        "@timestamp": now.isoformat(),
        "type": "Tanner",
        "src_ip": "198.51.100.51",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "url": "/search?q=<script>alert(1)</script>",
        "attack_type": "xss",
    }

    # ── Case 4: substantive — cmd_exec via nested paths form ──────────
    cmd_doc = {
        "@timestamp": now.isoformat(),
        "type": "Tanner",
        "src_ip": "198.51.100.52",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "url": "/cgi-bin/x.sh?cmd=;id",
        "paths": [{"path": "/cgi-bin/x.sh", "attack_type": "cmd_exec"}],
    }

    # ── Case 5: drive-by — empty attack_type ──────────────────────────
    empty_doc = {
        "@timestamp": now.isoformat(),
        "type": "Tanner",
        "src_ip": "203.0.113.51",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "url": "/favicon.ico",
        "attack_type": "",
    }

    de = parser.parse(driveby_doc)
    se = parser.parse(sqli_doc)
    xe = parser.parse(xss_doc)
    ce = parser.parse(cmd_doc)
    ee = parser.parse(empty_doc)
    assert all((de, se, xe, ce, ee)), "parse failed"

    ds = parser.correlate([de])[0]
    ss = parser.correlate([se])[0]
    xs = parser.correlate([xe])[0]
    cs = parser.correlate([ce])[0]
    es = parser.correlate([ee])[0]

    assert parser.has_substance(ds) is False, "unknown must NOT be substantive"
    assert parser.has_substance(ss) is True, "sqli must be substantive"
    assert parser.has_substance(xs) is True, "xss must be substantive"
    assert parser.has_substance(cs) is True, "cmd_exec must be substantive"
    assert parser.has_substance(es) is False, "empty must NOT be substantive"

    # MITRE technique pre-resolved
    assert se.meta.get("mitre_technique") == {
        "id": "T1190", "name": "Exploit Public-Facing Application",
    }, f"sqli mapping wrong: {se.meta.get('mitre_technique')}"
    assert xe.meta.get("mitre_technique") == {
        "id": "T1189", "name": "Drive-by Compromise",
    }, f"xss mapping wrong: {xe.meta.get('mitre_technique')}"
    assert ce.meta.get("attack_type") == "cmd_exec"
    assert ce.meta.get("mitre_technique", {}).get("id") == "T1190"

    # URL mirrored onto the session
    assert ss.urls == ["/index.php?id=1' OR '1'='1"]

    print("OK")
