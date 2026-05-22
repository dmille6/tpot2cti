"""CiscoASA parser — Cisco ASA emulator (CVE-2018-0101 and friends).

The Cisco ASA honeypot listens on the WebVPN/AnyConnect port (443) and
records the crafted XML payloads attackers send hunting for known
SSL-VPN vulnerabilities — most famously CVE-2018-0101 (a SOAP/XML
double-free in the WebVPN endpoint that yields unauthenticated RCE
against ASA software 9.x).  Because attackers don't probe a fake ASA
casually — internet background-radiation scanners are mostly looking
at much lower-hanging fruit on port 443 — every event captured here
is meaningful and substantive.  We do not apply a substance filter:
each probe gets the full STIX graph downstream.

Per V1_SPEC.md §5.13:

  T-Pot doc fields used:
    src_ip, payload

  Event correlation:
    one ES doc → one ParsedEvent → one AttackSession (the default
    one-event-per-session correlator; each TLS connection carrying a
    crafted payload is its own discrete attack record).

  Substance filter:
    Always substantive — every probe of a Cisco ASA emulator is
    worth recording (port 443 with crafted payload).

CVE-2018-0101 detection (per V1_SPEC.md §5.13):
    The published exploit POSTs a SOAP envelope containing a
    `<host>` element and a `<key>` element to the WebVPN endpoint;
    the malformed XML triggers the double-free.  We match
    conservatively on the conjunction of three substrings:
    `<host>`, `<key>`, and `webvpn` (case-insensitive).  We also
    accept payloads that begin with `tcp_test` — a fingerprint of one
    publicly-circulated PoC tool's connectivity probe.  When matched,
    we stash `matched_cve = "CVE-2018-0101"` in event.meta; otherwise
    we leave the field unset (downstream emits a generic
    AttackPattern instead of a CVE-tagged one).
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

#: Maximum payload length preserved in event.meta — 4 KiB matches the
#: cap V1_SPEC §5.13 implies; longer payloads get truncated with a
#: trailing marker so downstream Note builders don't ship megabytes.
_PAYLOAD_CAP_BYTES: int = 4096
_TRUNCATION_MARKER: str = "...[truncated]"

#: CVE id we report when the high-confidence pattern matches.
_CVE_2018_0101: str = "CVE-2018-0101"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class CiscoasaParser(BaseParser):
    """Parser for T-Pot's CiscoASA honeypot."""

    type_name = "Ciscoasa"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert a CiscoASA ES doc into a normalized ParsedEvent.

        Missing `src_ip` or `@timestamp` aborts parsing.  An absent
        `payload` is tolerated — the IP / port observation alone is
        still substantive (someone touched our fake ASA on 443).
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("ciscoasa: skipping doc with no src_ip")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("ciscoasa: skipping doc with unparseable @timestamp")
            return None

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="Ciscoasa",
            session_id=doc.get("session_id"),
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int((doc.get("dest_port") or doc.get("dst_port")) or 443),
            dst_ip=(doc.get("dest_ip") or doc.get("dst_ip")),
            protocol="https",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── Payload handling ──────────────────────────────────────────
        # `payload` may be str or bytes (older T-Pot indexed bytes
        # before logstash decoded them).  Normalize to str and truncate
        # to _PAYLOAD_CAP_BYTES to keep ParsedEvent.meta small.
        raw_payload = doc.get("payload")
        if isinstance(raw_payload, (bytes, bytearray)):
            try:
                payload = raw_payload.decode("utf-8", errors="replace")
            except Exception:
                payload = ""
        elif isinstance(raw_payload, str):
            payload = raw_payload
        else:
            payload = ""

        if payload:
            if len(payload) > _PAYLOAD_CAP_BYTES:
                event.meta["payload"] = (
                    payload[:_PAYLOAD_CAP_BYTES] + _TRUNCATION_MARKER
                )
                event.meta["payload_truncated"] = True
                event.meta["payload_len_original"] = len(payload)
            else:
                event.meta["payload"] = payload

            # CVE matching is deliberately conservative — we only
            # stash matched_cve on a high-confidence hit so downstream
            # Vulnerability emission is signal, not noise.
            cve = self._match_cve_2018_0101(payload)
            if cve:
                event.meta["matched_cve"] = cve

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — default one-event-per-session is correct here
    # ──────────────────────────────────────────────────────────────────
    # Per V1_SPEC §5.13: each exploit attempt is its own connection.
    # We inherit BaseParser.correlate (one event → one session) — no
    # override needed.

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — always True per V1_SPEC §5.13
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Always substantive — every probe of a fake Cisco ASA is
        meaningful (port 443 with crafted payload is not internet
        background radiation).  Per V1_SPEC §5.13.
        """
        return True

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _match_cve_2018_0101(payload: str) -> Optional[str]:
        """Conservative pattern match for CVE-2018-0101 / known PoCs.

        High-confidence hit when EITHER:
          - the payload contains all three of `<host>`, `<key>`, and
            `webvpn` (case-insensitive) — the classic SOAP-envelope
            shape of the published exploit, OR
          - the payload starts with `tcp_test` — fingerprint of a
            widely-circulated public PoC connectivity probe.

        We deliberately do not match looser shapes (e.g. any XML on
        443) — false positives here would dilute the value of CVE
        Vulnerability emissions downstream.
        """
        if not payload:
            return None

        # Liberal detection at the start-of-payload PoC fingerprint
        stripped = payload.lstrip()
        if stripped.lower().startswith("tcp_test"):
            return _CVE_2018_0101

        lowered = payload.lower()
        if "<host>" in lowered and "<key>" in lowered and "webvpn" in lowered:
            return _CVE_2018_0101

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
register(CiscoasaParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = CiscoasaParser()
    now = datetime.now(timezone.utc)

    base = {
        "type": "Ciscoasa",
        "t-pot_hostname": "node1",
        "src_ip": "192.0.2.13",
        "src_port": 51111,
        "dst_port": 443,
        "geoip": {
            "country_iso_code": "US", "country_name": "United States",
            "asn": 64512, "organization": "ExampleNet",
        },
    }

    # ── Case 1: bare probe (no payload) — still substantive ────────────
    bare_doc = {**base, "@timestamp": now.isoformat()}
    bare_event = parser.parse(bare_doc)
    assert bare_event is not None
    bare_sessions = parser.correlate([bare_event])
    assert len(bare_sessions) == 1
    bare = bare_sessions[0]
    bare_has = parser.has_substance(bare)
    print(f"bare-probe:      payload={bool(bare_event.meta.get('payload'))} matched_cve={bare_event.meta.get('matched_cve')} substance={bare_has}  (expected True)")
    assert bare_has is True
    assert bare_event.meta.get("matched_cve") is None

    # ── Case 2: CVE-2018-0101 SOAP payload ─────────────────────────────
    soap_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
        '<SOAP-ENV:Body><config-auth client="vpn">'
        '<webvpn-private/><host>attacker</host><key>AAAA</key>'
        '</config-auth></SOAP-ENV:Body></SOAP-ENV:Envelope>'
    )
    soap_doc = {**base, "@timestamp": now.isoformat(), "payload": soap_payload}
    soap_event = parser.parse(soap_doc)
    assert soap_event is not None
    soap_sessions = parser.correlate([soap_event])
    soap = soap_sessions[0]
    soap_has = parser.has_substance(soap)
    print(f"cve-2018-0101:   matched_cve={soap_event.meta.get('matched_cve')!r} substance={soap_has}  (expected True / 'CVE-2018-0101')")
    assert soap_has is True
    assert soap_event.meta.get("matched_cve") == "CVE-2018-0101"

    # ── Case 3: tcp_test PoC fingerprint ───────────────────────────────
    tcp_doc = {**base, "@timestamp": now.isoformat(),
               "payload": "tcp_test\r\n"}
    tcp_event = parser.parse(tcp_doc)
    assert tcp_event is not None
    tcp_sessions = parser.correlate([tcp_event])
    tcp = tcp_sessions[0]
    tcp_has = parser.has_substance(tcp)
    print(f"tcp_test:        matched_cve={tcp_event.meta.get('matched_cve')!r} substance={tcp_has}  (expected True / 'CVE-2018-0101')")
    assert tcp_has is True
    assert tcp_event.meta.get("matched_cve") == "CVE-2018-0101"

    # ── Case 4: unrelated junk payload — substantive but no CVE ────────
    junk_doc = {**base, "@timestamp": now.isoformat(),
                "payload": "GET / HTTP/1.0\r\n\r\n"}
    junk_event = parser.parse(junk_doc)
    junk_sessions = parser.correlate([junk_event])
    junk = junk_sessions[0]
    junk_has = parser.has_substance(junk)
    print(f"unrelated:       matched_cve={junk_event.meta.get('matched_cve')} substance={junk_has}  (expected True / None)")
    assert junk_has is True
    assert junk_event.meta.get("matched_cve") is None

    # ── Case 5: oversize payload — truncated to 4 KiB ──────────────────
    big = "A" * (_PAYLOAD_CAP_BYTES + 1024)
    big_doc = {**base, "@timestamp": now.isoformat(), "payload": big}
    big_event = parser.parse(big_doc)
    assert big_event is not None
    assert big_event.meta.get("payload_truncated") is True
    assert big_event.meta.get("payload_len_original") == len(big)
    assert big_event.meta["payload"].endswith(_TRUNCATION_MARKER)
    print(f"oversize:        truncated={big_event.meta.get('payload_truncated')} original_len={big_event.meta.get('payload_len_original')}")

    print("OK")
