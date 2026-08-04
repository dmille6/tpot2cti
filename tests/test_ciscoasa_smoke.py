"""Smoke test for the ciscoasa parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.ciscoasa as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_ciscoasa_smoke():
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
    print(f"bare-probe:      payload={bool(bare_event.meta.get('payload'))} matched_cve={bare_event.meta.get('matched_cve')}")
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
    print(f"cve-2018-0101:   matched_cve={soap_event.meta.get('matched_cve')!r}  (expected 'CVE-2018-0101')")
    assert soap_event.meta.get("matched_cve") == "CVE-2018-0101"

    # ── Case 3: tcp_test PoC fingerprint ───────────────────────────────
    tcp_doc = {**base, "@timestamp": now.isoformat(),
               "payload": "tcp_test\r\n"}
    tcp_event = parser.parse(tcp_doc)
    assert tcp_event is not None
    tcp_sessions = parser.correlate([tcp_event])
    tcp = tcp_sessions[0]
    print(f"tcp_test:        matched_cve={tcp_event.meta.get('matched_cve')!r}  (expected 'CVE-2018-0101')")
    assert tcp_event.meta.get("matched_cve") == "CVE-2018-0101"

    # ── Case 4: unrelated junk payload — substantive but no CVE ────────
    junk_doc = {**base, "@timestamp": now.isoformat(),
                "payload": "GET / HTTP/1.0\r\n\r\n"}
    junk_event = parser.parse(junk_doc)
    junk_sessions = parser.correlate([junk_event])
    junk = junk_sessions[0]
    print(f"unrelated:       matched_cve={junk_event.meta.get('matched_cve')}  (expected None)")
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
