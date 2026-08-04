"""Smoke test for the ipphoney parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.ipphoney as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_ipphoney_smoke():
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = IppHoneyParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: Get-Printer-Attributes probe with structured attrs ─────
    get_attrs_doc = {
        "@timestamp": now.isoformat(),
        "type": "Ipphoney",
        "src_ip": "203.0.113.91",
        "src_port": 53000,
        "dst_port": 631,
        "t-pot_hostname": "node1",
        "request_attributes": {
            "operation-id": "0x000B",
            "attributes-charset": "utf-8",
            "attributes-natural-language": "en-us",
            "printer-uri": "ipp://victim.example.com:631/printers/main",
        },
        "geoip": {
            "country_iso_code": "BR",
            "country_name": "Brazil",
            "asn": 7738,
            "organization": "Telemar Norte Leste",
        },
    }

    # ── Case 2: minimal probe with no request_attributes ───────────────
    minimal_doc = {
        "@timestamp": now.isoformat(),
        "type": "Ipphoney",
        "src_ip": "198.51.100.55",
        "dst_port": 631,
    }

    # ── Case 3: oversized request_attributes — should truncate ─────────
    big_attrs_doc = {
        "@timestamp": now.isoformat(),
        "type": "Ipphoney",
        "src_ip": "192.0.2.123",
        "request_attributes": "A" * (ATTRIBUTES_BLOB_CAP + 500),
    }

    docs = [get_attrs_doc, minimal_doc, big_attrs_doc]
    events = [parser.parse(d) for d in docs]
    assert all(e is not None for e in events), "parse() returned None unexpectedly"
    print(f"parsed {len(events)} Ipphoney events")
    for e in events:
        attrs = e.meta.get("request_attributes")
        attrs_repr = (attrs[:60] + "...") if attrs and len(attrs) > 60 else attrs
        print(
            f"  src_ip={e.src_ip:<16} dst_port={e.dst_port} "
            f"attrs={attrs_repr!r}"
        )

    # The oversized doc should have been truncated at the cap.
    assert events[2].meta.get("request_attributes_truncated") is True
    assert len(events[2].meta["request_attributes"]) == ATTRIBUTES_BLOB_CAP

    sessions = parser.correlate(events)
    assert len(sessions) == 3, f"expected 3 sessions, got {len(sessions)}"
    print(f"\ncorrelated into {len(sessions)} session(s)")

    for s in sessions:
        has_attrs = "request_attributes" in s.meta
        print(
            f"  session src_ip={s.src_ip:<16} "
            f"has_attrs={has_attrs}"
        )

    # First session must carry the IPP attributes on session.meta.
    assert "request_attributes" in sessions[0].meta
    # Truncation flag carries through correlate().
    assert sessions[2].meta.get("request_attributes_truncated") is True

    # Malformed docs return None
    assert parser.parse({}) is None
    assert parser.parse({"src_ip": "1.2.3.4"}) is None

    print("\nOK")
