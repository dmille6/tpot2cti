"""Smoke test for the fallback parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
has_substance/STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.fallback as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_fallback_smoke():
    import os
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = FallbackParser()

    now = datetime.now(timezone.utc)

    # --- Case 1: brand-new honeypot type with src_ip ----------------------
    doc1 = {
        "@timestamp": now.isoformat(),
        "src_ip": "1.2.3.4",
        "dst_port": 4242,
        "t-pot_hostname": "node1",
        "type": "BrandNewHoneypot",
        "weird_field": "some payload",
        "geoip": {
            "country_iso_code": "RU",
            "country_name": "Russia",
            "city_name": "Moscow",
            "asn": 12345,
            "organization": "ExampleNet",
        },
    }

    e1 = parser.parse(doc1)
    assert e1 is not None, "case 1: parse should not return None"
    assert e1.src_ip == "1.2.3.4", "case 1: src_ip captured"
    assert e1.event_type == "BrandNewHoneypot", "case 1: type captured"
    assert e1.dst_port == 4242, "case 1: dst_port captured"
    print(f"case 1: parsed event src_ip={e1.src_ip} type={e1.event_type}")

    sessions1 = parser.correlate([e1])
    assert len(sessions1) == 1, "case 1: one event → one session"
    s1 = sessions1[0]
    assert parser.has_substance(s1), "case 1: fallback always substantive"

    # --- Case 2: same type again — WARNING must NOT re-fire ---------------
    doc2 = {
        "@timestamp": now.isoformat(),
        "src_ip": "5.6.7.8",
        "dst_port": 4242,
        "t-pot_hostname": "node1",
        "type": "BrandNewHoneypot",     # same type as case 1
    }
    warned_before = set(_warned_types)
    e2 = parser.parse(doc2)
    assert e2 is not None, "case 2: parse should not return None"
    assert _warned_types == warned_before, (
        f"case 2: WARNING should fire ONCE per type, but _warned_types changed: "
        f"{warned_before} → {_warned_types}"
    )
    print(f"case 2: _warned_types unchanged ({sorted(_warned_types)})")

    # --- Case 3: different unknown type, NO src_ip ------------------------
    doc3 = {
        "@timestamp": now.isoformat(),
        "t-pot_hostname": "node2",
        "type": "WeirdProtocol",
        "blob": {"foo": "bar"},
    }
    e3 = parser.parse(doc3)
    assert e3 is not None, "case 3: parse should not return None even without src_ip"
    assert e3.src_ip == "", "case 3: missing src_ip → empty string sentinel"
    assert "WeirdProtocol" in _warned_types, "case 3: new type triggers warning"
    print(f"case 3: parsed no-src_ip event type={e3.event_type}")

    # --- Build STIX via the builder for all three cases -------------------
    from tpot2cti.parsers.base import _smoketest_env
    _smoketest_env()
    from tpot2cti.config import load_config
    from tpot2cti.stix.builder import STIXBuilder

    cfg = load_config()
    builder = STIXBuilder(cfg)

    # Case 1: full graph (IPv4 + Indicator + Sighting + sensor + geoip)
    objs1 = builder.build_fallback_event(s1)
    types1 = {o["type"] for o in objs1}
    print(f"\ncase 1 built {len(objs1)} STIX objects: {sorted(types1)}")
    assert "ipv4-addr" in types1, "case 1: IPv4-Addr expected when src_ip present"
    assert "indicator" in types1, "case 1: IP Indicator expected"
    assert "sighting" in types1, "case 1: Sighting expected"
    # Post-refactor (LESSONS §7.1): no Note when src_ip present —
    # the per-event summary lives in the Sighting.description instead.
    assert "note" not in types1, (
        "case 1: Note should NOT be emitted when src_ip present "
        "(summary goes in Sighting.description)"
    )
    sighting1 = next(o for o in objs1 if o["type"] == "sighting")
    assert sighting1.get("description"), "case 1: Sighting missing description"
    assert "BrandNewHoneypot" in sighting1["description"], \
        f"case 1: sighting description should name the unknown type, got {sighting1['description']!r}"

    # Case 3: no src_ip — Note IS emitted as the only surface (Sighting
    # can't exist without an IP indicator).
    s3 = parser.correlate([e3])[0]
    objs3 = STIXBuilder(cfg).build_fallback_event(s3)
    types3 = {o["type"] for o in objs3}
    print(f"case 3 built {len(objs3)} STIX objects: {sorted(types3)}")
    assert "ipv4-addr" not in types3, "case 3: no IPv4-Addr without src_ip"
    assert "sighting" not in types3, "case 3: no Sighting without src_ip"
    assert "note" in types3, "case 3: free-floating Note expected without src_ip"

    note3 = next(o for o in objs3 if o["type"] == "note")
    assert "Source IP: missing" in note3["content"]
    assert "Destination port: missing" in note3["content"]

    print("\nSmoke test passed.")
