"""Smoke test for the suricata parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.suricata as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_suricata_smoke():
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = SuricataParser()

    now = datetime.now(timezone.utc)
    doc = {
        "@timestamp": now.isoformat(),
        "type": "Suricata",
        "src_ip": "5.6.7.8",
        "src_port": 41234,
        "dest_ip": "10.0.0.2",
        "dest_port": 443,
        "proto": "TCP",
        "flow_id": 1234567890,
        "t-pot_hostname": "node1",
        "geoip": {
            "country_iso_code": "RU", "country_name": "Russia",
            "city_name": "Moscow", "asn": 12389, "organization": "Rostelecom",
        },
        "alert": {
            "signature": "ET EXPLOIT Apache log4j CVE-2021-44228 RCE Attempt",
            "signature_id": 2034647,
            "category": "Web Application Attack",
            "severity": 1,
            "metadata": {
                "mitre_technique_id": "T1190",
                "mitre_tactic_id": "TA0001",
            },
        },
        "tls": {"sni": "victim.example.com"},
        "http": {"hostname": "victim.example.com", "url": "/api/v1/login"},
    }

    # 1. parse
    event = parser.parse(doc)
    assert event is not None, "parse() returned None"
    print(f"parsed event: src_ip={event.src_ip} sig_id={event.meta.get('signature_id')}")
    print(f"  mitre_techniques: {event.meta.get('mitre_techniques')}")
    print(f"  cves:             {event.meta.get('cves')}")
    print(f"  tls_sni:          {event.meta.get('tls_sni')}")

    # 2. correlate
    sessions = parser.correlate([event])
    assert len(sessions) == 1, f"expected 1 session, got {len(sessions)}"
    session = sessions[0]
    print(f"correlated into {len(sessions)} session(s); session_id={session.session_id}")

    # 3. build STIX via the builder (parser no longer owns build()).
    import os
    from tpot2cti.parsers.base import _smoketest_env
    _smoketest_env()
    from tpot2cti.config import load_config
    from tpot2cti.stix.builder import STIXBuilder

    cfg = load_config()
    builder = STIXBuilder(cfg)
    objects = builder.build_suricata_alert(session)
    print(f"\nbuilt {len(objects)} STIX objects:")
    by_type: dict[str, int] = {}
    for o in objects:
        by_type[o["type"]] = by_type.get(o["type"], 0) + 1
    for t, n in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"  {t:25s} {n}")

    # 5. Verify Vulnerability for CVE-2021-44228 and AttackPattern for T1190
    cve_names = {o.get("name") for o in objects if o["type"] == "vulnerability"}
    ap_ext_ids = {
        ref.get("external_id")
        for o in objects if o["type"] == "attack-pattern"
        for ref in (o.get("external_references") or [])
    }
    assert "CVE-2021-44228" in cve_names, f"missing CVE-2021-44228; got {cve_names}"
    assert "T1190" in ap_ext_ids, f"missing T1190 AttackPattern; got {ap_ext_ids}"
    print("\nVerified: CVE-2021-44228 Vulnerability + T1190 AttackPattern present.")

    # Also assert a Domain-Name was emitted from the TLS SNI
    domains = {o.get("value") for o in objects if o["type"] == "domain-name"}
    assert "victim.example.com" in domains, f"missing SNI domain; got {domains}"
    print(f"Verified: Domain-Name for TLS SNI present: {domains}")

    print("\nSmoke test passed.")
