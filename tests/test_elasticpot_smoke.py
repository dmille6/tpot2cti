"""Smoke test for the elasticpot parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
has_substance/STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.elasticpot as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_elasticpot_smoke():
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = ElasticPotParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — bare GET / probe ───────────────────────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "ElasticPot",
        "src_ip": "203.0.113.10",
        "src_port": 51000,
        "dst_port": 9200,
        "t-pot_hostname": "node1",
        "request_url": "/",
        "request_method": "GET",
        "request_body": "",
        "geoip": {"country_iso_code": "US", "asn": 64500},
    }

    # ── Case 2: substantive — CVE-2014-3120 Groovy RCE ────────────────
    cve_body = (
        '{"size":1,"script_fields":{"x":{"script":'
        '"java.lang.Runtime.getRuntime().exec(\\"id\\")",'
        '"lang":"groovy"}}}'
    )
    cve_doc = {
        "@timestamp": now.isoformat(),
        "type": "ElasticPot",
        "src_ip": "198.51.100.20",
        "src_port": 52000,
        "dst_port": 9200,
        "t-pot_hostname": "node1",
        "request_url": "/_search",
        "request_method": "POST",
        "request_body": cve_body,
        "geoip": {"country_iso_code": "CN", "asn": 4134},
    }

    # ── Case 3: substantive — PUT (non-GET write) ─────────────────────
    put_doc = {
        "@timestamp": now.isoformat(),
        "type": "ElasticPot",
        "src_ip": "198.51.100.21",
        "dst_port": 9200,
        "t-pot_hostname": "node1",
        "request_url": "/foo/bar/1",
        "request_method": "PUT",
        "request_body": '{"any":"value"}',
    }

    # Parse + correlate
    de = parser.parse(driveby_doc)
    ce = parser.parse(cve_doc)
    pe = parser.parse(put_doc)
    assert de and ce and pe, "parse failed"

    ds = parser.correlate([de])[0]
    cs = parser.correlate([ce])[0]
    ps = parser.correlate([pe])[0]

    # has_substance assertions
    assert parser.has_substance(ds) is False, "drive-by must NOT be substantive"
    assert parser.has_substance(cs) is True, "CVE body must be substantive"
    assert parser.has_substance(ps) is True, "PUT must be substantive"

    # CVE was correctly identified
    assert ce.meta.get("matched_cve") == "CVE-2014-3120", (
        f"expected CVE-2014-3120, got {ce.meta.get('matched_cve')!r}"
    )

    # session.urls populated
    assert ds.urls == ["/"]
    assert cs.urls == ["/_search"]

    print("OK")
