"""Smoke test for the nginx parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.nginx as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_nginx_smoke():
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = NginxParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — vanilla GET / with 200 from a real-looking UA
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "NGINX",
        "src_ip": "203.0.113.40",
        "src_port": 50000,
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_uri": "/",
        "request_method": "GET",
        "status_code": 200,
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
        "geoip": {"country_iso_code": "US", "asn": 64500},
    }

    # ── Case 2: substantive — /.git/HEAD probe (scan signature)
    git_doc = {
        "@timestamp": now.isoformat(),
        "type": "NGINX",
        "src_ip": "198.51.100.60",
        "src_port": 50001,
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_uri": "/.git/HEAD",
        "request_method": "GET",
        "status_code": 404,
        "user_agent": "curl/8.0",
        "geoip": {"country_iso_code": "CN", "asn": 4134},
    }

    # ── Case 3: substantive — sqlmap UA against `/`
    sqlmap_doc = {
        "@timestamp": now.isoformat(),
        "type": "NGINX",
        "src_ip": "198.51.100.61",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_uri": "/index.php?id=1",
        "request_method": "GET",
        "status_code": 200,   # 200 alone wouldn't fire, but UA does
        "user_agent": "sqlmap/1.7.2#stable (https://sqlmap.org)",
    }

    # ── Case 4: substantive — 500 server error on otherwise clean URI
    err_doc = {
        "@timestamp": now.isoformat(),
        "type": "NGINX",
        "src_ip": "198.51.100.62",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_uri": "/api/v1/users",
        "request_method": "POST",
        "status_code": 500,
        "user_agent": "Mozilla/5.0",
    }

    de = parser.parse(driveby_doc)
    ge = parser.parse(git_doc)
    se = parser.parse(sqlmap_doc)
    ee = parser.parse(err_doc)
    assert de and ge and se and ee, "parse failed"

    ds = parser.correlate([de])[0]
    gs = parser.correlate([ge])[0]
    ss = parser.correlate([se])[0]
    es = parser.correlate([ee])[0]

    # session.urls populated from request_uri
    assert ds.urls == ["/"]
    assert gs.urls == ["/.git/HEAD"]

    print("OK")
