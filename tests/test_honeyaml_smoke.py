"""Smoke test for the honeyaml parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
has_substance/STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.honeyaml as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_honeyaml_smoke():
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
