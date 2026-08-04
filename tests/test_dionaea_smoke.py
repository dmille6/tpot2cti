"""Smoke test for the dionaea parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.dionaea as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_dionaea_smoke():
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = DionaeaParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — SMB connection, no binary captured ──────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Dionaea",
        "src_ip": "203.0.113.7",
        "src_port": 41001,
        "dst_port": 445,
        "connection_protocol": "smbd",
        "t-pot_hostname": "node1",
        "geoip": {
            "country_iso_code": "CN",
            "country_name": "China",
            "asn": 4134,
            "organization": "ChinaNet",
        },
    }

    # ── Case 2: substantive — binary captured, hashes + URL present ────
    substantive_doc = {
        "@timestamp": now.isoformat(),
        "type": "Dionaea",
        "src_ip": "198.51.100.99",
        "src_port": 33222,
        "dst_port": 445,
        "connection_protocol": "smbd",
        "t-pot_hostname": "node1",
        "sha256": "AABBCCDDEEFF" + "00" * 26,    # 64 hex chars
        "md5": "11223344556677889900aabbccddeeff",
        "sha1": "0123456789abcdef0123456789abcdef01234567",
        "size_bytes": 142336,
        "download_url": "http://malware.example.com/payload.exe",
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

    # The substantive session must carry the primary hash, URL, and
    # derived domain in the session aggregates the orchestrator reads.
    assert subs_session.malware_hashes, "primary hash should be promoted"
    assert subs_session.urls == ["http://malware.example.com/payload.exe"]
    assert subs_session.domains == ["malware.example.com"]
    assert subs_session.meta.get("all_hashes", {}).get("md5"), "md5 in meta.all_hashes"
    assert subs_session.meta.get("connection_protocol") == "smbd"
    assert subs_session.meta.get("size_bytes") == 142336

    print("OK")
