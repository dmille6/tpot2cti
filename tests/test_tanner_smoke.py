"""Smoke test for the tanner parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
has_substance/STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.tanner as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_tanner_smoke():
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = TannerParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — attack_type unknown ────────────────────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Tanner",
        "src_ip": "203.0.113.50",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "url": "/",
        "attack_type": "unknown",
        "geoip": {"country_iso_code": "US", "asn": 64500},
    }

    # ── Case 2: substantive — SQLi ────────────────────────────────────
    sqli_doc = {
        "@timestamp": now.isoformat(),
        "type": "Tanner",
        "src_ip": "198.51.100.50",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "url": "/index.php?id=1' OR '1'='1",
        "attack_type": "sqli",
    }

    # ── Case 3: substantive — XSS (maps to T1189) ─────────────────────
    xss_doc = {
        "@timestamp": now.isoformat(),
        "type": "Tanner",
        "src_ip": "198.51.100.51",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "url": "/search?q=<script>alert(1)</script>",
        "attack_type": "xss",
    }

    # ── Case 4: substantive — cmd_exec via nested paths form ──────────
    cmd_doc = {
        "@timestamp": now.isoformat(),
        "type": "Tanner",
        "src_ip": "198.51.100.52",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "url": "/cgi-bin/x.sh?cmd=;id",
        "paths": [{"path": "/cgi-bin/x.sh", "attack_type": "cmd_exec"}],
    }

    # ── Case 5: drive-by — empty attack_type ──────────────────────────
    empty_doc = {
        "@timestamp": now.isoformat(),
        "type": "Tanner",
        "src_ip": "203.0.113.51",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "url": "/favicon.ico",
        "attack_type": "",
    }

    de = parser.parse(driveby_doc)
    se = parser.parse(sqli_doc)
    xe = parser.parse(xss_doc)
    ce = parser.parse(cmd_doc)
    ee = parser.parse(empty_doc)
    assert all((de, se, xe, ce, ee)), "parse failed"

    ds = parser.correlate([de])[0]
    ss = parser.correlate([se])[0]
    xs = parser.correlate([xe])[0]
    cs = parser.correlate([ce])[0]
    es = parser.correlate([ee])[0]

    assert parser.has_substance(ds) is False, "unknown must NOT be substantive"
    assert parser.has_substance(ss) is True, "sqli must be substantive"
    assert parser.has_substance(xs) is True, "xss must be substantive"
    assert parser.has_substance(cs) is True, "cmd_exec must be substantive"
    assert parser.has_substance(es) is False, "empty must NOT be substantive"

    # MITRE technique pre-resolved
    assert se.meta.get("mitre_technique") == {
        "id": "T1190", "name": "Exploit Public-Facing Application",
    }, f"sqli mapping wrong: {se.meta.get('mitre_technique')}"
    assert xe.meta.get("mitre_technique") == {
        "id": "T1189", "name": "Drive-by Compromise",
    }, f"xss mapping wrong: {xe.meta.get('mitre_technique')}"
    assert ce.meta.get("attack_type") == "cmd_exec"
    assert ce.meta.get("mitre_technique", {}).get("id") == "T1190"

    # URL mirrored onto the session
    assert ss.urls == ["/index.php?id=1' OR '1'='1"]

    print("OK")
