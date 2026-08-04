"""Smoke test for the wordpot parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.wordpot as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_wordpot_smoke():
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = WordpotParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — root probe ─────────────────────────────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Wordpot",
        "src_ip": "203.0.113.40",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_path": "/",
        "user_agent": "Mozilla/5.0 (compatible; SomeBot/1.0)",
        "geoip": {"country_iso_code": "US", "asn": 64500},
    }

    # ── Case 2: substantive — /wp-login.php brute-force ───────────────
    login_doc = {
        "@timestamp": now.isoformat(),
        "type": "Wordpot",
        "src_ip": "198.51.100.40",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_path": "/wp-login.php",
        "user_agent": "wpscan",
    }

    # ── Case 3: substantive — /xmlrpc.php ─────────────────────────────
    xmlrpc_doc = {
        "@timestamp": now.isoformat(),
        "type": "Wordpot",
        "src_ip": "198.51.100.41",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_path": "/xmlrpc.php",
        "user_agent": "curl/8.0",
    }

    # ── Case 4: substantive — plugin enumeration ──────────────────────
    plugin_doc = {
        "@timestamp": now.isoformat(),
        "type": "Wordpot",
        "src_ip": "198.51.100.42",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_path": "/wp-content/plugins/contact-form-7/readme.txt",
        "user_agent": "Mozilla/5.0",
    }

    # ── Case 5: substantive — wp-config disclosure attempt ────────────
    config_doc = {
        "@timestamp": now.isoformat(),
        "type": "Wordpot",
        "src_ip": "198.51.100.43",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_path": "/wp-config.php.bak",
        "user_agent": "Nmap NSE",
    }

    # ── Case 6: drive-by — robots.txt ─────────────────────────────────
    robots_doc = {
        "@timestamp": now.isoformat(),
        "type": "Wordpot",
        "src_ip": "203.0.113.41",
        "dst_port": 80,
        "t-pot_hostname": "node1",
        "request_path": "/robots.txt",
        "user_agent": "Googlebot",
    }

    de = parser.parse(driveby_doc)
    le = parser.parse(login_doc)
    xe = parser.parse(xmlrpc_doc)
    pe = parser.parse(plugin_doc)
    ce = parser.parse(config_doc)
    re_ = parser.parse(robots_doc)
    assert all((de, le, xe, pe, ce, re_)), "parse failed"

    ds = parser.correlate([de])[0]
    ls = parser.correlate([le])[0]
    xs = parser.correlate([xe])[0]
    ps = parser.correlate([pe])[0]
    cs = parser.correlate([ce])[0]
    rs = parser.correlate([re_])[0]

    # URL mirrored onto the session
    assert ls.urls == ["/wp-login.php"]

    print("OK")
