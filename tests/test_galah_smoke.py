"""Smoke test for the galah parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.galah as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_galah_smoke():
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = GalahParser()
    now = datetime.now(timezone.utc)

    base = {
        "type": "Galah",
        "t-pot_hostname": "node2",
        "src_ip": "165.154.6.130",
        "src_port": "53118",
        "dest_port": "80",
        "session": "1779982737649292133_AbCdEf==",
        "geoip": {
            "country_iso_code": "RU",
            "country_name": "Russia",
        },
    }

    # ── Case 1: bare GET / — drive-by ──────────────────────────────────
    drive_doc = {
        **base,
        "@timestamp": now.isoformat(),
        "request.method": "GET",
        "request.requestURI": "/",
        "request.userAgent": "Mozilla/5.0 (X11; Linux)",
        "request.headers.Host": "dev.example.com",
    }
    ev = parser.parse(drive_doc)
    assert ev is not None
    parser.correlate([ev])
    print(f"GET-/ drive-by:         substance=False  url={ev.meta.get('http_url')}")

    # ── Case 2: GET /.env — exploit-hint URI → substantive ─────────────
    env_doc = {
        **base,
        "@timestamp": now.isoformat(),
        "request.method": "GET",
        "request.requestURI": "/.env",
        "request.userAgent": "curl/8.5.0",
    }
    ev = parser.parse(env_doc)
    parser.correlate([ev])
    assert ev.meta["galah_uri_hint"] is True
    print(f"GET-/.env hint:         substance=True   uri_hint=True")

    # ── Case 3: POST /dashboard/login — credential capture ─────────────
    cred_doc = {
        **base,
        "@timestamp": now.isoformat(),
        "request.method": "POST",
        "request.requestURI": "/dashboard/login",
        "request.body": "email=admin%40example.com&password=Password123%21",
        "request.bodySha256": "dcc07fe3821626a5067f4f1cdc502ace9af14b2d3814f70344e5a2b5707ef37d",
        "request.userAgent": "Mozilla/5.0",
        "response.metadata.model": "qwen2.5-coder:7b",
        "response.metadata.provider": "ollama",
    }
    ev = parser.parse(cred_doc)
    parser.correlate([ev])
    assert ev.meta["galah_cred_capture_path"] is True
    assert ev.meta["http_method"] == "POST"
    assert ev.meta["http_body"].startswith("email=")
    assert ev.meta["http_body_sha256"].startswith("dcc07fe38")
    assert ev.meta["galah_response_source"] == "llm"
    assert ev.meta["llm_model"] == "qwen2.5-coder:7b"
    print(f"POST-cred-capture:      substance=True   path={ev.meta['http_uri']}")
    print(f"  body[:60]:            {ev.meta['http_body'][:60]}")
    print(f"  body_sha:             {ev.meta['http_body_sha256'][:24]}...")
    print(f"  resp_source:          {ev.meta['galah_response_source']} ({ev.meta.get('llm_model')})")

    # ── Case 4: sqlmap UA on /index.php — UA-only substance ────────────
    sqlmap_doc = {
        **base,
        "@timestamp": now.isoformat(),
        "request.method": "GET",
        "request.requestURI": "/index.php?id=1",
        "request.userAgent": "sqlmap/1.7.2#stable (https://sqlmap.org)",
    }
    ev = parser.parse(sqlmap_doc)
    parser.correlate([ev])
    assert ev.meta["galah_ua_hint"] is True
    print(f"sqlmap UA:              substance=True   ua_hint=True")

    # ── Case 4b: cred extraction populates session.credentials_tried ─
    cred_sessions = parser.correlate([parser.parse(cred_doc)])
    assert len(cred_sessions) == 1
    assert ("admin@example.com", "Password123!") in cred_sessions[0].credentials_tried, (
        f"expected captured creds, got {cred_sessions[0].credentials_tried}"
    )
    print(f"cred-extract form:      pairs={cred_sessions[0].credentials_tried}")

    # ── Case 4c: JSON body cred extraction ─────────────────────────────
    json_doc = {
        **base,
        "@timestamp": now.isoformat(),
        "request.method": "POST",
        "request.requestURI": "/api/v1/auth",
        "request.headers.Content-Type": "application/json",
        "request.body": '{"username":"root","password":"toor"}',
    }
    json_sessions = parser.correlate([parser.parse(json_doc)])
    assert ("root", "toor") in json_sessions[0].credentials_tried
    print(f"cred-extract json:      pairs={json_sessions[0].credentials_tried}")

    # ── Case 5: nested-shape (logstash un-flattened) — same result ─────
    nested_doc = {
        **base,
        "@timestamp": now.isoformat(),
        "request": {
            "method": "POST",
            "requestURI": "/api/v2/exec",
            "body": "cmd=cat+%2Fetc%2Fpasswd",
            "bodySha256": "abc123",
            "userAgent": "exploit-tool/1.0",
        },
    }
    ev = parser.parse(nested_doc)
    parser.correlate([ev])
    assert ev.meta["http_method"] == "POST"
    assert "cmd=cat" in ev.meta["http_body"]
    print(f"nested-shape POST:      substance=True   method={ev.meta['http_method']}")

    print("OK")
