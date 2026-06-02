"""Smoke test for the miniprint parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
has_substance/STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.miniprint as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_miniprint_smoke():
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = MiniprintParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — port-9100 SYN-and-close, empty body / path ──
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Miniprint",
        "src_ip": "203.0.113.17",
        "src_port": 50300,
        "dst_port": 9100,
        "t-pot_hostname": "node1",
        "request_path": "",
        "request_body": "",
        "geoip": {"country_iso_code": "BR", "country_name": "Brazil"},
    }

    # ── Case 2: substantive — PJL job pushed via raw-print ─────────────
    substantive_doc = {
        "@timestamp": now.isoformat(),
        "type": "Miniprint",
        "src_ip": "198.51.100.33",
        "src_port": 33555,
        "dst_port": 9100,
        "t-pot_hostname": "node1",
        "request_path": "@PJL INFO STATUS",
        "request_body": (
            "@PJL ENTER LANGUAGE=POSTSCRIPT\n"
            "%!PS-Adobe-3.0\n"
            "/Helvetica findfont 12 scalefont setfont\n"
            "100 100 moveto (Hacked) show\n"
            "showpage\n"
        ),
        "geoip": {
            "country_iso_code": "CN",
            "country_name": "China",
            "asn": 4134,
            "organization": "ChinaNet",
        },
    }

    drive_event = parser.parse(driveby_doc)
    subs_event = parser.parse(substantive_doc)
    assert drive_event and subs_event, "parse failed"

    drive_session = parser.correlate([drive_event])[0]
    subs_session = parser.correlate([subs_event])[0]

    drive_has = parser.has_substance(drive_session)
    subs_has = parser.has_substance(subs_session)
    print(f"drive-by    has_substance: {drive_has}  (expected False)")
    print(f"substantive has_substance: {subs_has}  (expected True)")
    assert drive_has is False, "empty-path empty-body probe must be non-substantive"
    assert subs_has is True, "PJL job push must be substantive"

    # The substantive session must carry the request_path and body in
    # session.meta so the downstream Note builder can quote them.
    assert subs_session.meta.get("request_path", "").startswith("@PJL"), (
        f"expected @PJL request_path; got "
        f"{subs_session.meta.get('request_path')!r}"
    )
    assert "POSTSCRIPT" in subs_session.meta.get("request_body", ""), (
        "expected PostScript body fragment in session.meta.request_body"
    )
    assert subs_session.meta.get("matched_print_markers"), (
        "expected at least one print-marker hit on @PJL path"
    )

    # Also verify a path-only (empty body) PJL probe is substantive.
    path_only_doc = {
        **driveby_doc,
        "src_ip": "198.51.100.34",
        "request_path": "@PJL INFO ID",
        "request_body": "",
    }
    path_only_event = parser.parse(path_only_doc)
    assert path_only_event is not None
    path_only_session = parser.correlate([path_only_event])[0]
    assert parser.has_substance(path_only_session) is True, (
        "PJL path alone (empty body) should still be substantive"
    )

    print("OK")
