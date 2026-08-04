"""Smoke test for the heralding parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.heralding as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_heralding_smoke():
    from datetime import datetime, timedelta, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = HeraldingParser()
    now = datetime.now(timezone.utc)

    base_doc = {
        "type": "Heralding",
        "t-pot_hostname": "node1",
        "src_ip": "203.0.113.10",
        "src_port": 55555,
        "dst_port": 22,
        "protocol": "ssh",
        "geoip": {
            "country_iso_code": "CN", "country_name": "China",
            "asn": 4134, "organization": "ChinaNet",
        },
    }

    # ── Case 1: drive-by — single touch, no credential captured ────────
    driveby_doc = {
        **base_doc,
        "@timestamp": now.isoformat(),
        "session_id": "drv-sess-1",
        # no username/password — connection opened but no auth attempt
    }

    # ── Case 2: substantive — multiple credential attempts ─────────────
    sub_docs = []
    for i, (u, p) in enumerate([("root", "root"), ("admin", "admin"),
                                 ("root", "123456"), ("user", "password")]):
        sub_docs.append({
            **base_doc,
            "@timestamp": (now + timedelta(seconds=i)).isoformat(),
            "session_id": "sub-sess-1",
            "username": u,
            "password": p,
        })

    # parse + correlate the drive-by
    drive_events = [parser.parse(driveby_doc)]
    drive_events = [e for e in drive_events if e is not None]
    assert len(drive_events) == 1, "drive-by parse failed"
    drive_sessions = parser.correlate(drive_events)
    assert len(drive_sessions) == 1
    drive_session = drive_sessions[0]
    print(f"drive-by:       events={drive_session.event_count} creds={len(drive_session.credentials_tried)}")

    # parse + correlate the substantive session
    sub_events = [parser.parse(d) for d in sub_docs]
    sub_events = [e for e in sub_events if e is not None]
    assert len(sub_events) == 4, f"expected 4 substantive events, got {len(sub_events)}"
    sub_sessions = parser.correlate(sub_events)
    assert len(sub_sessions) == 1, f"expected 1 session, got {len(sub_sessions)}"
    sub_session = sub_sessions[0]
    print(f"substantive:    events={sub_session.event_count} creds={len(sub_session.credentials_tried)}")
    print(f"                credentials_tried: {sub_session.credentials_tried}")
    print(f"                dst_ports:         {sorted(sub_session.dst_ports)}")
    print(f"                protocols:         {sorted(sub_session.protocols)}")
    assert len(sub_session.credentials_tried) == 4
    assert ("root", "root") in sub_session.credentials_tried
    assert 22 in sub_session.dst_ports
    assert "ssh" in sub_session.protocols

    # ── Case 3: substantive by event_count > 2 with no credentials ─────
    probe_docs = []
    for i in range(3):
        probe_docs.append({
            **base_doc,
            "@timestamp": (now + timedelta(seconds=i)).isoformat(),
            "session_id": "probe-sess-1",
            # no creds, just repeated protocol-layer touches
        })
    probe_events = [parser.parse(d) for d in probe_docs]
    probe_events = [e for e in probe_events if e is not None]
    probe_sessions = parser.correlate(probe_events)
    assert len(probe_sessions) == 1
    probe_session = probe_sessions[0]
    print(f"probe-cluster:  events={probe_session.event_count} creds={len(probe_session.credentials_tried)}")
    assert probe_session.event_count == 3

    print("OK")
