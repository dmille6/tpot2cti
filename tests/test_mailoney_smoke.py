"""Smoke test for the mailoney parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.mailoney as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_mailoney_smoke():
    from datetime import datetime, timedelta, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = MailoneyParser()
    now = datetime.now(timezone.utc)

    base = {
        "type": "Mailoney",
        "t-pot_hostname": "node1",
        "src_ip": "198.51.100.5",
        "src_port": 44444,
        "dst_port": 25,
        "geoip": {
            "country_iso_code": "RU", "country_name": "Russia",
            "asn": 12345, "organization": "ExampleNet",
        },
    }

    # ── Case 1: drive-by — EHLO + QUIT only, no creds, no DATA ─────────
    driveby_docs = [
        {**base, "@timestamp": now.isoformat(),
         "session_id": "drv-1", "commands": "EHLO scan.example.com"},
        {**base, "@timestamp": (now + timedelta(seconds=1)).isoformat(),
         "session_id": "drv-1", "commands": "QUIT"},
    ]
    drive_events = [parser.parse(d) for d in driveby_docs]
    drive_events = [e for e in drive_events if e is not None]
    drive_sessions = parser.correlate(drive_events)
    assert len(drive_sessions) == 1
    drive = drive_sessions[0]
    print(f"drive-by:    protocol_requests={drive.protocol_requests} creds={len(drive.credentials_tried)} has_data={drive.meta.get('has_data')}")

    # ── Case 2: substantive by commands — MAIL/RCPT/DATA ───────────────
    sub_docs = [
        {**base, "@timestamp": now.isoformat(),
         "session_id": "sub-1", "commands": ["EHLO bad.example.com"]},
        {**base, "@timestamp": (now + timedelta(seconds=1)).isoformat(),
         "session_id": "sub-1", "commands": ["MAIL FROM:<a@b.com>"]},
        {**base, "@timestamp": (now + timedelta(seconds=2)).isoformat(),
         "session_id": "sub-1", "commands": ["RCPT TO:<v@victim.org>"]},
        {**base, "@timestamp": (now + timedelta(seconds=3)).isoformat(),
         "session_id": "sub-1", "commands": ["DATA"],
         "data": "Subject: test\r\n\r\nhello\r\n.\r\n"},
        {**base, "@timestamp": (now + timedelta(seconds=4)).isoformat(),
         "session_id": "sub-1", "commands": ["QUIT"]},
    ]
    sub_events = [parser.parse(d) for d in sub_docs]
    sub_events = [e for e in sub_events if e is not None]
    sub_sessions = parser.correlate(sub_events)
    assert len(sub_sessions) == 1
    sub = sub_sessions[0]
    print(f"substantive: protocol_requests={sub.protocol_requests} "
          f"commands={sub.commands} has_data={sub.meta.get('has_data')}")
    # These land on `protocol_requests`, NOT `commands`. This assertion used
    # to require the opposite and so locked in the defect: an SMTP verb the
    # listener RECEIVED was recorded as a command someone RAN, which gave
    # every relay probe +25 score (75 vs a true 50), prose reading "ran N
    # shell command(s)", T1059 Command and Scripting Interpreter, and a
    # Process SDO whose command_line was "EHLO\nMAIL\nRCPT\nDATA".
    assert ("MAIL" in sub.protocol_requests and "RCPT" in sub.protocol_requests
            and "DATA" in sub.protocol_requests)
    assert sub.commands == [], (
        "a received SMTP verb is being reported as an executed command — "
        "every downstream consumer believes that field"
    )

    # ── Case 3: substantive by credentials — AUTH attempt ──────────────
    auth_docs = [
        {**base, "@timestamp": now.isoformat(),
         "session_id": "auth-1", "commands": "EHLO x"},
        {**base, "@timestamp": (now + timedelta(seconds=1)).isoformat(),
         "session_id": "auth-1", "commands": "AUTH LOGIN",
         "auth_user": "postmaster", "auth_pass": "password123"},
        {**base, "@timestamp": (now + timedelta(seconds=2)).isoformat(),
         "session_id": "auth-1", "commands": "QUIT"},
    ]
    auth_events = [parser.parse(d) for d in auth_docs]
    auth_events = [e for e in auth_events if e is not None]
    auth_sessions = parser.correlate(auth_events)
    assert len(auth_sessions) == 1
    auth = auth_sessions[0]
    print(f"auth:        protocol_requests={auth.protocol_requests} creds={auth.credentials_tried}")
    assert ("postmaster", "password123") in auth.credentials_tried

    # ── Case 4: no session_id → window correlator path ─────────────────
    win_docs = [
        {**base, "@timestamp": now.isoformat(), "commands": "EHLO w"},
        {**base, "@timestamp": (now + timedelta(seconds=10)).isoformat(),
         "commands": "MAIL FROM:<x@y>"},
        {**base, "@timestamp": (now + timedelta(seconds=20)).isoformat(),
         "commands": "QUIT"},
    ]
    win_events = [parser.parse(d) for d in win_docs]
    win_events = [e for e in win_events if e is not None]
    assert all(e.session_id is None for e in win_events)
    win_sessions = parser.correlate(win_events)
    assert len(win_sessions) == 1, f"window correlator should collapse to 1 session, got {len(win_sessions)}"
    win = win_sessions[0]
    print(f"window:      events={win.event_count} protocol_requests={win.protocol_requests}")

    print("OK")
