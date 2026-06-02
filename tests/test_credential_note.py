"""Per-IP credential Note + cowrie successful-credential capture.

The Note is the ONLY credential thing that reaches OpenCTI — bulk pairs
stay in the credential store. So this pins: one Note per IP, attached to
the IP observable, accepted login flagged, body capped.
"""

from __future__ import annotations

from datetime import datetime, timezone

from tpot2cti.stix_ids import generate_credential_note_id, generate_ipv4_id


def _rows(n, accepted_idx=None):
    out = []
    for i in range(n):
        out.append({
            "username": f"user{i}", "password": f"pw{i}", "attempts": i + 1,
            "succeeded": (i == accepted_idx), "service": "ssh", "port": 22,
        })
    return out


def test_note_none_when_empty(builder):
    assert builder.build_ip_credential_note("1.2.3.4", []) is None


def test_note_attaches_to_ip_and_flags_accepted(builder):
    note = builder.build_ip_credential_note("1.2.3.4", _rows(3, accepted_idx=1))
    assert note["type"] == "note"
    assert note["id"] == generate_credential_note_id("1.2.3.4")   # deterministic/upsert
    assert note["object_refs"] == [generate_ipv4_id("1.2.3.4")]    # hangs off the IP
    assert "1 accepted" in note["abstract"]
    assert "✅" in note["content"]
    # The accepted pair (user1/pw1) is present in the table.
    assert "user1" in note["content"] and "pw1" in note["content"]


def test_note_caps_rows_but_keeps_accepted_first(builder):
    # 500 unique pairs, the accepted one buried near the end.
    note = builder.build_ip_credential_note(
        "5.6.7.8", _rows(500, accepted_idx=499), max_rows=50
    )
    assert "showing top 50" in note["content"]
    body = note["content"]
    # Accepted + highest-attempt pair is kept; the low-signal tail is capped out.
    assert "user499" in body          # accepted (and most attempts) → shown
    assert "user0 " not in body and "| user0 |" not in body  # capped out
    assert "Unique pairs:** 500" in body


def test_pipe_in_password_does_not_break_table(builder):
    note = builder.build_ip_credential_note(
        "9.9.9.9", [{"username": "a", "password": "p|w\nx", "attempts": 1,
                     "succeeded": False, "service": "ssh", "port": 22}]
    )
    # Escaped pipe, newline stripped — table stays one row.
    assert "p\\|w x" in note["content"]


def test_cowrie_captures_successful_credential():
    from tpot2cti.parsers.cowrie import CowrieParser
    now = datetime.now(timezone.utc)
    parser = CowrieParser()
    docs = [
        {"@timestamp": now.isoformat(), "type": "Cowrie", "src_ip": "1.2.3.4",
         "session": "s1", "eventid": "cowrie.login.failed",
         "username": "root", "password": "wrong", "dst_port": 22},
        {"@timestamp": now.isoformat(), "type": "Cowrie", "src_ip": "1.2.3.4",
         "session": "s1", "eventid": "cowrie.login.success",
         "username": "root", "password": "toor", "dst_port": 22},
    ]
    events = [parser.parse(d) for d in docs]
    sessions = parser.correlate([e for e in events if e])
    assert len(sessions) == 1
    s = sessions[0]
    assert s.auth_success is True
    assert s.successful_credential == ("root", "toor")
    assert ("root", "wrong") in s.credentials_tried
