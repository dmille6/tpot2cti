"""DR-01 SIP_FRAUD, the first real evidence class behind the DR-02 gate.

Owner decision 2026-09-27: a SentryPeer session is evidence only when it
dials an international number. parsers/sentrypeer.py sets ``is_intl_dial``
for the "+", "00", "011" and "9011" exit prefixes (DR-01 measurement M7);
evidence.decide() accepts on it and refuses every other SentryPeer session.
Every other parser type still gets the stub accept.
"""
from __future__ import annotations

import json
import logging
from types import SimpleNamespace

import pytest

from tests import dr02_harness as H
from tpot2cti import evidence
from tpot2cti.parsers.sentrypeer import SentryPeerParser
from tpot2cti.stix_ids import attacker_ip_indicator_id, attacker_ip_observable_id

GATE = "TPOT2CTI_EVIDENCE_GATE"
DECOUPLED = "TPOT2CTI_SIGHTINGS_DECOUPLED"
DAY = "2026-03-07"
IP_INTL = "45.20.0.1"
IP_REG = "45.20.0.2"


def _doc(ip, method, number=None, hhmm="10:00"):
    d = {"@timestamp": f"{DAY}T{hhmm}:00.000Z", "type": "Sentrypeer", "src_ip": ip,
         "dst_port": 5060, "sip_method": method, "t-pot_hostname": "pbx-test",
         "sip_user_agent": "friendly-scanner"}
    if number is not None:
        d["called_number"] = number
    return d


def _session(doc):
    p = SentryPeerParser()
    (s,) = p.correlate([p.parse(doc)])
    return s


# ---------------------------------------------------------------------------
# 1. The parser flag
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("number,intl", [
    ("+447700900123", True),        # ITU plus
    ("00525598160169", True),       # ITU 00
    ("000525598160169", True),      # 00 then a 0: still 00 + digits
    ("011525598160169", True),      # North American exit code
    ("9011442037699931", True),     # PBX outside line 9, then 011
    ("  011442037699931", True),    # the parser strips the value before matching
    ("+442037699931;", True),       # one trailing ";" seen in real data
    ("+1234abc", False),            # anything else after the digits
    ("0111234@sip", False),
    ("+44 20 7946 0000", False),    # formatted numbers are not decided
    ("+442037699931;;", False),
    ("+４４２０３７６９９９３１", False),  # non-ASCII digits (attacker-controlled value)
    ("900442037699931", True),      # PBX outside line 9, then 00 (owner, 2026-09-27)
    ("9000442037699931", True),     # as dialled in real data: 9, 00, then 0...
    ("9001", False),                # a 900x extension: fewer than four digits after 900
    ("900123", False),
    ("5551234", False),             # local
    ("12548044501", False),         # domestic NANP, no exit code
    ("9442037699931", False),       # outside line 9 without an exit code: not decided (M7), not flagged
    ("01125", False),               # 011 with fewer than four digits after it
    ("1001", False),                # extension
    ("", False),
])
def test_intl_dial_prefixes(number, intl):
    ev = SentryPeerParser().parse(_doc("198.51.100.9", "INVITE", number))
    assert bool(ev.meta.get("is_intl_dial")) is intl


# ---------------------------------------------------------------------------
# 2. decide()
# ---------------------------------------------------------------------------

def test_intl_invite_is_sip_fraud_evidence():
    d = evidence.decide(_session(_doc(IP_INTL, "INVITE", "011525598160169")), site="driveby")
    assert d == evidence.GateDecision(True, evidence.REASON_SIP_FRAUD)


@pytest.mark.parametrize("method,number", [
    ("REGISTER", None), ("OPTIONS", None), ("INVITE", "5551234"), ("INVITE", None)])
def test_sip_without_intl_dial_is_refused(method, number):
    d = evidence.decide(_session(_doc(IP_REG, method, number)), site="driveby")
    assert d == evidence.GateDecision(False, evidence.REASON_SIP_NO_EVIDENCE)


def test_the_flag_on_any_event_counts_even_if_session_meta_lacks_it():
    s = _session(_doc(IP_INTL, "INVITE", "+447700900123"))
    s.meta.pop("is_intl_dial")
    assert evidence.decide(s, site="driveby").accept


def test_an_intl_flag_on_another_type_does_not_matter():
    s = SimpleNamespace(event_type="Suricata", meta={"is_intl_dial": True}, events=[])
    assert evidence.decide(s, site="suricata") == \
        evidence.GateDecision(True, evidence.REASON_STUB_ACCEPT)


def test_other_parser_types_still_get_the_stub():
    for et in ("Cowrie", "Suricata", "Heralding", "Honeytrap", "Xyzpot"):
        s = SimpleNamespace(event_type=et, meta={}, events=[])
        assert evidence.decide(s, site="driveby") == \
            evidence.GateDecision(True, evidence.REASON_STUB_ACCEPT)


def test_reasons_are_bounded_counter_keys():
    for r in (evidence.REASON_SIP_FRAUD, evidence.REASON_SIP_NO_EVIDENCE):
        assert r.isascii() and " " not in r and len(r) <= 32


# ---------------------------------------------------------------------------
# 3. Through the builder
# ---------------------------------------------------------------------------

def _build(env, sessions):
    b = H._fixed_builder(H.make_cfg(env))
    objs = []
    for s in sessions:
        with b.session_context(s):
            objs.extend(b.build_sentrypeer_session(s))
    return b.finalize_bundle(objs), b


def _both():
    return [_session(_doc(IP_INTL, "INVITE", "9011442037699931", "10:00")),
            _session(_doc(IP_REG, "REGISTER", None, "10:05"))]


def _indicator_ids(objs):
    return {o["id"] for o in objs if o.get("type") == "indicator"}


def _sighted(objs):
    return {o["sighting_of_ref"] for o in objs if o.get("type") == "sighting"}


def test_sentrypeer_reaches_a_gated_site():
    objs, b = _build({GATE: "shadow", DECOUPLED: "true"}, _both())
    assert sum(b.gate_stats.site_calls.values()) == 2
    assert attacker_ip_indicator_id(IP_REG) in _indicator_ids(objs), "shadow must still emit it"


def test_shadow_changes_nothing_and_logs_the_would_refuse(caplog):
    baseline, _ = _build({}, _both())
    with caplog.at_level(logging.INFO, logger="tpot2cti.evidence"):
        objs, b = _build({GATE: "shadow", DECOUPLED: "true"}, _both())
    assert H.serialize(objs) == H.serialize(baseline)
    assert b.gate_stats.accepted == {evidence.REASON_SIP_FRAUD: 1}
    assert b.gate_stats.refused == {evidence.REASON_SIP_NO_EVIDENCE: 1}
    assert b.gate_stats.indicators_withheld == 0
    lines = [json.loads(r.getMessage()[len("evidence_gate "):]) for r in caplog.records
             if r.getMessage().startswith("evidence_gate ")]
    assert [(l["action"], l["reason"], l["src_ip"], l["event_type"], l["sessions"]) for l in lines] == \
        [("would-refuse", evidence.REASON_SIP_NO_EVIDENCE, IP_REG, "Sentrypeer", 1)]


def test_refusals_are_logged_once_per_address_per_bundle(caplog):
    sessions = [_session(_doc(IP_REG, "REGISTER", None, f"10:{i:02d}")) for i in range(40)]
    sessions += [_session(_doc("45.20.0.3", "OPTIONS", None, "11:00"))]
    with caplog.at_level(logging.INFO, logger="tpot2cti.evidence"):
        objs, b = _build({GATE: "shadow", DECOUPLED: "true"}, sessions)
        b.finalize_bundle(objs)  # a second finalize logs nothing more
    lines = [json.loads(r.getMessage()[len("evidence_gate "):]) for r in caplog.records
             if r.getMessage().startswith("evidence_gate ")]
    assert [(l["src_ip"], l["sessions"]) for l in lines] == [(IP_REG, 40), ("45.20.0.3", 1)]
    first = lines[0]
    assert first["first_seen"].startswith(f"{DAY}T10:00") and first["last_seen"].startswith(f"{DAY}T10:39")
    assert b.gate_stats.refused == {evidence.REASON_SIP_NO_EVIDENCE: 41}


def test_enforce_withholds_only_the_non_fraud_indicator_and_keeps_its_sighting():
    objs, b = _build({GATE: "enforce", DECOUPLED: "true"}, _both())
    ids = _indicator_ids(objs)
    assert attacker_ip_indicator_id(IP_INTL) in ids
    assert attacker_ip_indicator_id(IP_REG) not in ids
    assert attacker_ip_observable_id(IP_REG) in _sighted(objs), "the observable keeps its Sighting"
    assert b.gate_stats.indicators_withheld == 1
    assert b.gate_stats.site_calls["none"] == 0
    # nothing left pointing at the withheld Indicator
    withheld = attacker_ip_indicator_id(IP_REG)
    assert not [o for o in objs if withheld in json.dumps(o) and o.get("id") != withheld]


@pytest.mark.parametrize("invite_first", [False, True], ids=["register-first", "invite-first"])
def test_same_address_with_one_intl_invite_keeps_its_indicator_under_enforce(invite_first):
    sessions = [_session(_doc(IP_INTL, "REGISTER", None, "09:00")),
                _session(_doc(IP_INTL, "INVITE", "00525598160169", "09:01"))]
    if invite_first:
        sessions.reverse()
    objs, b = _build({GATE: "enforce", DECOUPLED: "true"}, sessions)
    assert attacker_ip_indicator_id(IP_INTL) in _indicator_ids(objs)
    assert b.gate_stats.refused == {evidence.REASON_SIP_NO_EVIDENCE: 1}
    # indicators_withheld counts refused sessions, even when the Indicator survives
    assert b.gate_stats.indicators_withheld == 1
    assert b.gate_stats.relationships_dropped == 0 and b.gate_stats.object_refs_dropped == 0
