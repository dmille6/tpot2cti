"""Per-type builder families: malware-drop, fingerprint, protocol.

Plus the regression guard that EVERY registered honeypot type routes to a
dedicated builder (only genuinely-unknown types may hit the fallback) — the
"no generic parsers" requirement.
"""

from __future__ import annotations

from datetime import datetime, timezone

import tpot2cti.parsers as P
from tpot2cti.main import _PARSER_DISPATCH
from tpot2cti.parsers.base import AttackSession, ParsedEvent
from tpot2cti.stix import builder as B

_SHA = "a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2"


def _session(etype, *, ip="203.0.113.5", meta=None, **kw):
    ev = ParsedEvent(
        src_ip=ip, timestamp=datetime.now(timezone.utc), sensor_hostname="s1",
        event_type=etype, dst_port=kw.pop("dst_port", 80),
        src_country_code="DE", src_asn=64512,
    )
    ev.meta = dict(meta or {})
    s = AttackSession.from_event(ev)
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def _kinds(objs):
    k = {}
    for o in objs:
        k[o["type"]] = k.get(o["type"], 0) + 1
    return k


# --- regression guard: no honeypot type falls back to generic ---------------
def test_every_registered_type_has_dedicated_builder():
    generic = [t for t in P.registered_types()
               if _PARSER_DISPATCH.get(P.get_parser(t).type_name) is None]
    assert generic == [], f"types hitting the generic fallback: {generic}"
    # And each named builder method actually exists.
    for name in set(_PARSER_DISPATCH.values()):
        assert hasattr(B.STIXBuilder, name), f"missing builder method {name}"


# --- malware-drop family -----------------------------------------------------
def test_malware_family_emits_file_indicator_and_url(builder):
    s = _session("Dionaea", malware_hashes=[_SHA],
                 urls=["http://203.0.113.5/m.bin"], domains=["evil.example"])
    objs = builder.build_dionaea_session(s)
    k = _kinds(objs)
    assert k.get("file") == 1
    assert k.get("indicator", 0) >= 2          # IP indicator + file indicator
    assert k.get("url") == 1
    assert k.get("domain-name") == 1
    # File-Indicator based-on File
    assert any(o["type"] == "relationship" and o["relationship_type"] == "based-on"
               and o["source_ref"].startswith("indicator--") for o in objs)


def test_malware_family_bare_connection_is_base_graph(builder):
    objs = builder.build_adbhoney_session(_session("Adbhoney"))
    k = _kinds(objs)
    assert "file" not in k and "url" not in k    # nothing to add
    assert k.get("ipv4-addr") == 1               # base graph still present


# --- fingerprint family ------------------------------------------------------
def test_fingerprint_family_emits_cryptographic_keys(builder):
    s = _session("Fatt", hassh="ec7378c1a92f5a8d", ja3="769,47-53,0-10")
    objs = builder.build_fatt_session(s)
    assert _kinds(objs).get("cryptographic-key") == 2   # hassh + ja3
    # related-to the attacker IP
    assert any(o["type"] == "relationship" and o["relationship_type"] == "related-to"
               for o in objs)


# --- protocol family ---------------------------------------------------------
def test_protocol_family_attack_pattern_and_process_on_interaction(builder):
    s = _session("Redishoneypot", commands=["INFO", "CONFIG GET *"])
    objs = builder.build_redishoneypot_session(s)
    k = _kinds(objs)
    assert k.get("attack-pattern") == 1
    assert k.get("process") == 1
    ap = next(o for o in objs if o["type"] == "attack-pattern")
    assert ap["name"] == "Redis unauthorized-access attempt"
    assert any(o["type"] == "relationship" and o["relationship_type"] == "indicates"
               for o in objs)


def test_protocol_family_bare_probe_no_attack_pattern(builder):
    # single event, no commands, no meta → no AttackPattern minted
    objs = builder.build_conpot_session(_session("ConPot"))
    assert "attack-pattern" not in _kinds(objs)
    assert _kinds(objs).get("ipv4-addr") == 1     # base graph
