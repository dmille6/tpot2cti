"""Tests for behaviour-driven ATT&CK technique mapping."""
from __future__ import annotations

from datetime import datetime, timezone

from tpot2cti import attack_mapping
from tpot2cti.parsers.base import AttackSession, ParsedEvent
from tpot2cti.stix_ids import generate_ip_indicator_id


def _session(etype="Cowrie", ip="203.0.113.5", **kw):
    ev = ParsedEvent(src_ip=ip, timestamp=datetime(2026, 5, 22, tzinfo=timezone.utc),
                     sensor_hostname="s1", event_type=etype, dst_port=22)
    s = AttackSession.from_event(ev)
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def _ids(session):
    return [t[0] for t in attack_mapping.techniques_for_session(session)]


def test_no_signal_no_technique():
    assert attack_mapping.techniques_for_session(_session()) == []


def test_brute_force_and_password_guessing():
    assert _ids(_session(credentials_tried=[("root", "root")])) == ["T1110"]
    multi = _ids(_session(credentials_tried=[("a", "b"), ("c", "d")]))
    assert "T1110" in multi and "T1110.001" in multi


def test_valid_accounts_on_auth_success():
    assert "T1078" in _ids(_session(auth_success=True))


def test_command_exec_unix_shell_gating():
    # Cowrie is a unix shell → parent + .004
    cow = _ids(_session(etype="Cowrie", commands=["id", "uname -a"]))
    assert "T1059" in cow and "T1059.004" in cow
    # Redis runs "commands" but is NOT a unix shell → parent only
    red = _ids(_session(etype="Redishoneypot", commands=["CONFIG GET dir"]))
    assert red == ["T1059"]


def test_ingress_tool_transfer():
    assert "T1105" in _ids(_session(malware_hashes=["a" * 64]))
    assert "T1105" in _ids(_session(downloads=[{"sha256": "a" * 64, "url": "http://x/y"}]))


def test_ssh_key_persistence():
    ids = _ids(_session(planted_ssh_keys=[{"fingerprint": "fp"}]))
    assert "T1098" in ids and "T1098.004" in ids


def test_active_scanning_threshold():
    assert _ids(_session(dst_ports={22, 23})) == []          # below threshold
    scan = _ids(_session(etype="Honeytrap", dst_ports={1, 2, 3, 4}))
    assert "T1595" in scan and "T1595.001" in scan


def test_all_returned_ids_have_canonical_names():
    s = _session(etype="Cowrie", credentials_tried=[("a", "b"), ("c", "d")],
                 auth_success=True, commands=["wget x"], malware_hashes=["a" * 64],
                 planted_ssh_keys=[{"fingerprint": "fp"}], dst_ports={1, 2, 3})
    for tid, name in attack_mapping.techniques_for_session(s):
        assert attack_mapping.TECHNIQUES[tid] == name


# ─── builder integration ─────────────────────────────────────────────────────

def test_build_session_attack_patterns_shape(builder):
    s = _session(etype="Cowrie", commands=["id"], malware_hashes=["a" * 64])
    objs = builder.build_session_attack_patterns(s)
    aps = [o for o in objs if o["type"] == "attack-pattern"]
    rels = [o for o in objs if o["type"] == "relationship"]
    assert aps, "expected attack-patterns"
    # x_mitre_id set (the OpenCTI merge key) + canonical external ref
    for ap in aps:
        assert ap["x_mitre_id"].startswith("T1")
        assert ap["external_references"][0]["source_name"] == "mitre-attack"
    # every technique anchored to the IP indicator via indicates
    ip_ind = generate_ip_indicator_id(s.src_ip)
    assert rels and all(r["relationship_type"] == "indicates" for r in rels)
    assert all(r["source_ref"] == ip_ind for r in rels)
    assert {r["target_ref"] for r in rels} == {ap["id"] for ap in aps}


def test_build_session_attack_patterns_empty_paths(builder):
    assert builder.build_session_attack_patterns(_session()) == []          # no signal
    no_ip = _session(commands=["id"]); no_ip.src_ip = ""
    assert builder.build_session_attack_patterns(no_ip) == []               # no src_ip


def test_attack_patterns_dedupe_across_sessions(builder):
    """Regression for the 2026-07-19 ingestion outage.

    build_attack_pattern() must return None for an already-emitted
    technique (like every sibling build_* method) instead of re-minting
    the full SDO. Because build_session_attack_patterns() runs for EVERY
    session, the old ` or obj` fallback re-emitted the ~30 unique
    techniques once per substantive session — a busy catch-up window
    produced ~947k duplicate attack-pattern dicts that overflowed
    SQLite's bind-variable limit in the publisher's pre-dedup lookup.
    """
    s1 = _session(etype="Cowrie", commands=["id"], malware_hashes=["a" * 64])
    first = builder.build_session_attack_patterns(s1)
    first_aps = [o for o in first if o["type"] == "attack-pattern"]
    assert first_aps, "first session should emit its techniques"

    # A second session from the SAME IP mapping to the SAME techniques
    # must NOT re-emit those attack-pattern SDOs (they are already in the
    # bundle, collapsed by deterministic id).
    s2 = _session(etype="Cowrie", commands=["id"], malware_hashes=["a" * 64])
    second = builder.build_session_attack_patterns(s2)
    second_aps = [o for o in second if o["type"] == "attack-pattern"]
    assert second_aps == [], (
        "duplicate techniques from a second session must not be re-emitted "
        "(build_attack_pattern must honour _dedup, not fall back to `or obj`)"
    )


def test_build_attack_pattern_returns_none_on_duplicate(builder):
    """build_attack_pattern honours the builder's per-bundle dedup contract."""
    first = builder.build_attack_pattern("Brute Force", mitre_id="T1110")
    assert first is not None and first["type"] == "attack-pattern"
    assert builder.build_attack_pattern("Brute Force", mitre_id="T1110") is None
