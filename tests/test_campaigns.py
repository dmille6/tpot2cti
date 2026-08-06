"""Tests for tpot2cti.campaigns — shared-IoC Campaign grouping.

Covers artifact extraction, the >=2-distinct-IP threshold gate, the emitted
STIX shape (Campaign + indicates edges + related-to artifact SCO), and the
emitted-flag idempotency that stops popular artifacts re-emitting every cycle.
"""
from __future__ import annotations

from datetime import timedelta

from tpot2cti import campaigns
from tpot2cti.parsers.base import AttackSession, ParsedEvent
from tpot2cti.stix_ids import (
    generate_campaign_id,
    generate_cryptographic_key_id,
    generate_file_id,
    generate_ip_indicator_id,
)

_SHA = "a" * 64
_SHB = "b" * 64


def _fresh_builder(cfg):
    """A new STIXBuilder per call — mirrors main.run_cycle's per-cycle
    builder_factory(), so cross-cycle re-emission isn't swallowed by a single
    builder's per-bundle dedup."""
    from tpot2cti.stix.builder import STIXBuilder
    return STIXBuilder(cfg)


def _session(src_ip, now, *, malware=None, hassh=None, ja3=None, planted=None):
    ev = ParsedEvent(
        src_ip=src_ip, timestamp=now, sensor_hostname="node1",
        event_type="Cowrie", dst_port=22, protocol="tcp",
    )
    s = AttackSession.from_event(ev)
    if malware:
        s.malware_hashes.extend(malware)
    if hassh:
        s.hassh = hassh
    if ja3:
        s.ja3 = ja3
    if planted:
        s.planted_ssh_keys.extend(planted)
    return s


# ─── extraction ────────────────────────────────────────────────────────────

def test_extract_artifacts_all_types(now_utc):
    s = _session(
        "1.1.1.1", now_utc,
        malware=[_SHA.upper()],  # upper → must be lowercased
        hassh="hasshvalue123",
        ja3="ja3value456",
        planted=[{"fingerprint": "fp" * 20}],
    )
    arts = {a["type"]: a for a in campaigns.extract_artifacts(s)}
    # HASSH and JA3 are deliberately absent. They identify the SSH/TLS
    # LIBRARY the client was built against, not an actor — measured on the
    # live corpus, 217 of 243 generated campaigns clustered on one of them,
    # including a JA3 asserted to link 4 IPs that 468 IPs actually carried.
    # This assertion used to require them and so locked in the wrong SDO.
    assert set(arts) == {"malware", "ssh-key"}
    assert "hassh" not in arts and "ja3" not in arts, (
        "a tooling fingerprint is being materialised as a Campaign again"
    )
    assert arts["malware"]["value"] == _SHA  # lowercased
    assert arts["malware"]["key"] == f"malware:{_SHA}"


def test_extract_skips_garbage_hash_and_no_ip(now_utc):
    s = _session("2.2.2.2", now_utc, malware=["not-a-hash", ""])
    assert campaigns.extract_artifacts(s) == []
    s2 = _session("", now_utc, hassh="x")
    s2.src_ip = ""
    assert campaigns.extract_artifacts(s2) == []


# ─── threshold gate ──────────────────────────────────────────────────────────

def test_single_ip_does_not_make_a_campaign(state_db, cfg, now_utc):
    s = _session("3.3.3.3", now_utc, malware=[_SHA])
    keys = campaigns.record_session_artifacts(state_db, s)
    assert keys == [f"malware:{_SHA}"]
    objs = campaigns.emit_campaigns(state_db, _fresh_builder(cfg), keys)
    assert objs == []  # one IP → below MIN_CAMPAIGN_MEMBERS


def test_two_ips_sharing_malware_materialise_campaign(state_db, cfg, now_utc):
    key = f"malware:{_SHA}"
    # cycle 1: IP A only → no campaign
    campaigns.record_session_artifacts(state_db, _session("10.0.0.1", now_utc, malware=[_SHA]))
    assert campaigns.emit_campaigns(state_db, _fresh_builder(cfg), [key]) == []

    # cycle 2: IP B shares the same hash → campaign materialises
    later = now_utc + timedelta(minutes=20)
    keys2 = campaigns.record_session_artifacts(state_db, _session("10.0.0.2", later, malware=[_SHA]))
    objs = campaigns.emit_campaigns(state_db, _fresh_builder(cfg), keys2)

    by_type: dict[str, list] = {}
    for o in objs:
        by_type.setdefault(o["type"], []).append(o)

    # exactly one Campaign SDO, deterministic id
    assert len(by_type["campaign"]) == 1
    camp = by_type["campaign"][0]
    assert camp["id"] == generate_campaign_id(key)
    assert "shared-malware" in camp["labels"]
    assert camp["objective"]
    assert _SHA in camp["description"] and "2 distinct" in camp["description"]

    rels = by_type["relationship"]
    indicates = [r for r in rels if r["relationship_type"] == "indicates"]
    related = [r for r in rels if r["relationship_type"] == "related-to"]

    # one indicates edge per member IP (both, since both were pending)
    assert {r["source_ref"] for r in indicates} == {
        generate_ip_indicator_id("10.0.0.1"),
        generate_ip_indicator_id("10.0.0.2"),
    }
    assert all(r["target_ref"] == camp["id"] for r in indicates)
    # campaign → related-to → the File SCO
    assert len(related) == 1
    assert related[0]["source_ref"] == camp["id"]
    assert related[0]["target_ref"] == generate_file_id(_SHA)


def test_third_ip_adds_one_edge_no_duplicate(state_db, cfg, now_utc):
    # Uses a shared malware hash, not a HASSH — this test is about the
    # incremental-edge mechanism, and tooling fingerprints are no longer
    # campaign artifacts (they group a library, not an actor).
    key = f"malware:{_SHA}"
    a = _session("10.0.0.1", now_utc, malware=[_SHA])
    b = _session("10.0.0.2", now_utc + timedelta(minutes=5), malware=[_SHA])
    campaigns.record_session_artifacts(state_db, a)
    campaigns.record_session_artifacts(state_db, b)
    # first materialisation: 2 indicates edges
    first = campaigns.emit_campaigns(state_db, _fresh_builder(cfg), [key])
    n_ind_first = len([o for o in first if o.get("relationship_type") == "indicates"])
    assert n_ind_first == 2

    # re-emit with no new member → nothing (emitted gating)
    assert campaigns.emit_campaigns(state_db, _fresh_builder(cfg), [key]) == []

    # cycle 3: a third IP shares it → exactly ONE new indicates edge
    c = _session("10.0.0.3", now_utc + timedelta(minutes=40), malware=[_SHA])
    keys3 = campaigns.record_session_artifacts(state_db, c)
    third = campaigns.emit_campaigns(state_db, _fresh_builder(cfg), keys3)
    ind3 = [o for o in third if o.get("relationship_type") == "indicates"]
    assert len(ind3) == 1
    assert ind3[0]["source_ref"] == generate_ip_indicator_id("10.0.0.3")
    # the related-to target is the File SCO for the shared malware hash
    related = [o for o in third if o.get("relationship_type") == "related-to"]
    assert related[0]["target_ref"] == generate_file_id(_SHA)


def test_same_ip_twice_is_not_two_members(state_db, cfg, now_utc):
    """The same IP re-presenting an artifact must NOT cross the threshold."""
    # Uses a malware hash: a JA3 here would make this test VACUOUS, because
    # ja3 is no longer collected as an artifact, so emit_campaigns would
    # return [] without ever exercising same-IP de-duping.
    key = f"malware:{_SHA}"
    campaigns.record_session_artifacts(
        state_db, _session("9.9.9.9", now_utc, malware=[_SHA]))
    campaigns.record_session_artifacts(
        state_db, _session("9.9.9.9", now_utc + timedelta(minutes=10),
                           malware=[_SHA]))
    # Positive control: the rows ARE being recorded, so [] below means
    # "one IP is not two members", not "nothing was stored".
    assert campaigns.emit_campaigns(state_db, _fresh_builder(cfg), [key]) == []
    campaigns.record_session_artifacts(
        state_db, _session("9.9.9.8", now_utc + timedelta(minutes=20),
                           malware=[_SHA]))
    assert campaigns.emit_campaigns(state_db, _fresh_builder(cfg), [key]) != [], (
        "a SECOND distinct IP should cross the threshold — if this is empty "
        "the test above passed for the wrong reason"
    )
