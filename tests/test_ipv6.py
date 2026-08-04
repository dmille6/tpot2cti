"""IPv6 attacker support in the STIX builder.

Before this, only `_IPV4_RE` existed: `build_ipv4` / `build_ip_indicator` /
`build_attacker_context` all returned None for IPv6, and the session
builders hardcoded `generate_ipv4_id(session.src_ip)` — so an IPv6 `src_ip`
produced NO observable, NO indicator, NO sighting (silent total loss), and
any relationship would have dangled. These tests pin the additive IPv6 path
and confirm IPv4 behaviour is unchanged.
"""
from __future__ import annotations

from datetime import datetime, timezone

from tpot2cti.parsers.base import AttackSession, ParsedEvent
from tpot2cti.stix_ids import (
    attacker_ip_indicator_id,
    attacker_ip_observable_id,
    canonical_ip,
    generate_ipv4_id,
    generate_ipv6_id,
)

_V6 = "2001:db8::dead:beef"
_V6_RAW = "2001:0DB8:0:0:0:0:DEAD:BEEF"  # non-canonical (expanded/uppercase) form of _V6


def _session(etype="Honeytrap", ip=_V6, **kw):
    ev = ParsedEvent(src_ip=ip, timestamp=datetime(2026, 8, 4, tzinfo=timezone.utc),
                     sensor_hostname="s1", event_type=etype, dst_port=443)
    s = AttackSession.from_event(ev)
    for k, v in kw.items():
        setattr(s, k, v)
    return s


# ── ID helpers ───────────────────────────────────────────────────────────

def test_generate_ipv6_id_deterministic_and_distinct():
    assert generate_ipv6_id(_V6) == generate_ipv6_id(_V6)
    assert generate_ipv6_id(_V6).startswith("ipv6-addr--")
    # An IPv6 id must never collide with an IPv4 id.
    assert generate_ipv6_id(_V6) != generate_ipv4_id("1.2.3.4")


# ── Observable builders ──────────────────────────────────────────────────

def test_build_ipv6_observable(builder):
    obj = builder.build_ipv6(_V6)
    assert obj is not None
    assert obj["type"] == "ipv6-addr"
    assert obj["value"] == _V6
    assert obj["id"] == generate_ipv6_id(_V6)


def test_build_ipv4_rejects_v6_and_build_ipv6_rejects_v4(builder):
    assert builder.build_ipv4(_V6) is None
    assert builder.build_ipv6("203.0.113.5") is None


def test_build_ip_observable_dispatches_both_families(builder):
    v4 = builder.build_ip_observable("203.0.113.5")
    v6 = builder.build_ip_observable(_V6)
    assert v4 and v4["type"] == "ipv4-addr"
    assert v6 and v6["type"] == "ipv6-addr"
    assert builder.build_ip_observable("not-an-ip") is None


def test_ipv6_canonicalization_stable_id(builder):
    """A non-canonical notation is normalized to the compressed form, and its
    id matches the canonical id (so the same address can't fork into two)."""
    obj = builder.build_ipv6("2001:0db8:0000:0000:0000:0000:dead:beef")  # expanded
    assert obj is not None
    assert obj["value"] == "2001:db8::dead:beef"                # compressed
    assert obj["id"] == generate_ipv6_id("2001:db8::dead:beef")
    # (A second build_ipv6 on the compressed form dedups to None within the
    # same bundle — same id — which is the correctness property we want.)


# ── Indicator ────────────────────────────────────────────────────────────

def test_build_ip_indicator_ipv6_pattern(builder):
    ind = builder.build_ip_indicator(_V6, session=_session())
    assert ind is not None
    assert ind["pattern"] == f"[ipv6-addr:value = '{_V6}']"
    assert ind["x_opencti_main_observable_type"] == "IPv6-Addr"


# ── End-to-end: a full driveby session over IPv6 ─────────────────────────

# ── Centralized canonical-id helpers (the fix for dangling refs) ─────────

def test_attacker_ip_ids_canonical_across_notations():
    """Every consumer (builder, attacker_profile, campaigns) mints ids via
    these helpers, so the same address in ANY notation must yield one id."""
    assert attacker_ip_observable_id(_V6_RAW) == attacker_ip_observable_id(_V6)
    assert attacker_ip_indicator_id(_V6_RAW) == attacker_ip_indicator_id(_V6)
    # ...and they equal the canonical-form ids.
    assert attacker_ip_observable_id(_V6_RAW) == generate_ipv6_id(_V6)


def test_helper_ids_match_emitted_builder_objects(builder):
    """The regression guard: an id from the helper (used by attacker_profile /
    campaigns / attack-pattern edges) MUST equal the id the builder emits for
    the SAME non-canonical IPv6 — otherwise those references dangle."""
    obs = builder.build_ipv6(_V6_RAW)
    ind = builder.build_ip_indicator(_V6_RAW, session=_session())
    assert obs["id"] == attacker_ip_observable_id(_V6_RAW)
    assert ind["id"] == attacker_ip_indicator_id(_V6_RAW)


def test_ipv4_mapped_ipv6_normalized_to_ipv4():
    """`::ffff:1.2.3.4` normalizes to IPv4 so an attacker isn't split across
    two observable families."""
    assert canonical_ip("::ffff:1.2.3.4") == ("ipv4", "1.2.3.4")
    assert attacker_ip_observable_id("::ffff:1.2.3.4") == generate_ipv4_id("1.2.3.4")


def test_malformed_ip_yields_no_id():
    for bad in ("", "not-an-ip", "1.2.3.04", "999.999.999.999", None):
        assert attacker_ip_observable_id(bad) is None
        assert attacker_ip_indicator_id(bad) is None


def test_non_canonical_ipv6_session_no_ip_dangling(builder):
    """End-to-end: a full session over a NON-canonical IPv6 has no dangling
    IP-observable or IP-indicator references (the exact bug the pre-merge
    review reproduced)."""
    objs = builder.build_cowrie_session(_session(etype="Cowrie", ip=_V6_RAW))
    ids = {o["id"] for o in objs}
    ip_ish = {o["id"] for o in objs if o["type"] in ("ipv6-addr", "ipv4-addr", "indicator")}
    for o in objs:
        if o["type"] == "relationship":
            for ref in (o["source_ref"], o["target_ref"]):
                # every IP/indicator reference must resolve to an emitted object
                if ref.split("--")[0] in ("ipv6-addr", "ipv4-addr", "indicator"):
                    assert ref in ids, f"dangling IP/indicator ref: {ref}"
    assert ip_ish, "expected ipv6-addr + indicator to be emitted"


def test_driveby_session_ipv6_emits_full_graph_without_dangling(builder):
    """The regression: an IPv6 attacker must produce an ipv6-addr observable,
    an indicator, and a sighting — with relationships anchored on the real
    ipv6-addr id (no dangling references)."""
    objs = builder.build_driveby_session(_session())
    by_type: dict[str, list] = {}
    for o in objs:
        by_type.setdefault(o["type"], []).append(o)

    assert by_type.get("ipv6-addr"), "no IPv6 observable emitted"
    assert not by_type.get("ipv4-addr"), "must not emit an IPv4 observable for a v6 attacker"
    assert by_type.get("indicator"), "no indicator emitted"
    assert by_type.get("sighting"), "no sighting emitted"

    # Every relationship/sighting ref must resolve to an object in the bundle
    # (i.e. the version-aware id wiring produced no dangling edges).
    ids = {o["id"] for o in objs}
    v6_id = by_type["ipv6-addr"][0]["id"]
    assert v6_id == generate_ipv6_id(_V6)
    for rel in by_type.get("relationship", []):
        assert rel["source_ref"] in ids and rel["target_ref"] in ids
    # The IP observable is referenced by at least one relationship or sighting.
    refd = {r["source_ref"] for r in by_type.get("relationship", [])} | \
           {r["target_ref"] for r in by_type.get("relationship", [])} | \
           {s.get("sighting_of_ref") for s in by_type.get("sighting", [])}
    assert v6_id in refd, "the IPv6 observable is not wired into the graph"
