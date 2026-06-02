"""Web/HTTP family builder — URL observables + AttackPattern + Vulnerability.

Every web honeypot (Galah, Tanner, H0neytr4p, ElasticPot, Ciscoasa, Wordpot,
NGINX, Honeyaml) routes through _build_web_session via its own dispatch entry.
On top of the base attacker graph it adds URL observables, and — only when
the parser flagged a technique/CVE — an AttackPattern and Vulnerability.
"""

from __future__ import annotations

from datetime import datetime, timezone

from tpot2cti.parsers.base import AttackSession, ParsedEvent


def _session(urls=(), meta=None, ip="203.0.113.9", etype="Tanner"):
    ev = ParsedEvent(
        src_ip=ip, timestamp=datetime.now(timezone.utc), sensor_hostname="s1",
        event_type=etype, dst_port=80, src_country_code="DE", src_asn=64512,
    )
    ev.meta = dict(meta or {})
    s = AttackSession.from_event(ev)
    s.urls = list(urls)
    return s


def _kinds(objs):
    k = {}
    for o in objs:
        k[o["type"]] = k.get(o["type"], 0) + 1
    return k


def test_web_emits_url_observables(builder):
    objs = builder.build_tanner_session(_session(urls=["http://203.0.113.9/wp-login.php"]))
    k = _kinds(objs)
    assert k.get("url") == 1
    assert k.get("ipv4-addr") == 1 and k.get("indicator") == 1   # base graph present
    # URL is related-to the attacker IP.
    assert any(o["type"] == "relationship" and o["relationship_type"] == "related-to"
               for o in objs)


def test_web_exploit_signals_emit_attack_pattern_and_vuln(builder):
    s = _session(
        urls=["http://203.0.113.9/?q=1"],
        meta={"attack_type": "sqli", "mitre_technique": "T1190",
              "matched_cve": "CVE-2021-44228"},
    )
    objs = builder.build_tanner_session(s)
    k = _kinds(objs)
    assert k.get("attack-pattern") == 1
    assert k.get("vulnerability") == 1
    ap = next(o for o in objs if o["type"] == "attack-pattern")
    assert ap["name"] == "sqli"
    assert ap["external_references"][0]["external_id"] == "T1190"
    v = next(o for o in objs if o["type"] == "vulnerability")
    assert v["name"] == "CVE-2021-44228"
    # IP indicator `indicates` both the AttackPattern and the Vulnerability.
    inds = [o for o in objs if o["type"] == "relationship"
            and o["relationship_type"] == "indicates"]
    assert len(inds) >= 2


def test_web_bare_probe_emits_no_attack_pattern(builder):
    # A plain GET with no technique/CVE signal must NOT mint an AttackPattern
    # or Vulnerability (avoid flooding OpenCTI with empty patterns).
    objs = builder.build_nginx_session(_session(urls=["http://203.0.113.9/"]))
    k = _kinds(objs)
    assert "attack-pattern" not in k
    assert "vulnerability" not in k
    assert k.get("url") == 1   # still emits the URL + base graph


def test_web_url_cap(builder):
    s = _session(urls=[f"http://203.0.113.9/p{i}" for i in range(100)])
    objs = builder.build_h0neytr4p_session(s)
    assert _kinds(objs).get("url") == 25   # _MAX_WEB_URLS


def test_all_web_types_dispatch_to_a_builder():
    from tpot2cti.main import _PARSER_DISPATCH
    from tpot2cti.stix import builder as B
    web = ["Galah", "Tanner", "H0neytr4p", "ElasticPot", "Ciscoasa",
           "Wordpot", "NGINX", "Honeyaml"]
    for t in web:
        assert t in _PARSER_DISPATCH, f"{t} not wired in _PARSER_DISPATCH"
        assert hasattr(B.STIXBuilder, _PARSER_DISPATCH[t])
