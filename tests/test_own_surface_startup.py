"""TPOT2CTI_OWN_DOMAINS is required and fails closed (Codex review of 25ce2b8).

A missing, blank or partly invalid persona-domain list must stop every
tpot2cti process at startup — load_config() is the one place all of them
(core, lookup, blocklists, noisefloor, malware-ingest, selftest) go through —
rather than run with a silently smaller own-surface guard.
"""
from __future__ import annotations

import pytest

from tpot2cti import own_surface as OS
from tpot2cti.config import ConfigError, load_config

BASE = {
    "TPOT_HOST": "tpot.example",
    "OPENCTI_ADMIN_TOKEN": "00000000-0000-0000-0000-000000000000",
    "TPOT2CTI_CONNECTOR_ID": "00000000-0000-0000-0000-000000000001",
}


def _load(**over):
    env = dict(BASE)
    env.update(over)
    return load_config(env_dict=env)


def test_missing_is_a_config_error():
    with pytest.raises(ConfigError, match="TPOT2CTI_OWN_DOMAINS is required"):
        _load()


@pytest.mark.parametrize("blank", ["", "   ", ",", " , ,, "])
def test_blank_is_a_config_error(blank):
    with pytest.raises(ConfigError, match="TPOT2CTI_OWN_DOMAINS"):
        _load(TPOT2CTI_OWN_DOMAINS=blank)


@pytest.mark.parametrize("bad", [
    "com",                                   # bare label: would own a TLD
    "persona.example.com,local",             # one bad entry among good ones
    "persona.example.com,192.0.2.1",         # address: belongs in TPOT_HONEYPOT_IPS
    "2001:db8::1",
    "https://persona.example.com",           # URL, not a root
    "persona.example.com:443",               # port
    "persona.example.com/path",
    "pers ona.example.com",
    "-persona.example.com",                  # label with a leading hyphen
    "persona..example.com",
    "persona_example.com",
    "[::1]",
])
def test_any_invalid_entry_is_a_config_error(bad):
    with pytest.raises(ConfigError, match="invalid entr"):
        _load(TPOT2CTI_OWN_DOMAINS=bad)


def test_valid_values_are_canonicalised():
    cfg = _load(TPOT2CTI_OWN_DOMAINS=" Persona-A.Example.COM., persona-b.example.net,,"
                                     "*.persona-c.example.org, bücher.example.org")
    assert cfg.tpot.own_domains == frozenset({
        "persona-a.example.com", "persona-b.example.net",
        "persona-c.example.org", "xn--bcher-kva.example.org"})


def test_from_env_and_default_fail_closed(monkeypatch):
    with pytest.raises(OS.OwnDomainsError):
        OS.from_env({"TPOT2CTI_OWN_DOMAINS": "ok.example.com,bad"}, redactor=False)
    monkeypatch.delenv("TPOT2CTI_OWN_DOMAINS", raising=False)
    OS.set_default(None)
    try:
        with pytest.raises(OS.OwnDomainsError):
            OS.default()
    finally:
        OS.set_default(None)


def test_the_builder_takes_the_validated_config():
    from tpot2cti.stix.builder import STIXBuilder
    b = STIXBuilder(_load(TPOT2CTI_OWN_DOMAINS="persona.example.com"))
    assert b._own_surface.roots == frozenset({"persona.example.com"})
    assert b.build_url("https://db1.persona.example.com/x") is None
    assert b.own_surface_refused == {"url:persona-domain": 1}


def test_main_exits_before_connecting_when_the_list_is_missing(monkeypatch):
    """main() loads the config first; nothing (logging, OpenCTI, ES, the
    health server) starts when the guard cannot be configured."""
    import tpot2cti.main as M
    monkeypatch.delenv("TPOT2CTI_OWN_DOMAINS", raising=False)

    def _boom(*a, **k):
        raise AssertionError("main() went past load_config")
    monkeypatch.setattr(M, "setup_logging", _boom)
    monkeypatch.setattr(M, "_connect_opencti", _boom)
    with pytest.raises(ConfigError, match="TPOT2CTI_OWN_DOMAINS"):
        M.main()


def test_profile_rendering_fails_closed_without_configuration(monkeypatch):
    from tpot2cti.stix.rendering import render_attacker_profile_body
    monkeypatch.delenv("TPOT2CTI_OWN_DOMAINS", raising=False)
    OS.set_default(None)
    try:
        with pytest.raises(OS.OwnDomainsError):
            render_attacker_profile_body("203.0.113.1", [{
                "parser": "Tanner", "sample_urls_json": ["http://x.example.net/"]}])
    finally:
        OS.set_default(None)
