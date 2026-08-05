"""Syntactic qualification of what we publish.

Everything this project validates acts on the INPUT side. These are the first
checks on the OUTPUT — what actually reaches OpenCTI and, eventually, other
people's threat-intelligence platforms.
"""
from __future__ import annotations

import pytest

from tpot2cti.stix.builder import IANA_TLDS, valid_domain, valid_url


# ── domains: shape is not existence ──────────────────────────────────────

@pytest.mark.parametrize("value", [
    "huangxcdh.html",        # a filename
    "azenv.nethttp",         # protocol residue welded onto a real domain
    "718.xuelian.lpost",
    "718.xuelianpost",
])
def test_values_that_are_not_domains_are_refused(value):
    """All four reached OpenCTI as Domain-Name observables. The regex ends in
    `[a-z]{2,63}`, so ANY alphabetic trailing label passed as a TLD — shape was
    checked, existence never was."""
    assert valid_domain(value) is None


@pytest.mark.parametrize("value,expected", [
    ("ircd1.rotero.vc", "ircd1.rotero.vc"),      # real C2 seen live
    ("cdn-n5f.pages.dev", "cdn-n5f.pages.dev"),
    ("GOOGLE.COM.", "google.com"),               # canonicalised
    ("  Example.Com  ", "example.com"),
])
def test_real_domains_survive(value, expected):
    assert valid_domain(value) == expected


def test_ip_literals_are_not_domains():
    assert valid_domain("1.2.3.4") is None


def test_the_tld_list_is_real_and_not_truncated():
    """Guard the guard: if the data file went missing or half-parsed, every
    assertion above would pass vacuously against an empty allowlist."""
    assert len(IANA_TLDS) > 1000
    for tld in ("com", "vc", "dev", "online", "tech"):
        assert tld in IANA_TLDS
    for junk in ("html", "nethttp", "lpost"):
        assert junk not in IANA_TLDS


def test_reserved_documentation_tlds_are_accepted():
    """RFC 2606 names are valid by standard and absent from IANA's delegated
    root. Every sanitised fixture in this repo depends on them."""
    assert valid_domain("c2.malicious.example") == "c2.malicious.example"


# ── URLs: build_url had NO validation at all ─────────────────────────────

@pytest.mark.parametrize("value", [
    "/admin.php",                          # 2,468 of these reached OpenCTI
    "/",
    "Mozilla/5.0 (compatible; Bot/1.0)",   # a User-Agent, published as a URL
    "httpncoding: gzip, deflate,",         # an HTTP header fragment
    "pay.xzxwl.cn:443",                    # a CONNECT request line
    "http://azenv.nethttp/x",              # host fails the TLD check
    "",
])
def test_values_that_are_not_urls_are_refused(value):
    """A URL naming no host cannot be blocked, hunted or attributed by any
    consumer. 22% of the live URL corpus was bare request paths."""
    assert valid_url(value) is None


@pytest.mark.parametrize("value", [
    "https://evil.example/x",
    "http://1.2.3.4/a",
    "ftp://files.example/pkg",
])
def test_real_urls_survive(value):
    assert valid_url(value) == value


# ── the case where strict validation would destroy intelligence ──────────

def test_a_jndi_exfil_payload_survives_despite_an_unresolvable_host():
    """The highest-value thing this pipeline recovers, and the one shape a
    naive host check would delete.

    A Log4Shell exfil payload embeds an UNRESOLVED Log4j template inside the
    hostname so the victim leaks its Java version over DNS. The URL is
    EVIDENCE — the verbatim record of what was attempted — while the
    resolvable C2 zone is extracted separately and published as the
    Domain-Name observable, which is the actual IoC."""
    payload = "ldap://XFl0c-${sys:java.version}.c2.malicious.example/a"
    assert valid_url(payload) == payload
    # and the IoC half is a clean domain
    assert valid_domain("c2.malicious.example") == "c2.malicious.example"


@pytest.mark.parametrize("scheme", ["ldap", "ldaps", "rmi", "dns", "iiop", "nis"])
def test_every_jndi_provider_is_accepted(scheme):
    """log4shell.py recovers all of these; an http-only allowlist would have
    silently discarded every Log4Shell C2 the pipeline has ever found."""
    assert valid_url(f"{scheme}://c2.malicious.example/Exploit") is not None


def test_a_jndi_url_still_needs_a_netloc():
    assert valid_url("ldap:///Exploit") is None


# ── rejections must be counted, never silent ─────────────────────────────

def test_rejections_are_counted(builder):
    """A validator that drops values silently is indistinguishable from an
    extractor that never found any — a confusion this codebase has shipped
    more than once."""
    assert builder.build_url("/admin.php") is None
    assert builder.build_url("Mozilla/5.0") is None
    assert builder.build_domain("huangxcdh.html") is None
    assert builder.rejected_urls == 2
    assert builder.rejected_domains == 1
