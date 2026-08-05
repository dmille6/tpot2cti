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


# ── review findings, 2026-08-05 ──────────────────────────────────────────
# Every test below is a defect that six independent reviews found in the
# first cut of this branch. They are regression locks, not coverage padding.

def test_a_rejected_download_url_leaves_no_dangling_relationship(builder):
    """THE BLOCKER. `_link_download_chain` anchored the URL->File edge on
    `generate_url_id(url)` unconditionally. That was safe only while
    build_url accepted everything; once it can refuse, the edge points at an
    SCO that is never published — a dangling ref, which
    LESSONS_LEARNED_FROM_V0 §3 calls the costliest failure in this project."""
    from datetime import datetime, timezone
    from tpot2cti.parsers.base import AttackSession
    now = datetime(2026, 8, 5, tzinfo=timezone.utc)
    s = AttackSession(src_ip="198.51.100.9", session_id="s1",
                      sensor_hostname="sensor01", event_type="Cowrie",
                      first_seen=now, last_seen=now)
    sha = "a" * 64
    s.malware_hashes.append(sha)
    s.downloads = [{"sha256": sha, "url": "/admin.php"}]   # bare path, refused

    objs = builder._link_download_chain(s)
    ids = {o["id"] for o in objs}
    for o in objs:
        for ref in ("source_ref", "target_ref"):
            if ref in o and o[ref].startswith("url--"):
                assert o[ref] in ids, (
                    f"dangling ref: {o[ref]} is referenced but never emitted"
                )
    # `_link_download_chain` emits edges only (the File SCO is built by the
    # caller from session.malware_hashes), so the refused URL must cost
    # exactly this one edge and nothing else.
    assert not [o for o in objs if o["type"] == "relationship"
                and o["source_ref"].startswith("url--")], (
        "the URL->File edge was emitted for a URL that was never published"
    )


def test_a_valid_download_url_still_gets_its_edge(builder):
    """The positive control. Without it the test above passes vacuously the
    moment `_link_download_chain` stops emitting anything at all."""
    from datetime import datetime, timezone
    from tpot2cti.parsers.base import AttackSession
    now = datetime(2026, 8, 5, tzinfo=timezone.utc)
    s = AttackSession(src_ip="198.51.100.9", session_id="s2",
                      sensor_hostname="sensor01", event_type="Cowrie",
                      first_seen=now, last_seen=now)
    sha = "b" * 64
    s.malware_hashes.append(sha)
    s.downloads = [{"sha256": sha, "url": "http://evil.example/x.sh"}]

    objs = builder._link_download_chain(s)
    ids = {o["id"] for o in objs}
    rels = [o for o in objs if o["type"] == "relationship"
            and o["source_ref"].startswith("url--")]
    assert rels, "the URL->File edge disappeared for a perfectly good URL"
    assert all(r["source_ref"] in ids for r in rels)


def test_whitespace_padding_cannot_split_a_url_across_two_ids(builder):
    """valid_url strips; hashing the raw string anchored the edge on a
    different id than the SCO was published under."""
    from tpot2cti.stix_ids import generate_url_id
    from tpot2cti.stix.builder import valid_url
    padded = "  http://evil.example/x  "
    assert valid_url(padded) == "http://evil.example/x"
    assert generate_url_id(valid_url(padded)) == \
        generate_url_id("http://evil.example/x")


# ── false rejections of real IoCs ────────────────────────────────────────

def test_tftp_droppers_survive():
    """`_CMD_URL_RE` is written to extract tftp:// out of command
    transcripts — its own comment says "wget/curl/tftp droppers". If the
    scheme sets drift, the extractor mints a URL the validator throws away,
    silently, on the highest-confidence intel path there is."""
    from tpot2cti.stix.builder import _CMD_URL_RE, _URL_SCHEMES
    assert valid_url("tftp://185.62.190.11/bins.sh") is not None
    for scheme in ("http", "https", "ftp", "tftp"):
        assert scheme in _URL_SCHEMES, f"{scheme} extracted but not accepted"
        assert _CMD_URL_RE.match(f"{scheme}://h.example/x"), scheme


def test_onion_addresses_are_not_malformed():
    """RFC 7686 reserves .onion, so it is absent from the IANA root BY
    DESIGN — the same argument that already admits example/test/invalid."""
    assert valid_domain("3g2upl4pq6kufc4m.onion") == "3g2upl4pq6kufc4m.onion"
    assert valid_url("http://3g2upl4pq6kufc4m.onion/") is not None


def test_every_shipped_punycode_tld_is_actually_reachable():
    """All 151 xn-- entries in iana_tlds.txt were unreachable dead weight:
    _DOMAIN_RE ended in [a-z]{2,63}, which no A-label can ever match. The
    file shipped them, so the intent was plainly to accept them."""
    from tpot2cti.stix.builder import IANA_TLDS
    puny = sorted(t for t in IANA_TLDS if t.startswith("xn--"))
    assert puny, "no punycode TLDs shipped — has the list been truncated?"
    unreachable = [t for t in puny if valid_domain(f"example.{t}") is None]
    assert not unreachable, (
        f"{len(unreachable)} of {len(puny)} punycode TLDs are unreachable, "
        f"e.g. {unreachable[:3]}"
    )
    assert valid_domain("shop.xn--p1ai") == "shop.xn--p1ai"


# ── the JNDI exemption must stay an exemption ────────────────────────────

def test_the_jndi_exemption_is_not_a_general_bypass():
    """Keyed on the scheme alone, ANY attacker-controlled string carrying a
    JNDI scheme skipped host validation entirely. Only an unresolved
    template justifies the skip, because only a template is un-validatable
    by construction."""
    for bypass in ("ldap://ANYTHING-AT-ALL", "ldap://----/x",
                   "ldap://azenv.nethttp/x", "nds://../../etc/passwd",
                   "dns://Mozilla-5.0-compatible-Bot/x"):
        assert valid_url(bypass) is None, f"{bypass} bypassed host validation"


def test_a_templated_jndi_host_is_still_kept_verbatim():
    """The exemption's actual justification: an exfil payload embeds an
    unresolved Log4j template in the hostname so the victim leaks its Java
    version over DNS. The URL is the evidence and cannot be validated."""
    exfil = "ldap://x-${sys:java.version}.c2.example/a"
    assert valid_url(exfil) == exfil


def test_a_jndi_url_with_an_ordinary_host_takes_the_normal_path():
    """Narrowing the exemption must not start refusing good Log4Shell C2."""
    assert valid_url("ldap://c2.malicious.example/Exploit") is not None
    assert valid_url("rmi://c2.malicious.example:1099/Exploit") is not None


# ── ports ────────────────────────────────────────────────────────────────

def test_invalid_ports_are_refused():
    """urlsplit does not validate the port until `.port` is touched."""
    assert valid_url("http://evil.example:65536/a") is None
    assert valid_url("http://evil.example:bad/a") is None
    assert valid_url("http://evil.example:8080/a") is not None


# ── the counters must actually reach the operator ────────────────────────

def test_rejection_counters_are_surfaced_in_the_cycle_summary():
    """The counters existed but had no reader outside the test file. A
    counter nothing reports is the silent-drop defect with extra steps."""
    import inspect
    from tpot2cti import main
    src = inspect.getsource(main.run_cycle)
    assert '"rejected_urls": builder.rejected_urls' in src, (
        "rejected_urls is not in the cycle summary dict"
    )
    assert '"rejected_domains": builder.rejected_domains' in src, (
        "rejected_domains is not in the cycle summary dict"
    )
    assert "rejected_urls={builder.rejected_urls}" in src, (
        "rejected_urls is not in the cycle-complete log line"
    )
