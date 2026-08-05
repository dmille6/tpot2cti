"""Forward-confirmed rDNS matching for rented scanner infrastructure."""
from __future__ import annotations

import pytest

from tpot2cti.benign_filter import BenignScannerFilter, ScannerRule
from tpot2cti.parsers.base import ParsedEvent
from tpot2cti.rdns import ForwardConfirmedRDNS, suffix_matches


class _FakeDNS:
    """PTR and forward maps under test control."""
    def __init__(self, ptr=None, fwd=None, raise_on=()):
        self.ptr, self.fwd, self.raise_on = ptr or {}, fwd or {}, set(raise_on)
        self.reverse_calls = 0
    def reverse(self, ip):
        self.reverse_calls += 1
        if ip in self.raise_on:
            raise OSError("simulated resolver failure")
        return self.ptr.get(ip)
    def forward(self, name):
        return self.fwd.get(name, [])


def _r(**kw):
    d = _FakeDNS(**kw)
    return d, ForwardConfirmedRDNS(resolver=d.reverse, forward_resolver=d.forward)


# ── the security property ────────────────────────────────────────────────

def test_an_unconfirmed_ptr_is_rejected():
    """THE reason this module exists. PTR records are set by whoever holds the
    address block, so an attacker can publish `scan-99.shadowserver.io` for
    their own host. Without forward confirmation that is an allowlist anyone
    can opt into — they would vanish from the intelligence by editing DNS."""
    dns, r = _r(ptr={"45.9.1.2": "scan-99.shadowserver.io"},
                fwd={"scan-99.shadowserver.io": ["184.105.139.69"]})  # not 45.9.1.2
    assert r.name_for("45.9.1.2") is None
    assert r.rejected_unconfirmed == 1


def test_a_confirmed_ptr_is_accepted():
    dns, r = _r(ptr={"184.105.139.69": "scan-03.shadowserver.io"},
                fwd={"scan-03.shadowserver.io": ["184.105.139.69"]})
    assert r.name_for("184.105.139.69") == "scan-03.shadowserver.io"
    assert r.confirmed == 1


def test_suffix_matching_respects_label_boundaries():
    """A plain endswith would let a lookalike domain into the allowlist."""
    assert suffix_matches("scan-03.shadowserver.io", "shadowserver.io")
    assert suffix_matches("shadowserver.io", "shadowserver.io")
    assert not suffix_matches("evil-shadowserver.io", "shadowserver.io")
    assert not suffix_matches("shadowserver.io.attacker.net", "shadowserver.io")


# ── failure is always "not a scanner" ────────────────────────────────────

@pytest.mark.parametrize("case", ["no_ptr", "resolver_error", "bad_ip"])
def test_every_uncertain_outcome_keeps_the_event(case):
    """Failing open KEEPS data. Dropping a real attacker because a resolver
    blipped is data loss; keeping a Shadowserver record is cosmetic."""
    if case == "no_ptr":
        _, r = _r(ptr={}); ip = "45.9.1.2"
    elif case == "resolver_error":
        _, r = _r(raise_on=["45.9.1.2"]); ip = "45.9.1.2"
    else:
        _, r = _r(); ip = "not-an-ip"
    assert r.name_for(ip) is None


# ── caching ──────────────────────────────────────────────────────────────

def test_results_are_cached_so_dns_is_not_hit_per_event():
    """match() runs per EVENT — millions per cycle. An uncached lookup would
    be a DNS query per event."""
    dns, r = _r(ptr={"184.105.139.69": "scan-03.shadowserver.io"},
                fwd={"scan-03.shadowserver.io": ["184.105.139.69"]})
    for _ in range(50):
        r.name_for("184.105.139.69")
    assert dns.reverse_calls == 1


def test_misses_are_cached_too_but_briefly():
    dns, r = _r(ptr={})
    for _ in range(10):
        r.name_for("45.9.1.2")
    assert dns.reverse_calls == 1
    assert r._negative_ttl < r._ttl, "a miss must expire sooner than a hit"


def test_the_cache_is_bounded():
    dns, r = _r(ptr={})
    r._max_entries = 50
    for i in range(200):
        r.name_for(f"45.9.{i // 256}.{i % 256}")
    assert len(r._cache) <= 50


# ── integration with the allowlist ───────────────────────────────────────

def _event(ip, asn=6939, org="Hurricane Electric LLC"):
    return ParsedEvent(src_ip=ip, timestamp=None, sensor_hostname="s1",
                       event_type="Cowrie", session_id="x",
                       src_asn=asn, src_as_org=org)


def test_shadowserver_on_rented_infrastructure_is_now_matched():
    """The live defect: 17 addresses were reaching `targeted:substantive`.
    Shadowserver scans from Hurricane Electric (AS6939), so ASN and org rules
    could never match, even though the vendor was already in the allowlist."""
    dns, r = _r(ptr={"184.105.139.69": "scan-03.shadowserver.io"},
                fwd={"scan-03.shadowserver.io": ["184.105.139.69"]})
    f = BenignScannerFilter(
        [ScannerRule(vendor="shadowserver", asns=frozenset({33038}),
                     org_keywords=("shadowserver",),
                     rdns_suffixes=("shadowserver.io",))],
        resolver=r)
    assert f.match(_event("184.105.139.69")) == "shadowserver"


def test_a_real_attacker_in_the_same_asn_is_untouched():
    """Hurricane Electric carries plenty of genuine attackers. Matching must
    key on the confirmed name, never on the shared ASN."""
    dns, r = _r(ptr={"184.105.139.69": "scan-03.shadowserver.io"},
                fwd={"scan-03.shadowserver.io": ["184.105.139.69"]})
    f = BenignScannerFilter(
        [ScannerRule(vendor="shadowserver", asns=frozenset(),
                     org_keywords=(), rdns_suffixes=("shadowserver.io",))],
        resolver=r)
    assert f.match(_event("45.9.1.2")) is None


def test_with_no_resolver_the_filter_behaves_exactly_as_before():
    f = BenignScannerFilter(
        [ScannerRule(vendor="shadowserver", asns=frozenset({33038}),
                     org_keywords=("shadowserver",),
                     rdns_suffixes=("shadowserver.io",))])
    assert f.match(_event("184.105.139.69")) is None
    assert f.match(_event("1.2.3.4", asn=33038)) == "shadowserver"


def test_the_shipped_allowlist_actually_carries_the_suffixes():
    """Guard against the rules loading but the yaml never being updated —
    the shape of bug where a knob is renamed and the config keeps the old key."""
    f = BenignScannerFilter.from_yaml()
    by_vendor = {r.vendor: r for r in f._rules}
    for vendor, suffix in (("shadowserver", "shadowserver.io"),
                           ("binaryedge", "binaryedge.ninja"),
                           ("stretchoid", "stretchoid.com")):
        assert vendor in by_vendor, f"{vendor} missing from shipped allowlist"
        assert suffix in by_vendor[vendor].rdns_suffixes, \
            f"{vendor} has no rdns_suffixes — ASN/org can never match it"


def test_the_dns_timeout_does_not_leak_into_the_rest_of_the_process():
    """`socket.setdefaulttimeout()` is PROCESS-GLOBAL. Setting it for a DNS
    call and walking away would silently impose a 1-second timeout on every
    socket created afterwards — including the Elasticsearch and OpenCTI
    clients, turning a DNS convenience into cycle-wide failures under load."""
    import socket
    before = socket.getdefaulttimeout()
    r = ForwardConfirmedRDNS(timeout=0.5)
    r.name_for("192.0.2.1")          # will fail to resolve; that is fine
    assert socket.getdefaulttimeout() == before, \
        "rDNS leaked its socket timeout into the process"
    probe = socket.socket()
    try:
        assert probe.gettimeout() == before
    finally:
        probe.close()
