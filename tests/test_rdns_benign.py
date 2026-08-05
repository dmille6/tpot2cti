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


def test_a_negative_cache_entry_outlives_a_cycle():
    """A negative TTL shorter than the cycle interval buys nothing: every cycle
    re-resolves the same PTR-less addresses and exhausts the budget by
    construction — which also destroys the skip counter's value as a signal.
    Measured: ~932 distinct addresses per 2h window meant ~662 lookups/cycle
    against a budget of 500, forever."""
    dns, r = _r(ptr={})
    for _ in range(10):
        r.name_for("45.9.1.2")
    assert dns.reverse_calls == 1
    assert r._negative_ttl >= 2 * 3600, \
        "negative TTL must exceed any plausible cycle interval"


def test_an_expired_cache_entry_is_not_served():
    """The security-relevant half: serving an EXPIRED positive as fresh means
    unbounded allowlisting. Mutating `cached_name_for` to ignore expiry
    previously passed the entire suite."""
    import time as _t
    dns, r = _r(ptr={"184.105.139.69": "scan-03.shadowserver.io"},
                fwd={"scan-03.shadowserver.io": ["184.105.139.69"]})
    assert r.name_for("184.105.139.69") == "scan-03.shadowserver.io"
    assert r.cached_name_for("184.105.139.69") == ("scan-03.shadowserver.io", True)
    # force expiry
    name, _ = r._cache["184.105.139.69"]
    r._cache["184.105.139.69"] = (name, _t.monotonic() - 1)
    assert r.cached_name_for("184.105.139.69") == (None, False), \
        "an expired entry was served as a live cache hit"


def test_a_confirmed_name_expires_within_a_day():
    """Cloud addresses are recycled. A week-long positive TTL let an attacker
    assigned a released BinaryEdge/Stretchoid address inherit its allowlisting
    for days, with no DNS control at all — the strongest real bypass, and TTL
    is the only thing bounding it."""
    _, r = _r()
    assert r._ttl <= 24 * 3600


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


# NOTE: the default org here is deliberate — it is the LANDLORD's name, which
# is the whole point. An earlier version of these tests let that default hide
# a bug where an empty org short-circuited the rDNS path entirely.


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


def test_the_wall_clock_budget_is_what_actually_bounds_dns():
    """`socket.setdefaulttimeout()` does NOT bound gethostbyaddr/getaddrinfo —
    they use the system resolver. Verified live: a 1 ms setting still allowed a
    58 ms lookup, and 87 of 600 real addresses exceeded 1 s (max 11.5 s). So a
    per-lookup timeout bounds nothing and a count budget alone is not a stall
    bound; cumulative wall-clock is."""
    import time as _t

    class _Slow:
        def __init__(self): self.calls = 0
        def reverse(self, ip):
            self.calls += 1
            _t.sleep(0.01)
            return None
        def forward(self, name): return []

    slow = _Slow()
    r = ForwardConfirmedRDNS(resolver=slow.reverse, forward_resolver=slow.forward)
    f = BenignScannerFilter(
        [ScannerRule(vendor="x", asns=frozenset(), org_keywords=(),
                     rdns_suffixes=("example.com",))], resolver=r)
    f.begin_cycle(10_000, time_budget=0.05)      # huge count, tiny time
    for i in range(500):
        f.match(_event(f"45.9.{i // 256}.{i % 256}", asn=None, org=None))
    assert slow.calls < 500, "wall-clock budget did not stop the lookups"
    assert r.elapsed >= 0.05
    assert f.rdns_skipped_budget > 0, "skips must be counted"


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


# ── the empty-org path, and the budget ───────────────────────────────────

def test_rdns_runs_even_when_geoip_has_no_org():
    """`match()` used to `return None` the moment the org string was empty,
    which skipped the rDNS path entirely — for exactly the population it exists
    to serve. The original test suite hid this because its helper always
    supplied an org."""
    dns, r = _r(ptr={"184.105.139.69": "scan-03.shadowserver.io"},
                fwd={"scan-03.shadowserver.io": ["184.105.139.69"]})
    f = BenignScannerFilter(
        [ScannerRule(vendor="shadowserver", asns=frozenset(), org_keywords=(),
                     rdns_suffixes=("shadowserver.io",))], resolver=r)
    f.begin_cycle(10)
    assert f.match(_event("184.105.139.69", asn=None, org=None)) == "shadowserver"
    assert f.match(_event("184.105.139.69", asn=None, org="")) == "shadowserver"


def test_the_lookup_budget_is_bounded_and_fails_open():
    """Each miss costs up to two blocking DNS calls. Unbounded, a burst of new
    addresses (measured peak 3,118/day) could stall ingest for tens of minutes.
    Exhaustion must KEEP events, not drop them."""
    dns, r = _r(ptr={}, fwd={})
    f = BenignScannerFilter(
        [ScannerRule(vendor="x", asns=frozenset(), org_keywords=(),
                     rdns_suffixes=("example.com",))], resolver=r)
    f.begin_cycle(3)
    for i in range(20):
        assert f.match(_event(f"45.9.0.{i}", asn=None, org=None)) is None
    assert dns.reverse_calls == 3, "budget did not bound the lookups"
    assert f.rdns_skipped_budget == 17, "skips must be counted, not silent"


def test_cache_hits_do_not_spend_budget():
    """A single busy scanner would otherwise consume the whole cycle's budget
    on repeat visits and starve genuinely new addresses."""
    dns, r = _r(ptr={"184.105.139.69": "scan-03.shadowserver.io"},
                fwd={"scan-03.shadowserver.io": ["184.105.139.69"]})
    f = BenignScannerFilter(
        [ScannerRule(vendor="shadowserver", asns=frozenset(), org_keywords=(),
                     rdns_suffixes=("shadowserver.io",))], resolver=r)
    f.begin_cycle(1)
    for _ in range(100):
        assert f.match(_event("184.105.139.69", asn=None, org=None)) == "shadowserver"
    assert dns.reverse_calls == 1
    assert f.rdns_skipped_budget == 0, "cache hits wrongly consumed budget"


def test_a_filter_nobody_initialised_still_works():
    """Defaulting the budget to 0 would make a forgotten begin_cycle() call a
    silent no-op — the filter quietly stops catching scanners."""
    dns, r = _r(ptr={"184.105.139.69": "scan-03.shadowserver.io"},
                fwd={"scan-03.shadowserver.io": ["184.105.139.69"]})
    f = BenignScannerFilter(
        [ScannerRule(vendor="shadowserver", asns=frozenset(), org_keywords=(),
                     rdns_suffixes=("shadowserver.io",))], resolver=r)
    assert f.match(_event("184.105.139.69", asn=None, org=None)) == "shadowserver"


def test_the_wall_clock_bound_survives_a_resolver_without_an_elapsed_attribute():
    """The bound must not depend on the resolver exposing a counter. Reading
    `getattr(resolver, "elapsed", 0.0)` would return 0.0 for any duck-typed
    resolver and silently disable the only real stall bound — no error, no
    signal, exactly the failure shape this codebase keeps hitting."""
    import time as _t

    class _Bare:                      # deliberately has no `elapsed`
        def __init__(self): self.calls = 0
        def name_for(self, ip):
            self.calls += 1
            _t.sleep(0.01)
            return None

    bare = _Bare()
    f = BenignScannerFilter(
        [ScannerRule(vendor="x", asns=frozenset(), org_keywords=(),
                     rdns_suffixes=("example.com",))], resolver=bare)
    f.begin_cycle(10_000, time_budget=0.05)
    for i in range(500):
        f.match(_event(f"45.9.{i // 256}.{i % 256}", asn=None, org=None))
    assert bare.calls < 500, "no elapsed attribute silently disabled the bound"
    assert f.rdns_skipped_budget > 0
