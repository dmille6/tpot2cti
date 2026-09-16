"""Lane B — ledger discipline, tiering, and the write-back rules.

The rules under test are the ones docs/ENRICHMENT.md says cost the predecessor
real damage: caching on attempted rather than confirmed, fuzzy attribution
promoted to SDOs, and third-party PTR names published as our infrastructure.
"""
from __future__ import annotations

import os
import tempfile

import pytest

from tpot2cti.enrich.ledger import EnrichmentLedger
from tpot2cti.enrich import lookup_sources as LS
from tpot2cti.enrich import lookup as L


@pytest.fixture()
def ledger():
    d = tempfile.mkdtemp()
    lg = EnrichmentLedger(os.path.join(d, "ledger.db"))
    yield lg
    lg.close()


# ── the rule that matters most ─────────────────────────────────────────────

def test_error_is_never_a_verdict(ledger):
    """A failed call must not become a reusable answer."""
    ledger.record_error("internetdb", "ipv4", "1.2.3.4", "HTTP 500")
    assert ledger.lookup("internetdb", "ipv4", "1.2.3.4") is None


def test_record_result_refuses_non_terminal_status(ledger):
    """The API itself forbids caching a speculative state."""
    with pytest.raises(ValueError):
        ledger.record_result("internetdb", "ipv4", "1.2.3.4",
                             status="pending", verdict={}, ttl_seconds=60)


def test_errors_accumulate_and_back_off(ledger):
    for _ in range(3):
        ledger.record_error("internetdb", "ipv4", "9.9.9.9", "boom")
    assert ledger.in_backoff("internetdb", "ipv4", "9.9.9.9") is True
    # a fresh value is not in backoff
    assert ledger.in_backoff("internetdb", "ipv4", "8.8.8.8") is False


def test_expired_entry_is_a_miss_not_a_hit(ledger):
    ledger.record_result("internetdb", "ipv4", "5.5.5.5",
                         status="found", verdict={"ports": [22]}, ttl_seconds=-1)
    assert ledger.lookup("internetdb", "ipv4", "5.5.5.5") is None


def test_found_entry_round_trips(ledger):
    ledger.record_result("internetdb", "ipv4", "6.6.6.6",
                         status="found", verdict={"ports": [22]}, ttl_seconds=600)
    hit = ledger.lookup("internetdb", "ipv4", "6.6.6.6")
    assert hit is not None and hit.status == "found"
    assert hit.verdict["ports"] == [22]


def test_budget_counts_errors_too(ledger):
    """A failed call still spent provider quota; the budget must see it."""
    ledger.record_error("internetdb", "ipv4", "1.1.1.1", "timeout")
    ledger.record_result("internetdb", "ipv4", "2.2.2.2",
                         status="not_found", verdict={}, ttl_seconds=60)
    assert ledger.spent_today("internetdb") == 2


# ── tiering: the no-signup path must need zero configuration ───────────────

def test_tier0_sources_need_no_credential():
    for s in LS.SOURCES:
        if s.tier == 0:
            assert s.credential_env is None, f"{s.key} is tier 0 but wants a key"
            assert s.enabled is True


def test_default_source_spec_is_tier0_only():
    for key in LS.DEFAULT_SOURCES.split(","):
        assert LS.SOURCES_BY_KEY[key].tier == 0


def test_unknown_source_is_a_hard_error():
    """A typo must not silently disable a source."""
    with pytest.raises(ValueError):
        LS.selected_sources("internetdb,nosuchsource")


def test_credentialless_tier1_disables_itself_without_raising(monkeypatch):
    """Tier 1/2 without a key is dropped, never fatal — that is what makes
    'works out of the box' true rather than aspirational."""
    fake = LS.LookupSource(
        key="needskey", tier=1, obs_type="ipv4", label_prefix="x:",
        fetch=lambda *a, **k: None, ttl_found=60, ttl_not_found=60,
        credential_env="DEFINITELY_NOT_SET_XYZ")
    monkeypatch.setitem(LS.SOURCES_BY_KEY, "needskey", fake)
    monkeypatch.delenv("DEFINITELY_NOT_SET_XYZ", raising=False)
    assert LS.selected_sources("needskey") == []


def test_label_prefixes_are_unique_and_owned():
    """§8: one module owns each prefix; no two sources may claim the same one."""
    prefixes = [s.label_prefix for s in LS.SOURCES]
    assert len(prefixes) == len(set(prefixes))


# ── write-back rules (§7) ──────────────────────────────────────────────────

class _Builder:
    """Minimal stand-in recording what would be emitted."""
    def __init__(self): self.vulns = []
    def build_ip_observable(self, v): return {"type": "ipv4-addr", "id": f"ipv4--{v}", "value": v}
    def build_file(self, h): return {"type": "file", "id": f"file--{h}"}
    def _emit_vulnerability(self, cve, *, out, description=None):
        self.vulns.append(cve); out.append({"type": "vulnerability", "id": f"v--{cve}", "name": cve})
        return f"v--{cve}"
    def build_relationship(self, a, t, b, description=None):
        return {"type": "relationship", "source_ref": a, "target_ref": b, "relationship_type": t}


def test_internetdb_ptr_names_never_become_domain_sdos():
    """A PTR name is chosen by whoever owns the netblock, so for attacker-owned
    ranges the attacker picks the name we would publish as their infrastructure.
    Recorded as presence only — never a Domain-Name SCO, never the value."""
    b = _Builder()
    out = L.build_objects(b, LS.SOURCES_BY_KEY["internetdb"], "ipv4", "1.2.3.4",
                          {"hostnames": ["evil-looking.example.com"], "ports": [22]})
    assert not any(o["type"] == "domain-name" for o in out)
    blob = repr(out)
    assert "evil-looking.example.com" not in blob
    labels = out[0]["x_opencti_labels"]
    assert "shodan:has-ptr" in labels


def test_internetdb_cves_promote_with_an_edge_never_floating():
    """§7 hard rule: never emit a floating edgeless SDO."""
    b = _Builder()
    out = L.build_objects(b, LS.SOURCES_BY_KEY["internetdb"], "ipv4", "1.2.3.4",
                          {"vulns": ["CVE-2021-44228"], "ports": [443]})
    assert b.vulns == ["CVE-2021-44228"]
    vulns = [o for o in out if o["type"] == "vulnerability"]
    rels = [o for o in out if o["type"] == "relationship"]
    assert len(vulns) == 1 and len(rels) == 1
    assert rels[0]["target_ref"] == vulns[0]["id"]


def test_circl_known_good_is_a_label_not_a_score():
    """Suppression is expressed as a label: the publisher keeps the MAXIMUM
    score across cycles, so a score can only ratchet up."""
    b = _Builder()
    out = L.build_objects(b, LS.SOURCES_BY_KEY["circl"], "sha256", "a" * 64,
                          {"known_good": True, "source": "NSRL"})
    assert out and "hashlookup:known-good" in out[0]["x_opencti_labels"]
    assert "x_opencti_score" not in out[0]


def test_ttl_asymmetry_negative_expires_faster():
    """Unknown -> known is the transition worth catching, so a not_found must
    expire faster than a found."""
    for s in LS.SOURCES:
        assert s.ttl_not_found < s.ttl_found, s.key


# ── health states (§6) ─────────────────────────────────────────────────────

def _c(**kw):
    base = {"backlog": 0, "calls": 0, "budget_blocked": []}
    base.update(kw); return base


def test_quiet_when_nothing_to_do():
    assert L.health_state(_c(), had_success=True)[0] == "quiet"


def test_budget_exhausted_is_healthy_and_named():
    st, code = L.health_state(_c(backlog=10, budget_blocked=["internetdb"]),
                              had_success=True)
    assert st == "budget-exhausted" and code == 200


def test_stalled_with_work_is_503():
    st, code = L.health_state(_c(backlog=10), had_success=True)
    assert st == "stalled-with-work" and code == 503


def test_stalled_alarm_is_disarmed_before_first_success():
    """A fresh install with a backlog and no successful cycle yet is not sick."""
    st, code = L.health_state(_c(backlog=10), had_success=False)
    assert st != "stalled-with-work" and code == 200


def test_a_real_user_agent_is_sent():
    """InternetDB returned HTTP 403 on 500/500 calls with urllib's default
    `Python-urllib/3.x` agent, and 200 with any real one. Measured 2026-08-26."""
    assert LS.USER_AGENT and "urllib" not in LS.USER_AGENT.lower()
    assert LS.USER_AGENT.startswith("tpot2cti/")
