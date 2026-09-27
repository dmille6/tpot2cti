"""DR-02: evidence gate, decoupled sightings, sighting grain, counters,
counts index pattern.

The contract (decisions/DR-02/decision.md, docs/EVIDENCE_GATE.md):

  * every flag defaults to today's behaviour, and the default output is
    BYTE-IDENTICAL to origin/main 71e47ec (golden digests, generated there
    before any DR-02 code existed -- see tests/dr02_harness.py);
  * with the gate stubbed to accept-all, shadow and enforce change nothing;
  * a refused (or absent) Indicator must not take the observable's
    ``:ipv4`` Sighting with it once sightings are decoupled -- at each of
    the five dual-sighting sites;
  * enforce leaves no reference to a withheld Indicator in the bundle;
  * counters reach the cycle summary, the state KV and /health;
  * sighting counts read their own index pattern, the event read does not.

Refusals are simulated by monkeypatching ``tpot2cti.evidence.decide`` --
the builder must look it up through the module, which is itself asserted
(a builder that imported the function by name would silently ignore DR-01's
real predicate).
"""
from __future__ import annotations

import dataclasses
import json
import logging
from pathlib import Path

import pytest

from tests import dr02_harness as H
from tpot2cti import evidence
from tpot2cti.config import ConfigError
from tpot2cti.stix_ids import attacker_ip_indicator_id, attacker_ip_observable_id

GATE = "TPOT2CTI_EVIDENCE_GATE"
DECOUPLED = "TPOT2CTI_SIGHTINGS_DECOUPLED"
GRAIN = "TPOT2CTI_SIGHTING_GRAIN"
COUNTS = "TPOT2CTI_COUNTS_INDEX_PATTERN"

REFUSE = evidence.GateDecision(accept=False, reason="test-refuse")


def _refuse_all(monkeypatch, sites=None):
    """Make the gate refuse every session (or only those at ``sites``)."""
    def fake(session, *, site):
        if sites is None or site in sites:
            return REFUSE
        return evidence.GateDecision(True, "test-accept")
    monkeypatch.setattr(evidence, "decide", fake)


def _sightings(objs):
    return [o for o in objs if o.get("type") == "sighting"]


def _by_type(objs, t):
    return [o for o in objs if o.get("type") == t]


def _ip_indicators(objs):
    """Attacker-IP Indicators only. File Indicators are not gated: DR-02's
    gate decides whether an ADDRESS is promoted (docs/EVIDENCE_GATE.md)."""
    return [o for o in objs if o.get("type") == "indicator"
            and ("ipv4-addr:value" in o.get("pattern", "")
                 or "ipv6-addr:value" in o.get("pattern", ""))]


def _refs(obj):
    out = set()
    for k in ("source_ref", "target_ref", "sighting_of_ref"):
        if obj.get(k):
            out.add(obj[k])
    out.update(obj.get("object_refs") or [])
    return out


# ---------------------------------------------------------------------------
# 1. Configuration
# ---------------------------------------------------------------------------

def test_defaults_are_todays_behaviour():
    cfg = H.make_cfg()
    assert cfg.cycle.evidence_gate == "off"
    assert cfg.cycle.sightings_decoupled is False
    assert cfg.cycle.sighting_grain == "legacy"
    assert cfg.es.counts_index_pattern is None
    assert cfg.es.effective_counts_index_pattern == cfg.es.index_pattern


@pytest.mark.parametrize("raw,want", [
    ("shadow", "shadow"), ("ENFORCE", "enforce"), ("  off ", "off"),
    ("shadow   # 14-day window", "shadow"), ("", "off"),
])
def test_gate_setting_parses_like_the_other_env_switches(raw, want):
    assert H.make_cfg({GATE: raw}).cycle.evidence_gate == want


@pytest.mark.parametrize("key,bad", [(GATE, "enfroce"), (GATE, "on"),
                                     (GRAIN, "per-type")])
def test_a_typo_in_a_dr02_switch_stops_startup(key, bad):
    """A misspelt safety switch must not quietly mean 'off'."""
    with pytest.raises(ConfigError, match=key):
        H.make_cfg({key: bad})


def test_counts_pattern_is_separate_and_defaults_to_the_event_pattern():
    cfg = H.make_cfg({"ES_INDEX_PATTERN": "logstash-2026*"})
    assert cfg.es.effective_counts_index_pattern == "logstash-2026*"
    cfg = H.make_cfg({COUNTS: "logstash-*,other-*"})
    assert cfg.es.index_pattern == "logstash-*"
    assert cfg.es.effective_counts_index_pattern == "logstash-*,other-*"


def test_enforce_without_decoupling_warns(caplog):
    with caplog.at_level(logging.WARNING, logger="tpot2cti.config"):
        H.make_cfg({GATE: "enforce"})
    assert any("SIGHTINGS_DECOUPLED" in r.getMessage() for r in caplog.records)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="tpot2cti.config"):
        H.make_cfg({GATE: "enforce", DECOUPLED: "true"})
    assert not any("SIGHTINGS_DECOUPLED" in r.getMessage() for r in caplog.records)


def test_counts_pattern_naming_the_transform_index_warns(caplog):
    with caplog.at_level(logging.WARNING, logger="tpot2cti.config"):
        H.make_cfg({COUNTS: "logstash-*,tsec-counts-suppressed"})
    assert any("transform index" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# 2. Byte identity against origin/main (golden digests)
# ---------------------------------------------------------------------------

#: Flag states whose output must equal today's with the stub gate. The
#: decoupled rows qualify only because every stub-gated site has an
#: Indicator; the decoupling tests below cover what changes when one does not.
IDENTICAL_STATES = {
    "unset": {},
    "off": {GATE: "off", DECOUPLED: "false", GRAIN: "legacy"},
    "shadow": {GATE: "shadow"},
    "enforce+decoupled (stub)": {GATE: "enforce", DECOUPLED: "true"},
    "enforce (stub)": {GATE: "enforce"},
    "decoupled only": {DECOUPLED: "true"},
    "counts pattern = event pattern": {COUNTS: "logstash-*"},
}


@pytest.mark.parametrize("env", IDENTICAL_STATES.values(), ids=IDENTICAL_STATES.keys())
def test_cycle_bundle_is_byte_identical_to_origin_main(env, tmp_path):
    objs, summary, _, _ = H.cycle_bundle(tmp_path, env)
    assert H.digest(objs) == H.golden()["cycle"], (
        "the cycle bundle differs from origin/main 71e47ec for flag state "
        f"{env}; run `python -m tests.dr02_harness --dump DIR` here and on "
        "origin/main and diff the two")
    # Non-vacuity: the fixture set reaches the dual-sighting sites at all.
    assert summary["evidence_gate"]["site_calls"]["with_indicator"] >= 20


@pytest.mark.parametrize("env", IDENTICAL_STATES.values(), ids=IDENTICAL_STATES.keys())
def test_direct_bundle_is_byte_identical_to_origin_main(env):
    objs, b = H.direct_bundle(env)
    assert H.digest(objs) == H.golden()["direct"], (
        f"the direct five-site bundle differs from origin/main for {env}")
    # Non-vacuity: every direct session reached a site, and every one of
    # the five methods is represented.
    assert b.gate_stats.site_calls["with_indicator"] == len(H.direct_sessions())
    assert {m for m, _ in H.direct_sessions()} == {
        "build_cowrie_session", "build_suricata_alert", "build_honeytrap_probe",
        "build_fallback_event", "build_driveby_session"}


def test_the_golden_was_taken_before_dr02_existed():
    """Provenance, so nobody 'fixes' a mismatch by regenerating on a branch."""
    assert H.golden()["generated_from"].startswith("origin/main 71e47ec")


def test_the_digest_is_sensitive_to_a_one_byte_change():
    """Guard the guard: a digest over the wrong thing would pass anything."""
    objs, _ = H.direct_bundle()
    objs[-1] = dict(objs[-1], count=objs[-1].get("count", 0) + 1)
    assert H.digest(objs) != H.golden()["direct"]


def test_off_mode_never_consults_the_gate(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("decide() called with TPOT2CTI_EVIDENCE_GATE=off")
    monkeypatch.setattr(evidence, "decide", boom)
    objs, b = H.direct_bundle({GATE: "off"})
    assert H.digest(objs) == H.golden()["direct"]
    assert not b.gate_stats.accepted and not b.gate_stats.refused


def test_builder_calls_decide_through_the_module(monkeypatch):
    """DR-01 will replace evidence.decide; a builder holding its own
    reference to the stub would keep accepting everything."""
    seen = []

    def spy(session, *, site):
        seen.append(site)
        return evidence.GateDecision(True, "spy")
    monkeypatch.setattr(evidence, "decide", spy)
    H.direct_bundle({GATE: "shadow"})
    assert sorted(set(seen)) == sorted(evidence.SITES)


def test_stub_shadow_counts_every_site_and_logs_no_refusal(caplog):
    with caplog.at_level(logging.INFO, logger="tpot2cti.evidence"):
        _, b = H.direct_bundle({GATE: "shadow"})
    assert b.gate_stats.accepted == {evidence.REASON_STUB_ACCEPT: len(H.direct_sessions())}
    assert not b.gate_stats.refused
    assert not [r for r in caplog.records if r.getMessage().startswith("evidence_gate ")]


# ---------------------------------------------------------------------------
# 3. Decoupling at each of the five sites
# ---------------------------------------------------------------------------

def _one_per_site():
    """(method, session) for the first direct session of each method."""
    seen, out = set(), []
    for method, session in H.direct_sessions():
        if method not in seen:
            seen.add(method)
            out.append((method, session))
    return out


SITE_CASES = _one_per_site()
SITE_IDS = [m for m, _ in SITE_CASES]


def _build_one(env, method, session):
    cfg = H.make_cfg(env)
    b = H._fixed_builder(cfg)
    with b.session_context(session):
        objs = getattr(b, method)(session)
    return b.finalize_bundle(objs), b


def _obs_sighting_id(b, session):
    return b._sighting_id(attacker_ip_observable_id(session.src_ip),
                          session.sensor_hostname, session, "ipv4")


@pytest.mark.parametrize("method,session", SITE_CASES, ids=SITE_IDS)
def test_refused_indicator_keeps_the_observable_sighting(method, session, monkeypatch):
    baseline, b0 = _build_one({}, method, session)
    obs_id = _obs_sighting_id(b0, session)
    base_obs = [s for s in _sightings(baseline) if s["id"] == obs_id]
    assert base_obs, "guard: today's output has the :ipv4 sighting for this site"

    _refuse_all(monkeypatch)
    objs, b = _build_one({GATE: "enforce", DECOUPLED: "true"}, method, session)
    ind_id = attacker_ip_indicator_id(session.src_ip)

    assert not _ip_indicators(objs), "refused Indicator was emitted"
    sightings = _sightings(objs)
    assert [s["sighting_of_ref"] for s in sightings] == \
        [attacker_ip_observable_id(session.src_ip)], (
        "exactly the observable-side sighting must survive the refusal")
    got = sightings[0]
    # Same object as today's -- same id, count, window, text -- so the
    # observable's history in OpenCTI continues rather than forks.
    assert got == base_obs[0]
    assert not any(ind_id in _refs(o) for o in objs), "dangling Indicator ref"
    assert b.gate_stats.site_calls == {"observable_only": 1}
    assert b.gate_stats.indicators_withheld == 1
    assert b.gate_stats.observable_sightings_without_indicator == 1


@pytest.mark.parametrize("method,session", SITE_CASES, ids=SITE_IDS)
def test_refusal_without_decoupling_loses_the_sighting_and_says_so(
        method, session, monkeypatch):
    """Today's shape under enforce: the loss DR-02 forbids, counted."""
    _refuse_all(monkeypatch)
    objs, b = _build_one({GATE: "enforce"}, method, session)
    assert not _sightings(objs)
    assert b.gate_stats.site_calls == {"none": 1}


@pytest.mark.parametrize("method,session", SITE_CASES, ids=SITE_IDS)
def test_absent_indicator_keeps_the_observable_sighting_when_decoupled(
        method, session, monkeypatch):
    """Not refused -- simply not built (build_ip_indicator returned None)."""
    from tpot2cti.stix.builder import STIXBuilder
    monkeypatch.setattr(STIXBuilder, "build_ip_indicator", lambda self, *a, **k: None)
    today, _ = _build_one({}, method, session)
    assert not _sightings(today), "guard: today an absent Indicator loses both"
    objs, b = _build_one({DECOUPLED: "true"}, method, session)
    assert [s["sighting_of_ref"] for s in _sightings(objs)] == \
        [attacker_ip_observable_id(session.src_ip)]
    assert b.gate_stats.site_calls == {"observable_only": 1}


@pytest.mark.parametrize("method,session", SITE_CASES, ids=SITE_IDS)
def test_shadow_refusal_changes_nothing_but_counts_and_logs(
        method, session, monkeypatch, caplog):
    baseline, _ = _build_one({}, method, session)
    _refuse_all(monkeypatch)
    with caplog.at_level(logging.INFO, logger="tpot2cti.evidence"):
        objs, b = _build_one({GATE: "shadow", DECOUPLED: "true"}, method, session)
    assert H.serialize(objs) == H.serialize(baseline)
    assert b.gate_stats.refused == {"test-refuse": 1}
    assert b.gate_stats.indicators_withheld == 0
    lines = [r.getMessage() for r in caplog.records
             if r.getMessage().startswith("evidence_gate ")]
    assert len(lines) == 1
    payload = json.loads(lines[0][len("evidence_gate "):])
    assert payload["action"] == "would-refuse"
    assert payload["reason"] == "test-refuse"
    assert payload["site"] == evidence.SITES[
        ["build_cowrie_session", "build_suricata_alert", "build_honeytrap_probe",
         "build_fallback_event", "build_driveby_session"].index(method)]
    assert payload["src_ip"] == session.src_ip
    assert payload["sensor"] == session.sensor_hostname


# ---------------------------------------------------------------------------
# 4. Enforce over a whole cycle: nothing dangles, no observable sighting lost
# ---------------------------------------------------------------------------

def test_enforce_refusing_everything_loses_no_observable_sighting(tmp_path, monkeypatch):
    base, _, _, _ = H.cycle_bundle(tmp_path / "a")
    base_obs = {s["id"]: s for s in _sightings(base)
                if not s["sighting_of_ref"].startswith("indicator--")}
    assert base_obs, "guard"

    _refuse_all(monkeypatch)
    objs, summary, _, _ = H.cycle_bundle(
        tmp_path / "b", {GATE: "enforce", DECOUPLED: "true"})
    assert not _ip_indicators(objs)
    assert _ip_indicators(base), "guard"
    assert not [s for s in _sightings(objs)
                if s["sighting_of_ref"].startswith("indicator--")]
    got_obs = {s["id"]: s for s in _sightings(objs)}
    assert got_obs == base_obs, "an observable sighting was lost or changed"

    emitted = {o["id"] for o in objs}
    withheld = {o["id"] for o in _ip_indicators(base)}
    for o in objs:
        missing = (_refs(o) & withheld) - emitted
        assert not missing, f"{o['type']} {o['id']} references withheld {missing}"

    gs = summary["evidence_gate"]
    assert gs["refused"] == {"test-refuse": gs["refused_total"]}
    assert gs["indicators_withheld"] == gs["refused_total"] > 0
    assert gs["accepted_total"] == 0
    # Non-vacuity of the dangling-ref sweep: the unconditional producers
    # (behaviour ATT&CK edges, web/protocol builders, profile Notes) did
    # reference the withheld Indicators and were cleaned.
    assert gs["relationships_dropped"] > 0
    assert gs["object_refs_dropped"] > 0
    assert gs["observable_sightings"] == {
        "with_indicator": 0, "without_indicator": len(base_obs)}


def test_a_refused_indicator_emitted_by_another_session_keeps_its_edges(monkeypatch):
    """Refusal is per session. When another session in the bundle emits the
    same Indicator, the refs are not dangling and must stay."""
    _refuse_all(monkeypatch, sites={"suricata"})
    objs, b = H.direct_bundle({GATE: "enforce", DECOUPLED: "true"})
    objs = b.finalize_bundle(objs)
    ind = attacker_ip_indicator_id(H.DIRECT_IP)
    assert ind in {o["id"] for o in objs}, "Cowrie accepted it, so it is emitted"
    assert b.gate_stats.refused == {"test-refuse": 1}
    assert b.gate_stats.relationships_dropped == 0


def test_finalize_returns_the_same_list_when_nothing_is_withheld():
    objs, b = H.direct_bundle({GATE: "shadow"})
    assert b.finalize_bundle(objs) is objs


# ---------------------------------------------------------------------------
# 5. Grain: one sighting per (sensor, IP, day), types in the description
# ---------------------------------------------------------------------------

def test_grain_keeps_todays_ids_and_counts_and_lists_the_types():
    legacy, _ = H.direct_bundle({})
    grain, _ = H.direct_bundle({GRAIN: "sensor-ip-day"})
    ls, gs = _sightings(legacy), _sightings(grain)
    assert [s["id"] for s in ls] == [s["id"] for s in gs], "id grain must not change"
    assert [s["count"] for s in ls] == [s["count"] for s in gs]
    assert [(s["first_seen"], s["last_seen"]) for s in ls] == \
        [(s["first_seen"], s["last_seen"]) for s in gs]

    obs = attacker_ip_observable_id(H.DIRECT_IP)
    day1 = [s for s in gs if s["sighting_of_ref"] == obs
            and s["first_seen"].startswith(H.DIRECT_DAY)]
    assert len(day1) == 1, "Cowrie, Suricata and Heralding: ONE sighting per side"
    lines = day1[0]["description"].splitlines()
    assert lines[0].endswith(": Cowrie, Heralding, Suricata")
    # Today's per-session lines follow unchanged.
    legacy_day1 = [s for s in ls if s["id"] == day1[0]["id"]][0]
    assert lines[1:] == legacy_day1["description"].splitlines()
    # ...and today's text named Cowrie alone, which is the defect.
    assert "Suricata" not in legacy_day1["description"]

    day2 = [s for s in gs if s["sighting_of_ref"] == obs
            and s["first_seen"].startswith("2026-03-08")]
    assert day2[0]["description"].splitlines()[0].endswith(": Cowrie")


def test_grain_gives_a_description_to_sightings_that_had_none():
    grain, _ = H.direct_bundle({GRAIN: "sensor-ip-day"})
    v6 = attacker_ip_observable_id(H.DIRECT_IP_V6)
    s = [x for x in _sightings(grain) if x["sighting_of_ref"] == v6][0]
    assert s["description"].endswith(": Heralding")


def test_grain_folds_in_the_days_types_from_es():
    """A narrow later cycle must not shrink the list OpenCTI replaces."""
    cfg = H.make_cfg({GRAIN: "sensor-ip-day"})
    b = H._fixed_builder(cfg)
    b.daily_event_types = {(H.DIRECT_IP, H.DIRECT_SENSOR, H.DIRECT_DAY): ["Ciscoasa", "Cowrie"]}
    objs, _ = H.direct_bundle({GRAIN: "sensor-ip-day"}, builder=b)
    obs = attacker_ip_observable_id(H.DIRECT_IP)
    s = [x for x in _sightings(objs) if x["sighting_of_ref"] == obs
         and x["first_seen"].startswith(H.DIRECT_DAY)][0]
    assert s["description"].splitlines()[0].endswith(
        ": Ciscoasa, Cowrie, Heralding, Suricata")


def test_legacy_grain_ignores_day_types():
    cfg = H.make_cfg({})
    b = H._fixed_builder(cfg)
    b.daily_event_types = {(H.DIRECT_IP, H.DIRECT_SENSOR, H.DIRECT_DAY): ["Ciscoasa"]}
    objs, _ = H.direct_bundle({}, builder=b)
    assert H.digest(objs) == H.golden()["direct"]


def _cycle_with_es(tmp_path, env, es_cls):
    from tpot2cti.main import run_cycle
    from tpot2cti.state import CycleState
    cfg = H.make_cfg(env)
    docs, ip_map = H.load_cycle_docs()
    es = es_cls(docs, {})
    state = CycleState(db_path=Path(tmp_path) / "state.db")
    pub = H.CapturingPublisher()
    summary = run_cycle(cfg, state, es, lambda: H._fixed_builder(cfg), pub,
                        now=H.FIXED_NOW)
    return es, summary, state


class _TypesES(H.FakeES):
    def __init__(self, docs, daily):
        super().__init__(docs, daily)
        self.types_kw = []

    def daily_event_counts(self, day_start, upper, index_pattern="logstash-*",
                           ignore_types=None, types_out=None, **kwargs):
        self.types_kw.append(types_out is not None)
        return super().daily_event_counts(day_start, upper, index_pattern,
                                          ignore_types, **kwargs)


def test_only_grain_mode_widens_the_counts_query(tmp_path):
    es, _, _ = _cycle_with_es(tmp_path / "a", {}, _TypesES)
    assert es.types_kw == [False], "legacy grain must send today's query"
    es, _, _ = _cycle_with_es(tmp_path / "b", {GRAIN: "sensor-ip-day"}, _TypesES)
    assert es.types_kw == [True]


# ---------------------------------------------------------------------------
# 6. The ES side: types sub-aggregation, and no read-time throttled skip
# ---------------------------------------------------------------------------

def _client_with(responses):
    from tpot2cti.es_client import TpotESClient
    c = TpotESClient.__new__(TpotESClient)
    c.sent = []

    def fake(body):
        c.sent.append(body)
        return responses.pop(0)
    c._search_with_retry = fake
    return c


def _resp(buckets):
    return {"aggregations": {"pairs": {"buckets": buckets}}}


def test_daily_counts_query_is_unchanged_without_types_out():
    from datetime import datetime, timezone
    c = _client_with([_resp([{"key": {"ip": "a", "host": "h", "day": "d"},
                               "doc_count": 3}])])
    out = c.daily_event_counts(datetime(2026, 3, 7, tzinfo=timezone.utc),
                               datetime(2026, 3, 8, tzinfo=timezone.utc),
                               index_pattern="cnt-*", ignore_types=["P0f"])
    assert out == {("a", "h", "d"): 3}
    body = c.sent[0]
    assert body["index"] == "cnt-*"
    assert set(body["aggs"]["pairs"]) == {"composite"}, "no sub-agg in legacy mode"


def test_daily_counts_types_out_collects_the_days_types():
    from datetime import datetime, timezone
    c = _client_with([_resp([{
        "key": {"ip": "a", "host": "h", "day": "d"}, "doc_count": 5,
        "types": {"buckets": [{"key": "Suricata", "doc_count": 1},
                              {"key": "Cowrie", "doc_count": 4}]}}])])
    types: dict = {}
    out = c.daily_event_counts(datetime(2026, 3, 7, tzinfo=timezone.utc),
                               datetime(2026, 3, 8, tzinfo=timezone.utc),
                               types_out=types)
    assert out == {("a", "h", "d"): 5}
    assert types == {("a", "h", "d"): ["Cowrie", "Suricata"]}
    assert c.sent[0]["aggs"]["pairs"]["aggs"]["types"]["terms"]["field"] == "type.keyword"


def test_core_does_not_skip_throttled_documents_at_read_time():
    """DR-02 point 6 / decision item 6. The event read and the counts query
    must not filter on the DR-07 ``throttled`` tag: a flood source's later
    sessions would lose AUTH_SUCCESS and commands from reconstruction, and
    the day's count would fall. Changing that needs the replay-fixture test
    the reconciliation names, not a quiet filter."""
    from datetime import datetime, timezone
    from tpot2cti.es_client import TpotESClient
    s, e = datetime(2026, 3, 7, tzinfo=timezone.utc), datetime(2026, 3, 8, tzinfo=timezone.utc)
    for alert_only in (False, True):
        q = json.dumps(TpotESClient._build_query(s, e, ["P0f"], alert_only))
        assert "throttled" not in q and "tags" not in q
    c = _client_with([_resp([])])
    c.daily_event_counts(s, e, ignore_types=["P0f"], types_out={})
    q = json.dumps(c.sent[0])
    assert "throttled" not in q and "tags" not in q


# ---------------------------------------------------------------------------
# 7. Counts index pattern in the cycle
# ---------------------------------------------------------------------------

def test_counts_pattern_reaches_only_the_counts_query(tmp_path):
    _, _, es, _ = H.cycle_bundle(tmp_path / "a")
    assert es.daily_patterns == ["logstash-*"]
    assert es.stream_patterns == ["logstash-*"]

    pattern = "logstash-*,counts-extra-*"
    objs, _, es, _ = H.cycle_bundle(tmp_path / "b", {COUNTS: pattern})
    assert es.daily_patterns == [pattern]
    assert es.stream_patterns == ["logstash-*"], "the event read must not widen"
    assert set(es.count_patterns) == {"logstash-*"}
    # The fake returns the same counts for any pattern, so the bundle is
    # today's: the setting changes WHERE counts come from, nothing else.
    assert H.digest(objs) == H.golden()["cycle"]


# ---------------------------------------------------------------------------
# 8. Counters: summary, state KV, /health
# ---------------------------------------------------------------------------

def test_counters_reach_state_and_health(tmp_path, monkeypatch):
    from tpot2cti.health import HealthStatus
    from tpot2cti.main import run_cycle
    from tpot2cti.state import CycleState

    _refuse_all(monkeypatch, sites={"suricata"})
    env = {GATE: "shadow", DECOUPLED: "true"}
    cfg = H.make_cfg(env)
    docs, ip_map = H.load_cycle_docs()
    state = CycleState(db_path=tmp_path / "state.db")
    summaries = []
    for _ in range(2):
        es = H.FakeES(docs, {})
        pub = H.CapturingPublisher()
        summaries.append(run_cycle(cfg, state, es, lambda: H._fixed_builder(cfg),
                                   pub, now=H.FIXED_NOW))
    last = summaries[-1]["evidence_gate"]
    assert last["mode"] == "shadow" and last["sightings_decoupled"] is True
    n_suricata = summaries[-1]["sessions_by_type"]["Suricata"]
    assert n_suricata >= 1, "guard"
    assert last["refused"] == {"test-refuse": n_suricata}, "one per Suricata session"
    assert last["accepted"]["test-accept"] == last["accepted_total"] > 0
    assert json.loads(state.get("last_cycle_evidence_gate")) == last

    totals = json.loads(state.get("evidence_gate_totals"))
    assert totals["cycles"] == 2
    assert totals["refused"] == {"test-refuse": 2 * n_suricata}
    assert totals["accepted_total"] == 2 * last["accepted_total"]
    assert totals["site_calls"]["with_indicator"] == 2 * last["site_calls"]["with_indicator"]
    assert totals["since"] == H.FIXED_NOW.isoformat()

    payload, _ = HealthStatus(state, pycti_version="test").compute_status()
    eg = payload["evidence_gate"]
    assert eg["last_cycle"] == last
    assert eg["totals"]["refused_total"] == 2 * n_suricata


def test_health_before_any_cycle_has_no_gate_block(state_db):
    from tpot2cti.health import HealthStatus
    payload, _ = HealthStatus(state_db, pycti_version="test").compute_status()
    assert payload["evidence_gate"] is None


def test_off_mode_still_reports_sighting_counters(tmp_path):
    _, summary, _, _ = H.cycle_bundle(tmp_path)
    gs = summary["evidence_gate"]
    assert gs["mode"] == "off" and gs["accepted"] == {} and gs["refused"] == {}
    obs = gs["observable_sightings"]
    assert obs["with_indicator"] > 0 and obs["without_indicator"] == 0
    assert gs["site_calls"]["none"] == 0


def test_merge_totals_sums_counters_and_keeps_latest_flags():
    a = evidence.GateStats(mode="shadow")
    a.record(evidence.GateDecision(True, "x"))
    a.site_calls["with_indicator"] += 2
    b = evidence.GateStats(mode="enforce", sightings_decoupled=True)
    b.record(evidence.GateDecision(False, "y"))
    b.indicators_withheld = 1
    t = evidence.merge_totals(None, a.to_dict())
    t = evidence.merge_totals(t, b.to_dict())
    assert t["cycles"] == 2
    assert t["accepted"] == {"x": 1} and t["refused"] == {"y": 1}
    assert t["site_calls"]["with_indicator"] == 2
    assert t["indicators_withheld"] == 1
    assert t["mode"] == "enforce" and t["sightings_decoupled"] is True
