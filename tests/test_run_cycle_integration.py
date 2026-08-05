"""End-to-end integration test for a single importer cycle.

V1_SPEC §13 called for a "mock ES → one cycle → assert counts" test; it
was never built, so `run_cycle` was only ever exercised indirectly. This
drives one real cycle through the real parser → correlate → build →
publish path with fake ES + fake publisher seams, and asserts the shape
of what lands.

It also carries the integration-level regression guard for the
2026-07-19 → 08-04 stall: **attack-pattern SDOs must be bounded by the
technique allowlist, not emitted once per session/IP.** Feeding many
distinct attacker IPs that all run commands must still collapse to a
handful of AttackPatterns — the exact property the outage violated
(~947k attack-patterns in one bundle).
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

from tpot2cti.main import run_cycle
from tpot2cti.stix.builder import STIXBuilder

_FIXTURES = Path(__file__).parent / "fixtures" / "real"


def _public_ip(n: int) -> str:
    """A globally-routable attacker IP.

    The fixtures are sanitized to TEST-NET documentation ranges
    (203.0.113.x etc.), which the cycle's self-filter correctly drops as
    non-global. Real attackers are on routable space, so tests remap
    src_ip into a public block to exercise the full ingest path.
    """
    return f"45.9.{(n // 254) % 254}.{(n % 254) + 1}"


def _command_cowrie_doc() -> dict:
    """A real (sanitized) Cowrie command event from the fixtures."""
    for line in (_FIXTURES / "cowrie.jsonl").read_text().splitlines():
        d = json.loads(line)
        if d.get("input"):
            return d
    raise AssertionError("no command-bearing cowrie fixture found")


class _FakeES:
    """Yields a fixed list of docs from stream_events(), matching the
    real TpotESClient call shape run_cycle uses."""

    def __init__(self, docs: list[dict]):
        self._docs = docs

    def stream_events(self, start, end, **kwargs):
        yield from self._docs


class _CapturingPublisher:
    """Captures the objects run_cycle hands to publish() and reports OK."""

    def __init__(self, errors=None):
        self.objects: list[dict] = []
        self._errors = list(errors or [])

    def publish(self, objects, cycle_id=None):
        self.objects = list(objects)
        # Mirrors the REAL PublishResult: it reports failure through `errors`
        # and has no `ok` attribute. The previous fake returned `ok=True`, a
        # shape the publisher never produces — so it could not have caught the
        # bug where CORE read `.ok` and treated every failure as success.
        return SimpleNamespace(cycle_id=cycle_id, pass_counts={},
                               errors=list(self._errors))


def _run(cfg, state_db, docs):
    pub = _CapturingPublisher()
    summary = run_cycle(
        cfg,
        state_db,
        _FakeES(docs),
        lambda: STIXBuilder(cfg),
        pub,
    )
    return summary, pub.objects


def test_one_cycle_produces_graph_and_advances_cursor(cfg, state_db):
    """A cycle over real Cowrie docs publishes a graph and advances the
    cursor on success."""
    docs = []
    ip_map: dict[str, str] = {}
    for line in (_FIXTURES / "cowrie.jsonl").read_text().splitlines():
        d = json.loads(line)
        # Remap each sanitized (TEST-NET) src_ip to a stable public IP so
        # the self-filter doesn't drop it. Same original → same public IP,
        # preserving the fixture's session/IP structure.
        orig = d.get("src_ip")
        if orig and orig not in ip_map:
            ip_map[orig] = _public_ip(len(ip_map))
        if orig:
            d["src_ip"] = ip_map[orig]
        docs.append(d)
    assert state_db.get_last_run() is None  # fresh

    summary, objects = _run(cfg, state_db, docs)

    assert summary["publish_ok"] is True
    assert state_db.get_last_run() is not None  # advanced only on success
    types = {o["type"] for o in objects}
    assert "ipv4-addr" in types
    assert "indicator" in types

    # Drop-reason accounting: every read event is exactly one of parsed /
    # unparsed / dispatch_error / src_ip_rejected / self_or_internal /
    # benign_scanner.
    dr = summary["drop_reasons"]
    assert set(dr) == {
        "unparsed", "dispatch_error", "src_ip_rejected",
        "self_or_internal", "benign_scanner",
    }
    accounted = summary["events_parsed"] + sum(dr.values())
    assert accounted == summary["events_read"], (
        f"events unaccounted for: read={summary['events_read']} "
        f"parsed={summary['events_parsed']} drops={dr}"
    )
    # The breakdown is also persisted for /health to read.
    import json as _json
    assert _json.loads(state_db.get("last_cycle_drops")) == dr


def test_attack_patterns_are_technique_bounded_not_per_event(cfg, state_db):
    """Regression guard for the 2026-07-19 stall.

    60 distinct attacker IPs, each running a command, must collapse to a
    handful of AttackPatterns (bounded by the ~30-technique allowlist) —
    NOT one AttackPattern per session/IP. Pre-fix this produced attack-
    patterns scaling with event count and overflowed the publish path.
    """
    base = _command_cowrie_doc()
    docs = []
    for i in range(1, 61):
        d = copy.deepcopy(base)
        d["src_ip"] = _public_ip(i)           # distinct routable attacker each time
        d["session"] = f"deadbeef{i:04d}"     # distinct session
        docs.append(d)

    summary, objects = _run(cfg, state_db, docs)
    assert summary["publish_ok"] is True

    by_type: dict[str, int] = {}
    for o in objects:
        by_type[o["type"]] = by_type.get(o["type"], 0) + 1

    ipv4 = by_type.get("ipv4-addr", 0)
    aps = by_type.get("attack-pattern", 0)

    # The 60 distinct IPs came through as observables...
    assert ipv4 >= 50, f"expected ~60 distinct IPs, got {ipv4}"
    # ...and the commands DID map to techniques (guards against a broken
    # ATT&CK path making the bound below pass vacuously)...
    assert aps > 0, "expected at least one attack-pattern from command sessions"
    # ...but AttackPatterns are bounded by the technique allowlist, and in
    # particular do NOT scale with the number of IPs/sessions.
    assert aps <= 40, f"attack-patterns not deduped: {aps} (regression!)"
    assert aps < ipv4, (
        f"attack-patterns ({aps}) scaling with events/IPs ({ipv4}) — the "
        f"2026-07-19 per-session re-emission bug has regressed"
    )


def test_query_exclusion_and_unparsed_breakdown_reach_state(cfg, state_db):
    """Both reviewers flagged the previous version of this test: it asserted on
    `inspect.getsource` text, verified nothing behavioural, and passed while the
    persistence it claimed to check did not exist anywhere in the codebase. A
    counter that documents a data EXCLUSION is the only evidence the exclusion
    happened, so this reads the rows back."""
    import json as _json
    docs = [json.loads(l) for l in
            (_FIXTURES / "cowrie.jsonl").read_text().splitlines() if l.strip()]
    # one doc the parser cannot use, to populate the breakdown
    docs.append({"type": "Suricata", "src_ip": "198.51.100.21",
                 "event_type": "flow", "@timestamp": docs[0]["@timestamp"],
                 "t-pot_hostname": "sensor01"})
    summary, _ = _run(cfg, state_db, docs)

    assert "unparsed_by_source" in summary
    assert summary["unparsed_by_source"].get("Suricata:flow") == 1, \
        "Suricata must be split by event_type, not lumped under one key"

    persisted = state_db.get("last_cycle_unparsed_by_source")
    assert persisted is not None, "breakdown documented as durable but never written"
    assert _json.loads(persisted).get("Suricata:flow") == 1
    assert state_db.get("last_cycle_query_excluded") is not None, \
        "query_excluded documented as durable but never written"


def test_a_failed_publish_is_not_recorded_as_success(cfg, state_db):
    """CORE read `getattr(result, "ok", True)`, but PublishResult has no `ok` —
    so every publish, including total failures, evaluated to success and
    advanced `last_run` past data that never landed. The old fake returned
    `ok=True`, a shape the real publisher never produces, so the suite could
    not have caught it."""
    from dataclasses import fields
    from tpot2cti.publisher import PublishResult
    assert "ok" not in [f.name for f in fields(PublishResult)], \
        "PublishResult grew an `ok` field — revisit how success is detected"

    docs = [json.loads(l) for l in
            (_FIXTURES / "cowrie.jsonl").read_text().splitlines() if l.strip()]
    pub = _CapturingPublisher(errors=["Pass 'entities' failed: 500"])
    summary = run_cycle(cfg, state_db, _FakeES(docs), lambda: STIXBuilder(cfg), pub)

    assert summary["publish_ok"] is False, "a failed publish reported success"
    assert state_db.get_last_run() is None, \
        "cursor advanced past a publish that failed — silent data loss"
