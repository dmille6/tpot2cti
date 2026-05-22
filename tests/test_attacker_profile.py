"""Attacker-profile Note ids — UUID5 idempotence across cadences.

Per V1_SPEC §4 + LESSONS §3: the three attacker-profile Note ids
(live/daily/weekly) are deterministic from (ip, cadence, period).
Re-emission in a later cycle MUST produce the same id so OpenCTI
upserts in place rather than spawning a Note per cycle (which is the
50k-Notes-per-day anti-pattern from PoC LESSONS §7.1).
"""

from __future__ import annotations

from tpot2cti.stix_ids import (
    generate_attacker_daily_note_id,
    generate_attacker_profile_note_id,
    generate_attacker_weekly_note_id,
)


def test_live_note_id_idempotent():
    """Two calls for the same IP produce the same live Note id."""
    a = generate_attacker_profile_note_id("203.0.113.42")
    b = generate_attacker_profile_note_id("203.0.113.42")
    assert a == b


def test_different_ips_yield_different_live_notes():
    """Different IPs map to distinct Note ids."""
    a = generate_attacker_profile_note_id("203.0.113.42")
    b = generate_attacker_profile_note_id("203.0.113.43")
    assert a != b


def test_daily_note_id_keyed_on_ip_and_date():
    """Same (ip, date) → same id; different date → different id."""
    a = generate_attacker_daily_note_id("203.0.113.42", "2026-05-22")
    b = generate_attacker_daily_note_id("203.0.113.42", "2026-05-22")
    c = generate_attacker_daily_note_id("203.0.113.42", "2026-05-23")
    assert a == b
    assert a != c


def test_weekly_note_id_keyed_on_iso_year_and_week():
    """Same (ip, iso_year, iso_week) twice → same id; different week → distinct."""
    a = generate_attacker_weekly_note_id("203.0.113.42", 2026, 21)
    b = generate_attacker_weekly_note_id("203.0.113.42", 2026, 21)
    c = generate_attacker_weekly_note_id("203.0.113.42", 2026, 22)
    assert a == b
    assert a != c


def test_cadence_namespaces_are_distinct():
    """live, daily, weekly Note ids never collide for the same IP."""
    live = generate_attacker_profile_note_id("203.0.113.42")
    daily = generate_attacker_daily_note_id("203.0.113.42", "2026-05-22")
    weekly = generate_attacker_weekly_note_id("203.0.113.42", 2026, 21)
    assert len({live, daily, weekly}) == 3
