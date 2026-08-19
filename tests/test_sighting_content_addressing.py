"""A Sighting is an aggregate of one entity at one sensor, not one per session.

Sighting ids were `generate_sighting_id(sensor, session_id)` — a fresh id for
every session, for a fact that is not per-session. OpenCTI derives its own
content-based standard_id for a Sighting, so it merged them all into one
object and filed each of our discarded ids in that object's `stix_ids` alias
array.

Measured on the live platform 2026-08-19: a single Sighting event in the Redis
stream weighed **1,736,299 bytes**, nearly all of it that array. Because every
update republishes the whole object, the stream hit 53 GB at only 100,000
entries, filled a 490 GB disk, and tripped Elasticsearch's flood-stage
watermark — killing ingestion for three days on 08-08 and again on 08-19.

Same defect and same fix as generate_process_id (PR #43).
"""
from __future__ import annotations

from datetime import datetime, timezone

from tpot2cti.parsers.base import AttackSession, ParsedEvent
from tpot2cti.stix_ids import generate_sighting_id, generate_sensor_id

NOW = datetime(2026, 8, 19, 12, 0, tzinfo=timezone.utc)
TARGET = "indicator--11111111-1111-5111-8111-111111111111"


def _sess(sid="s1", sensor="sensor01", ip="203.0.113.1", first=None, last=None):
    return AttackSession(
        src_ip=ip, session_id=sid, sensor_hostname=sensor, event_type="Cowrie",
        first_seen=first or NOW, last_seen=last or NOW,
    )


# ── identity ──────────────────────────────────────────────────────────────

def test_the_same_entity_at_the_same_sensor_is_one_id(cfg):
    """The regression lock — the id must not move with the session."""
    sen = generate_sensor_id("sensor01")
    assert generate_sighting_id(TARGET, sen) == generate_sighting_id(TARGET, sen)


def test_the_id_does_not_depend_on_the_session(builder, cfg):
    from tpot2cti.stix.builder import STIXBuilder
    a = STIXBuilder(cfg).build_sighting(TARGET, "sensor01", _sess("aaa"))
    b = STIXBuilder(cfg).build_sighting(TARGET, "sensor01", _sess("zzz"))
    assert a is not None and b is not None, "guard: both must be built"
    assert a["id"] == b["id"], (
        "two sessions minted different Sighting ids — this is the 1.7 MB "
        "alias-array defect"
    )


def test_a_different_sensor_is_a_different_sighting(cfg):
    """The positive control. Over-collapsing would merge separate sensors."""
    from tpot2cti.stix.builder import STIXBuilder
    a = STIXBuilder(cfg).build_sighting(TARGET, "sensor01", _sess())
    b = STIXBuilder(cfg).build_sighting(TARGET, "sensor02", _sess())
    assert a["id"] != b["id"]


def test_a_different_target_is_a_different_sighting(cfg):
    from tpot2cti.stix.builder import STIXBuilder
    other = "ipv4-addr--22222222-2222-5222-8222-222222222222"
    a = STIXBuilder(cfg).build_sighting(TARGET, "sensor01", _sess())
    b = STIXBuilder(cfg).build_sighting(other, "sensor01", _sess())
    assert a["id"] != b["id"]


def test_the_dual_sighting_pair_stays_distinct(cfg):
    """One Sighting on the Indicator, one on the observable — two different
    assertions about two different targets, and the discriminator must keep
    them apart even though both share a sensor."""
    from tpot2cti.stix.builder import STIXBuilder
    b = STIXBuilder(cfg)
    x = b.build_sighting(TARGET, "sensor01", _sess())
    y = b.build_sighting(TARGET, "sensor01", _sess(), id_discriminator="ipv4")
    assert x is not None and y is not None
    assert x["id"] != y["id"]


# ── the merge that content-addressing makes necessary ────────────────────
#
# Collapsing the id means several sessions in one bundle now land on ONE
# Sighting. `_dedup` returning None for the later ones would throw away their
# counts and their half of the window -- the platform under-reporting exactly
# the volume a Sighting exists to report. Third time this repo has hit
# "_dedup returned None" being read as "nothing to do here".

def test_duplicate_sightings_add_their_counts(builder):
    kept = builder.build_sighting(TARGET, "sensor01", _sess("s1"), count=3)
    dup = builder.build_sighting(TARGET, "sensor01", _sess("s2"), count=5)
    assert dup is None, "guard: the duplicate must not be emitted as its own object"
    assert kept["count"] == 8, (
        f"count is {kept['count']}, expected 3+5=8 — a Sighting is a tally, "
        "so duplicates ADD; taking max() would silently lose sessions"
    )


def test_duplicate_sightings_widen_the_window(builder):
    early = _sess("s1", first=datetime(2026, 8, 19, 8, tzinfo=timezone.utc),
                  last=datetime(2026, 8, 19, 9, tzinfo=timezone.utc))
    late = _sess("s2", first=datetime(2026, 8, 19, 14, tzinfo=timezone.utc),
                 last=datetime(2026, 8, 19, 15, tzinfo=timezone.utc))
    kept = builder.build_sighting(TARGET, "sensor01", early)
    builder.build_sighting(TARGET, "sensor01", late)
    assert kept["first_seen"].startswith("2026-08-19T08"), kept["first_seen"]
    assert kept["last_seen"].startswith("2026-08-19T15"), (
        f"last_seen is {kept['last_seen']} — the later observation was dropped"
    )


def test_an_earlier_duplicate_moves_first_seen_back(builder):
    """Sessions do not arrive in time order."""
    late = _sess("s1", first=datetime(2026, 8, 19, 14, tzinfo=timezone.utc),
                 last=datetime(2026, 8, 19, 15, tzinfo=timezone.utc))
    early = _sess("s2", first=datetime(2026, 8, 19, 8, tzinfo=timezone.utc),
                  last=datetime(2026, 8, 19, 9, tzinfo=timezone.utc))
    kept = builder.build_sighting(TARGET, "sensor01", late)
    builder.build_sighting(TARGET, "sensor01", early)
    assert kept["first_seen"].startswith("2026-08-19T08")
    assert kept["last_seen"].startswith("2026-08-19T15"), "stop should stay latest"
