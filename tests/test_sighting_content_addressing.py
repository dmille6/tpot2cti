"""A Sighting is a DAILY AGGREGATE of one entity at one sensor.

Sighting ids were `generate_sighting_id(sensor, session_id)` — one per
session. OpenCTI derives a Sighting's identity from (sighting_of_ref,
where_sighted_refs, first_seen, last_seen), so where many low-volume sessions
shared a window — `first_seen == last_seen` on the same second — OpenCTI
computed ONE id while we minted one per session, and every one of ours became
an alias on that single object.

Measured live 2026-08-19: one Sighting event in the Redis stream weighed
1,736,299 bytes, almost all of it that alias array. Every update republishes
the whole object, so the stream reached 53 GB at only 100,000 entries, filled
a 490 GB disk and tripped Elasticsearch's flood-stage watermark — three days
of dead ingestion on 08-08, and again on 08-19.

THE FIRST ATTEMPT AT THIS WAS WRONG and is worth remembering: content-address
on (target, sensor). That inverts the failure rather than fixing it — our id
goes stable while OpenCTI's still moves with the window, so one alias ends up
claimed by many objects. Both ids have to be stable, which means the WINDOW we
send has to be stable. Hence the day bucket, and hence deriving the id from
pycti so it equals OpenCTI's by construction rather than by hope.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tpot2cti.parsers.base import AttackSession
from tpot2cti.stix_ids import (generate_sensor_id, generate_sighting_id,
                               sighting_day_bucket)

DAY = datetime(2026, 8, 19, tzinfo=timezone.utc)
TARGET = "indicator--11111111-1111-5111-8111-111111111111"
OTHER = "ipv4-addr--22222222-2222-5222-8222-222222222222"


def _sess(sid="s1", sensor="sensor01", at=None, last=None):
    at = at or DAY.replace(hour=14, minute=3)
    return AttackSession(
        src_ip="203.0.113.1", session_id=sid, sensor_hostname=sensor,
        event_type="Cowrie", first_seen=at, last_seen=last or at,
    )


# ── the guarantee that makes alias growth zero ───────────────────────────

def test_our_id_is_the_id_opencti_derives(cfg):
    """The whole point. Not a tautology to lock down: if anyone reimplements
    this seed locally with sdo_id, aliases start accumulating again and
    nothing else in the suite would notice."""
    from pycti import StixSightingRelationship
    sensor = generate_sensor_id("sensor01")
    first, last = sighting_day_bucket(DAY.replace(hour=14))
    assert generate_sighting_id(TARGET, sensor, first, last) == \
        StixSightingRelationship.generate_id(TARGET, [sensor], first, last)


def test_the_emitted_object_and_its_id_use_the_same_window(cfg):
    """An id derived from a window the object does not carry is the defect in
    a new costume — OpenCTI would compute a different id from the fields."""
    from pycti import StixSightingRelationship
    from tpot2cti.stix.builder import STIXBuilder
    o = STIXBuilder(cfg).build_sighting(TARGET, "sensor01", _sess())
    assert o["id"] == StixSightingRelationship.generate_id(
        o["sighting_of_ref"], o["where_sighted_refs"],
        o["first_seen"], o["last_seen"],
    )


# ── identity: stable within a day, distinct across the things that matter ─

def test_two_sessions_on_one_day_reach_one_sighting(cfg):
    from tpot2cti.stix.builder import STIXBuilder
    a = STIXBuilder(cfg).build_sighting(
        TARGET, "sensor01", _sess("aaa", at=DAY.replace(hour=2)))
    b = STIXBuilder(cfg).build_sighting(
        TARGET, "sensor01", _sess("zzz", at=DAY.replace(hour=22)))
    assert a is not None and b is not None, "guard: both must be built"
    assert a["id"] == b["id"], "sessions still mint different Sighting ids"


def test_the_next_day_is_a_different_sighting(cfg):
    """The positive control for bucketing — without it the id never changes
    and 'daily aggregate' would be 'one object forever'."""
    from tpot2cti.stix.builder import STIXBuilder
    a = STIXBuilder(cfg).build_sighting(TARGET, "sensor01", _sess(at=DAY))
    b = STIXBuilder(cfg).build_sighting(
        TARGET, "sensor01", _sess(at=DAY + timedelta(days=1)))
    assert a["id"] != b["id"]


def test_a_different_sensor_or_target_is_a_different_sighting(cfg):
    from tpot2cti.stix.builder import STIXBuilder
    base = STIXBuilder(cfg).build_sighting(TARGET, "sensor01", _sess())
    other_sensor = STIXBuilder(cfg).build_sighting(TARGET, "sensor02", _sess())
    other_target = STIXBuilder(cfg).build_sighting(OTHER, "sensor01", _sess())
    assert base["id"] != other_sensor["id"], "sensors collapsed together"
    assert base["id"] != other_target["id"], "targets collapsed together"


def test_the_dual_sighting_pair_is_distinct_without_a_discriminator(builder):
    """Indicator-side and observable-side differ on target_ref alone now."""
    objs = builder.build_dual_sighting(TARGET, OTHER, "sensor01", _sess())
    ids = [o["id"] for o in objs if o.get("type") == "sighting"]
    assert len(ids) == 2, f"expected both sightings, got {len(ids)}"
    assert ids[0] != ids[1]


# ── the window is a bucket, and is honest about it ───────────────────────

def test_the_window_is_the_utc_day_not_the_session(cfg):
    from tpot2cti.stix.builder import STIXBuilder
    o = STIXBuilder(cfg).build_sighting(
        TARGET, "sensor01", _sess(at=DAY.replace(hour=14, minute=3)))
    assert o["first_seen"].startswith("2026-08-19T00:00:00"), o["first_seen"]
    assert o["last_seen"].startswith("2026-08-19T23:59:59"), o["last_seen"]


def test_the_bucket_is_a_superset_of_what_was_observed(cfg):
    """A bucket that did not contain the observation would be a false claim."""
    obs = DAY.replace(hour=14, minute=3, second=27)
    first, last = sighting_day_bucket(obs)
    assert datetime.fromisoformat(first) <= obs <= datetime.fromisoformat(last)


def test_a_non_utc_timestamp_buckets_to_its_utc_day(cfg):
    """23:30 in UTC+2 is 21:30Z — still 19 Aug in UTC.

    Compared as an INSTANT, not by string prefix. `.replace(hour=0)` without
    converting first yields "2026-08-19T00:00:00+02:00", whose prefix matches
    the UTC day start while being 22:00Z on the 18th — a different bucket. A
    startswith() assertion here passes either way and proves nothing; the
    mutation run is what exposed that.
    """
    tz2 = timezone(timedelta(hours=2))
    first, last = sighting_day_bucket(datetime(2026, 8, 19, 23, 30, tzinfo=tz2))
    assert datetime.fromisoformat(first) == datetime(2026, 8, 19, tzinfo=timezone.utc), \
        f"bucket starts at {first}, not the UTC day boundary"
    assert datetime.fromisoformat(last) == datetime(
        2026, 8, 19, 23, 59, 59, 999999, tzinfo=timezone.utc), last


# ── merging duplicates, which bucketing makes the common path ────────────

def test_duplicate_sightings_add_their_counts(builder):
    kept = builder.build_sighting(TARGET, "sensor01", _sess("s1"), count=3)
    dup = builder.build_sighting(TARGET, "sensor01", _sess("s2"), count=5)
    assert dup is None, "guard: the duplicate must not be a second object"
    assert kept["count"] == 8, (
        f"count is {kept['count']}, expected 3+5=8 — a Sighting is a tally, "
        "so duplicates ADD; max() would silently lose sessions"
    )


def test_a_merged_sighting_does_not_keep_one_sessions_description(builder):
    """Attaching one session's summary to an aggregate of several states
    something about the whole that was only true of one part."""
    builder.build_sighting(TARGET, "sensor01", _sess("s1"),
                           description="12 probes on port 445")
    kept_id = generate_sighting_id(
        TARGET, generate_sensor_id("sensor01"), *sighting_day_bucket(DAY))
    builder.build_sighting(TARGET, "sensor01", _sess("s2"),
                           description="unattributed payload blurb")
    kept = builder._emitted_sightings[kept_id]
    assert "port 445" not in kept["description"], (
        "the aggregate still claims one session's summary"
    )
    assert "Aggregate" in kept["description"]


def test_an_identical_description_is_not_replaced(builder):
    """Only DISAGREEMENT makes the per-session text wrong for the whole."""
    d = "SSH brute force"
    builder.build_sighting(TARGET, "sensor01", _sess("s1"), description=d)
    kept_id = generate_sighting_id(
        TARGET, generate_sensor_id("sensor01"), *sighting_day_bucket(DAY))
    builder.build_sighting(TARGET, "sensor01", _sess("s2"), description=d)
    assert builder._emitted_sightings[kept_id]["description"] == d
