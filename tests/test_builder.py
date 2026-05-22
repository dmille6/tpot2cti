"""STIXBuilder invariants.

The three properties we guard:
  - Deterministic ids: build_X(seed) twice → identical id
  - Dual sighting emits TWO sightings with distinct ids
  - Every SCO builder accepts a ``session=`` kwarg without raising

These guard against the 2026-05-22 audit #6 regression (3 SCO builders
silently dropped session enrichment) and the dual-sight Sightings work
in commit 8887bdb.
"""

from __future__ import annotations

import pytest

from tpot2cti.stix.builder import STIXBuilder
from tpot2cti.stix_ids import generate_ip_indicator_id, generate_ipv4_id


def test_ipv4_id_is_deterministic(cfg):
    """Two builders produce the same IPv4-Addr id for the same IP."""
    b1, b2 = STIXBuilder(cfg), STIXBuilder(cfg)
    o1 = b1.build_ipv4("1.2.3.4")
    o2 = b2.build_ipv4("1.2.3.4")
    assert o1["id"] == o2["id"]


def test_ipv4_rejects_garbage(builder):
    """build_ipv4 returns None on a non-IPv4 string."""
    assert builder.build_ipv4("not-an-ip") is None
    assert builder.build_ipv4("") is None


def test_indicator_id_is_deterministic(cfg, synthetic_session):
    """Same (session.src_ip) → same Indicator id across two builders."""
    b1, b2 = STIXBuilder(cfg), STIXBuilder(cfg)
    i1 = b1.build_ip_indicator(synthetic_session.src_ip, session=synthetic_session)
    i2 = b2.build_ip_indicator(synthetic_session.src_ip, session=synthetic_session)
    assert i1["id"] == i2["id"]


def test_dual_sighting_emits_two_distinct(builder, synthetic_session):
    """build_dual_sighting yields one Indicator-side + one Observable-side."""
    ipv4_id = generate_ipv4_id(synthetic_session.src_ip)
    ind_id = generate_ip_indicator_id(synthetic_session.src_ip)
    sightings = builder.build_dual_sighting(
        ind_id, ipv4_id, synthetic_session.sensor_hostname, synthetic_session,
    )
    assert len(sightings) == 2
    ids = {s["id"] for s in sightings}
    assert len(ids) == 2, "Indicator-side and Observable-side Sightings must have distinct ids"
    targets = {s["sighting_of_ref"] for s in sightings}
    assert targets == {ind_id, ipv4_id}


def test_dual_sighting_skips_missing_sides(builder, synthetic_session):
    """Passing None for one side suppresses just that Sighting."""
    ipv4_id = generate_ipv4_id(synthetic_session.src_ip)
    only_obs = builder.build_dual_sighting(
        "", ipv4_id, synthetic_session.sensor_hostname, synthetic_session,
    )
    assert len(only_obs) == 1
    assert only_obs[0]["sighting_of_ref"] == ipv4_id


@pytest.mark.parametrize("builder_method,args", [
    ("build_ipv4",              ("1.2.3.4",)),
    ("build_file",              ("a" * 64,)),
    ("build_url",               ("http://evil.example/x",)),
    ("build_domain",            ("evil.example",)),
    ("build_cryptographic_key", ("deadbeefcafebabe",)),
    ("build_country_location",  ("US",)),
    ("build_city_location",     ("US", "Mountain View")),
    ("build_autonomous_system", (64500,)),
])
def test_sco_builders_accept_session_kwarg(builder, synthetic_session, builder_method, args):
    """Every SCO/Location/AS builder MUST accept session= per audit #6.

    The audit found build_country_location/build_city_location/
    build_autonomous_system silently dropped session enrichment. This
    test makes the contract executable.
    """
    method = getattr(builder, builder_method)
    obj = method(*args, session=synthetic_session)
    assert obj is not None, f"{builder_method}: returned None"
    # When session is provided, enrichment fields appear on the object.
    assert "x_opencti_labels" in obj or "x_opencti_description" in obj, (
        f"{builder_method}: session= did not produce x_opencti_* enrichment "
        f"(audit #6 regression)"
    )


def test_driveby_session_emits_dual_sighting(builder, synthetic_session):
    """build_driveby_session always emits two Sightings (Ind + Obs)."""
    objs = builder.build_driveby_session(synthetic_session)
    sightings = [o for o in objs if o["type"] == "sighting"]
    assert len(sightings) == 2


def test_full_cowrie_session_has_substance_objects(builder, synthetic_session):
    """A substantive Cowrie session emits Process + File + URL + Domain."""
    objs = builder.build_cowrie_session(synthetic_session)
    types = {o["type"] for o in objs}
    for required in ("process", "file", "url", "domain-name", "indicator", "sighting"):
        assert required in types, f"missing {required!r} in full Cowrie graph"


def test_stamp_adds_required_fields(builder):
    """_stamp populates created/modified/created_by_ref/marking on every obj."""
    obj = builder.build_ipv4("1.2.3.4")
    assert obj["spec_version"] == "2.1"
    assert obj["created"] and obj["modified"]
    assert obj["created_by_ref"].startswith("identity--")
    assert obj["object_marking_refs"]
