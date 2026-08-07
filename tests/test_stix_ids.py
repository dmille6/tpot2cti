"""STIX-id helper invariants.

Every generate_* function MUST be deterministic and produce a valid
``<type>--<uuid>`` string.  This is the contract documented in
stix_ids.py: same logical input → same UUID forever.  If it breaks,
every prior emission in OpenCTI gets orphaned (see LESSONS §3).
"""

from __future__ import annotations

import re
import uuid

import pytest

from tpot2cti import stix_ids as S


STIX_ID_RE = re.compile(r"^[a-z][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


# (helper_name, args) — at least one happy case per generator.
CASES = [
    ("generate_identity_id",                  ("Test Org", "organization")),
    ("generate_sensor_id",                    ("node1",)),
    ("generate_ipv4_id",                      ("1.2.3.4",)),
    ("generate_file_id",                      ("a" * 64,)),
    ("generate_url_id",                       ("http://evil.example/x",)),
    ("generate_domain_id",                    ("evil.example",)),
    ("generate_process_id",                   (["uname -a", "cat /etc/passwd"],)),
    ("generate_cryptographic_key_id",         ("deadbeef",)),
    ("generate_autonomous_system_id",         (64500,)),
    ("generate_country_location_id",          ("US",)),
    ("generate_city_location_id",             ("US", "Reno")),
    ("generate_session_note_id",              ("node1", "sess001")),
    ("generate_attacker_profile_note_id",     ("1.2.3.4",)),
    ("generate_attacker_daily_note_id",       ("1.2.3.4", "2026-05-22")),
    ("generate_attacker_weekly_note_id",      ("1.2.3.4", 2026, 21)),
    ("generate_attack_pattern_id",            ("T1110",)),
    ("generate_file_indicator_id",            ("a" * 64,)),
    ("generate_ip_indicator_id",              ("1.2.3.4",)),
    ("generate_sighting_id",                  ("node1", "sess001")),
    ("generate_infrastructure_id",            ("node1",)),
    ("generate_malware_id",                   ("mirai",)),
    ("generate_vulnerability_id",             ("CVE-2021-44228",)),
]


@pytest.mark.parametrize("helper,args", CASES)
def test_generator_produces_valid_stix_id(helper, args):
    """The id matches STIX 2.1's ``<type>--<uuid>`` regex."""
    val = getattr(S, helper)(*args)
    assert STIX_ID_RE.match(val), f"{helper}{args} -> {val!r}"


@pytest.mark.parametrize("helper,args", CASES)
def test_generator_is_deterministic(helper, args):
    """Same input twice → identical UUID."""
    a = getattr(S, helper)(*args)
    b = getattr(S, helper)(*args)
    assert a == b


def test_marking_definition_returns_static_id():
    """TLP marking ids are STIX 2.1 statics, not UUID5-derived."""
    mid = S.generate_marking_definition_id("amber+strict")
    assert mid == "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"


def test_marking_definition_rejects_unknown_tlp():
    """An unknown TLP level raises ValueError, not silently misroutes."""
    with pytest.raises(ValueError):
        S.generate_marking_definition_id("pink")


def test_sighting_discriminator_yields_distinct_id():
    """Same (sensor, session) + a discriminator → a distinct Sighting id.

    Guards the dual-sight Sightings pattern from commit 8887bdb.
    """
    a = S.generate_sighting_id("node1", "sess001")
    b = S.generate_sighting_id("node1", "sess001", "ipv4")
    assert a != b


def test_sensor_infra_name_prefers_name_over_alias():
    """The LESSONS §3 invariant: every parser hashes the SAME string."""
    assert S.sensor_infra_name({"name": "node2", "alias": "n2"}) == "node2"
    assert S.sensor_infra_name({"alias": "n2"}) == "n2"
    assert S.sensor_infra_name({}) == ""


def test_infrastructure_id_empty_for_empty_sensor():
    """An empty sensor dict yields an empty string, not a bogus UUID."""
    assert S.generate_infrastructure_id_for_sensor({}) == ""
