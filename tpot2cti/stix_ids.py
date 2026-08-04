"""
tpot2cti.stix_ids
=================

Canonical, deterministic STIX 2.1 ID generator for the tpot2cti project.

This module is THE single source of truth for converting a logical entity
(an IPv4 address, a sensor, a file hash, a session, a TTP, etc.) into a
STIX 2.1 `<type>--<uuid5>` identifier. Every parser, every SDO builder,
every publisher across the project MUST import the helpers defined here.
Direct calls to ``uuid.uuid5()`` outside this module are FORBIDDEN.

Why this exists (read this before changing anything!)
-----------------------------------------------------

1. **The namespace constant ``NS_DNS`` MUST NEVER change between
   releases.** Every previously-emitted SDO in OpenCTI has a UUID derived
   from this namespace + a seed string. If the namespace shifts by even
   one bit, every prior SDO becomes orphaned, every cross-cycle
   relationship dangles, and OpenCTI's worker pool falls into a
   LOCK_ERROR cascade trying to auto-create the "missing" entities.
   This is documented in ``docs/LESSONS_LEARNED_FROM_V0.md`` §3.

2. **``sensor_infra_name()`` is THE helper for sensor IDs.** A sensor
   has both a ``name`` and an ``alias`` in the config. Different code
   paths (parser A vs parser B vs the Infrastructure builder) will
   naturally reach for different fields, producing two different UUIDs
   for the same logical sensor. The fix is to funnel every caller
   through one helper. See LESSONS_LEARNED_FROM_V0.md §3 for the full
   post-mortem of the UUID-drift bug that this prevents.

3. **Idempotency is the contract.** Same logical input → same UUID,
   forever, across every run, every host, every Python version. The
   ``if __name__ == "__main__"`` block at the bottom of this file is a
   smoke test you can run any time to confirm the contract still holds.

4. **Per V1_SPEC.md §4**, every per-entity-type helper takes the
   canonical identifier(s) for that entity and returns the deterministic
   id. The seed format is documented in each helper's docstring AND in
   the spec table; if you change a seed format you are breaking every
   previously-emitted SDO of that type. Don't.
"""

from __future__ import annotations

import uuid
from typing import Any

# ---------------------------------------------------------------------------
# Namespace — DO NOT CHANGE.
# ---------------------------------------------------------------------------
# Standard RFC 4122 DNS namespace. Picked once, fixed forever. Every
# tpot2cti SDO UUID in every OpenCTI database in the world is derived
# from this namespace. Changing it orphans every prior emission.
NS_DNS: uuid.UUID = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


# ---------------------------------------------------------------------------
# Core helper.
# ---------------------------------------------------------------------------
def sdo_id(stix_type: str, *seed_parts: Any) -> str:
    """Return a STIX 2.1 id of the form ``<type>--<uuid5>``.

    The seed string is the colon-joined string representation of
    ``seed_parts``. The same ``stix_type`` + same ``seed_parts`` will
    always produce the same UUID5.

    Args:
        stix_type: The STIX 2.1 type prefix (e.g. ``"ipv4-addr"``,
            ``"infrastructure"``, ``"indicator"``).
        *seed_parts: Canonical identifier components. Stringified and
            joined with ``":"`` to form the uuid5 seed.

    Returns:
        ``"<stix_type>--<uuid5>"`` — a valid STIX 2.1 id.
    """
    seed = ":".join(str(p) for p in seed_parts)
    return f"{stix_type}--{uuid.uuid5(NS_DNS, seed)}"


# ---------------------------------------------------------------------------
# Identity / sensor.
# ---------------------------------------------------------------------------
def generate_identity_id(name: str, identity_class: str) -> str:
    """Identity SDO id. Seed: ``identity:<class>:<lowercased-name>``."""
    return sdo_id("identity", "identity", identity_class, name.lower())


def generate_sensor_id(hostname: str) -> str:
    """Sensor-as-Identity id. Seed: ``identity:sensor:<hostname>``.

    This is the Identity SDO that represents a sensor (used in
    ``created_by_ref`` and similar). For the *Infrastructure* SDO that
    represents the sensor's network presence, use
    :func:`generate_infrastructure_id_for_sensor` instead.
    """
    return sdo_id("identity", "identity", "sensor", hostname)


# ---------------------------------------------------------------------------
# Observables (SCOs).
# ---------------------------------------------------------------------------
def generate_ipv4_id(ip: str) -> str:
    """IPv4-Addr SCO id. Seed: ``ipv4-addr:<ipv4>``."""
    return sdo_id("ipv4-addr", "ipv4-addr", ip)


def generate_ipv6_id(ip: str) -> str:
    """IPv6-Addr SCO id. Seed: ``ipv6-addr:<ipv6>``.

    Pass the canonical (compressed, lowercase) form so the same address in
    different textual notations doesn't fork into two ids.
    """
    return sdo_id("ipv6-addr", "ipv6-addr", ip)


def generate_file_id(sha256: str) -> str:
    """StixFile SCO id. Seed: ``stixfile:sha256:<sha256>``."""
    return sdo_id("file", "stixfile", "sha256", sha256.lower())


def generate_url_id(url: str) -> str:
    """URL SCO id. Seed: ``url:<full-url>``."""
    return sdo_id("url", "url", url)


def generate_domain_id(fqdn: str) -> str:
    """Domain-Name SCO id. Seed: ``domain-name:<fqdn>``."""
    return sdo_id("domain-name", "domain-name", fqdn.lower())


def generate_process_id(sensor: str, session_id: str) -> str:
    """Process SCO id. Seed: ``process:<sensor>:<session_id>``."""
    return sdo_id("process", "process", sensor, session_id)


def generate_cryptographic_key_id(value: str) -> str:
    """Cryptographic-Key SCO id. Seed: ``cryptographic-key:<value>``.

    Note: the correct STIX type is ``cryptographic-key``, NOT
    ``x-opencti-cryptographic-key`` (see LESSONS §8.4 for the
    silent-drop bug this prevents).
    """
    return sdo_id("cryptographic-key", "cryptographic-key", value)


def generate_autonomous_system_id(asn: int | str) -> str:
    """Autonomous-System SCO id. Seed: ``autonomous-system:<asn>``."""
    return sdo_id("autonomous-system", "autonomous-system", asn)


# ---------------------------------------------------------------------------
# Locations.
# ---------------------------------------------------------------------------
def generate_country_location_id(iso2: str) -> str:
    """Country Location SDO id. Seed: ``location:country:<iso2>``."""
    return sdo_id("location", "location", "country", iso2.upper())


def generate_city_location_id(iso2: str, city: str) -> str:
    """City Location SDO id. Seed: ``location:city:<iso2>:<city>``."""
    return sdo_id("location", "location", "city", iso2.upper(), city.lower())


# ---------------------------------------------------------------------------
# Notes.
# ---------------------------------------------------------------------------
def generate_session_note_id(sensor: str, session_id: str) -> str:
    """Per-session Note id. Seed: ``note:session:<sensor>:<session_id>``."""
    return sdo_id("note", "note", "session", sensor, session_id)


# ---------------------------------------------------------------------------
# Attacker-profile Note ids (per-IP rolling profile + daily/weekly snapshots).
# See ``tpot2cti/attacker_profile.py`` for the consumer and the V0 "don't emit 50K Notes/day" finding
# for the rationale (one rolling Note per attacker IP rather than 50 per-
# session Notes that nobody reads).
# ---------------------------------------------------------------------------

def generate_attacker_profile_note_id(ip: str) -> str:
    """Live attacker-profile Note id.

    Seed: ``note:attacker-profile:<ip>``. One Note per attacker IP,
    updated every cycle that sees activity from this IP. Idempotent
    via UUID5 so OpenCTI upserts in place rather than creating a new
    Note per cycle.
    """
    return sdo_id("note", "note", "attacker-profile", ip)


def generate_credential_note_id(ip: str) -> str:
    """Per-IP credential-summary Note id.

    Seed: ``note:credentials:<ip>``. One rolling Note per attacker IP
    summarising the (username, password) pairs it tried and which was
    accepted. Idempotent via UUID5 so OpenCTI upserts in place as the
    attacker's credential activity accumulates across cycles — the bulk
    pairs live in the local credential store, not OpenCTI.
    """
    return sdo_id("note", "note", "credentials", ip)


def generate_attacker_daily_note_id(ip: str, utc_date: str) -> str:
    """Daily attacker-profile snapshot Note id.

    Seed: ``note:attacker-daily:<ip>:<utc-date>``. One Note per
    (attacker IP, UTC calendar day). ``utc_date`` is ISO-8601
    ``YYYY-MM-DD``. Emitted once the cycle crosses UTC midnight.
    """
    return sdo_id("note", "note", "attacker-daily", ip, utc_date)


def generate_attacker_weekly_note_id(ip: str, iso_year: int, iso_week: int) -> str:
    """Weekly attacker-profile snapshot Note id.

    Seed: ``note:attacker-weekly:<ip>:<iso-year>:<iso-week>``. One Note
    per (attacker IP, ISO calendar week). ``iso_year`` is the ISO-8601
    week-numbering year (NOT the calendar year — they differ at year
    boundaries). ``iso_week`` is 1-53. Emitted once per cycle that
    crosses an ISO-week boundary (Monday 00:00 UTC).
    """
    return sdo_id("note", "note", "attacker-weekly", ip, str(iso_year), str(iso_week))


# ---------------------------------------------------------------------------
# TTPs / indicators / sightings.
# ---------------------------------------------------------------------------
def generate_attack_pattern_id(name: str) -> str:
    """Attack-Pattern SDO id. Seed: ``attack-pattern:<name>``."""
    return sdo_id("attack-pattern", "attack-pattern", name)


def generate_file_indicator_id(sha256: str) -> str:
    """File-hash Indicator SDO id. Seed: ``indicator:file:sha256:<sha256>``."""
    return sdo_id("indicator", "indicator", "file", "sha256", sha256.lower())


def generate_ip_indicator_id(ip: str) -> str:
    """IPv4 Indicator SDO id. Seed: ``indicator:ip:<ipv4>``."""
    return sdo_id("indicator", "indicator", "ip", ip)


def generate_campaign_id(artifact_key: str) -> str:
    """Campaign SDO id. Seed: ``campaign:<artifact_key>``.

    ``artifact_key`` is the shared concrete IoC that defines the campaign,
    e.g. ``"malware:<sha256>"``, ``"sshkey:<fingerprint>"``,
    ``"hassh:<hash>"``, ``"ja3:<hash>"`` (see ``tpot2cti/campaigns.py``).
    Deterministic so every cycle that observes another IP sharing the same
    artifact attributes it to the SAME Campaign node in OpenCTI.
    """
    return sdo_id("campaign", "campaign", artifact_key)


def generate_sighting_id(sensor: str, session_id: str, discriminator: str = "") -> str:
    """Sighting SRO id. Seed: ``sighting:<sensor>:<session_id>[:<discriminator>]``.

    The optional ``discriminator`` lets callers mint a second distinct
    Sighting ID for the same (sensor, session) pair — used by the dual-
    sighting pattern where one Sighting targets the IP Indicator (SDO)
    and a second targets the IPv4-Addr observable (SCO) so OpenCTI's
    "Sightings" tab populates on BOTH the Indicator page and the
    Observable page.  Empty discriminator (the default) preserves the
    pre-existing Indicator-side ID family so cross-cycle re-emission
    updates the same Sighting count, not orphan a new one.
    """
    if discriminator:
        return sdo_id("sighting", "sighting", sensor, session_id, discriminator)
    return sdo_id("sighting", "sighting", sensor, session_id)


def generate_relationship_id(src_id: str, dst_id: str, rel_type: str) -> str:
    """Relationship SRO id. Seed: ``<src_id>:<dst_id>:<rel_type>``.

    Note: the seed uses the FULL STIX ids of source and target (which
    are themselves deterministic), so the relationship id is itself
    deterministic across runs.
    """
    return sdo_id("relationship", src_id, dst_id, rel_type)


# ---------------------------------------------------------------------------
# Infrastructure — the one that survived the UUID-drift bug.
# ---------------------------------------------------------------------------
def generate_infrastructure_id(name: str) -> str:
    """Infrastructure SDO id. Seed: ``infrastructure:<lowercased-name>``.

    Most callers should use :func:`generate_infrastructure_id_for_sensor`
    instead, which routes through :func:`sensor_infra_name` to guarantee
    every parser agrees on which string gets hashed. See
    LESSONS_LEARNED_FROM_V0.md §3.
    """
    return sdo_id("infrastructure", "infrastructure", name.lower())


def sensor_infra_name(sensor: dict) -> str:
    """Canonical sensor-name string for Infrastructure SDO UUID generation.

    EVERY caller that needs the sensor's Infrastructure UUID MUST go
    through this function. Direct hashing of ``sensor["name"]`` or
    ``sensor["alias"]`` is forbidden — it produces UUID drift across
    parsers and triggers the LOCK_ERROR cascade documented in
    ``docs/LESSONS_LEARNED_FROM_V0.md`` §3.

    Picks ``name`` first (the canonical identity per V1_SPEC), falls
    back to ``alias`` only if ``name`` is empty. Returns the empty
    string if both are missing — callers should check for this and
    decline to emit rather than emitting a bad UUID.
    """
    name = (sensor.get("name") or "").strip()
    if name:
        return name
    return (sensor.get("alias") or "").strip()


def generate_infrastructure_id_for_sensor(sensor: dict) -> str:
    """Convenience: ``sensor_infra_name`` + ``generate_infrastructure_id``.

    Returns the empty string if the sensor dict has neither ``name`` nor
    ``alias`` (callers MUST handle this case rather than emitting).
    """
    name = sensor_infra_name(sensor)
    if not name:
        return ""
    return generate_infrastructure_id(name)


# ---------------------------------------------------------------------------
# Marking definitions, malware, vulnerabilities.
# ---------------------------------------------------------------------------
# Standard TLP marking-definition ids — these are STIX 2.1 statics, NOT
# uuid5-derived. Same constants every project uses. Provided here so
# callers don't have to hard-code them and don't have to depend on stix2.
_TLP_MARKING_IDS: dict[str, str] = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "clear": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "amber+strict": "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def generate_marking_definition_id(tlp_level: str) -> str:
    """Return the STIX 2.1 marking-definition id for a TLP level.

    Accepts: ``white``, ``clear``, ``green``, ``amber``, ``amber+strict``,
    ``red`` (case-insensitive). These are STIX 2.1 standard statics and
    are NOT derived from ``NS_DNS``; they're the universal ids every
    STIX-aware tool recognizes.

    Raises:
        ValueError: if ``tlp_level`` is not a recognized TLP level.
    """
    key = tlp_level.strip().lower().removeprefix("tlp:").removeprefix("tlp-")
    if key not in _TLP_MARKING_IDS:
        raise ValueError(
            f"Unknown TLP level {tlp_level!r}; "
            f"expected one of {sorted(_TLP_MARKING_IDS)}"
        )
    return _TLP_MARKING_IDS[key]


def generate_malware_id(family_name: str) -> str:
    """Malware SDO id. Seed: ``malware:family:<lowercased-family-slug>``.

    ``family_name`` is normalized to lowercase and any internal
    whitespace is collapsed to single dashes to form the slug.
    """
    slug = "-".join(family_name.lower().split())
    return sdo_id("malware", "malware", "family", slug)


def generate_vulnerability_id(cve_id: str) -> str:
    """Vulnerability SDO id. Seed: ``vulnerability:<cve-id>``.

    ``cve_id`` is normalized to uppercase (``CVE-YYYY-NNNN`` form).
    """
    return sdo_id("vulnerability", "vulnerability", cve_id.upper())


# ---------------------------------------------------------------------------
# Smoke test.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Smoke test: verify deterministic generation.
    print("Smoke test — same input must produce same UUID:")
    print(f"  ipv4 1.2.3.4:       {generate_ipv4_id('1.2.3.4')}")
    print(f"  ipv4 1.2.3.4 again: {generate_ipv4_id('1.2.3.4')}")
    print(
        "  sensor n2:          "
        f"{generate_infrastructure_id_for_sensor({'name': 'node2', 'alias': 'node2-hp'})}"
    )
    print(
        "  sensor n2 (alias):  "
        f"{generate_infrastructure_id_for_sensor({'alias': 'node2-hp'})}  "
        "(different — alias-only sensor)"
    )
    # Confirm UUID5 stability.
    assert generate_ipv4_id("1.2.3.4") == generate_ipv4_id("1.2.3.4"), (
        "idempotency broken!"
    )
    # Confirm sensor_infra_name prefers name over alias (the LESSONS §3 fix).
    assert (
        generate_infrastructure_id_for_sensor({"name": "node2", "alias": "node2-hp"})
        == generate_infrastructure_id("node2")
    ), "sensor_infra_name() did not prefer name over alias!"
    # Confirm alias-only sensors still get an id (fallback path).
    assert generate_infrastructure_id_for_sensor({"alias": "node2-hp"}) != "", (
        "alias-only fallback broken!"
    )
    # Confirm empty sensor produces empty string (no bogus UUID).
    assert generate_infrastructure_id_for_sensor({}) == "", (
        "empty-sensor case should return empty string, not a UUID!"
    )
    print("OK")
