"""Smoke test for the honeytrap parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
has_substance/STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.honeytrap as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_honeytrap_smoke():
    import os
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = HoneytrapParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — empty payload ───────────────────────────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Honeytrap",
        "src_ip": "203.0.113.5",
        "src_port": 54321,
        "dst_port": 4444,
        "proto": "tcp",
        "t-pot_hostname": "node1",
        "payload_printable": "",
        "payload_hex": "",
        "geoip": {
            "country_iso_code": "RU",
            "country_name": "Russia",
            "asn": 12345,
            "organization": "ExampleNet",
        },
    }

    # ── Case 2: substantive — HTTP-ish payload on a random port ────────
    substantive_doc = {
        "@timestamp": now.isoformat(),
        "type": "Honeytrap",
        "src_ip": "198.51.100.42",
        "src_port": 33333,
        "dst_port": 8081,
        "proto": "tcp",
        "t-pot_hostname": "node1",
        "payload_printable": "GET / HTTP/1.0\r\nHost: example.com\r\n",
        "payload_hex": "474554202f20485454502f312e300d0a486f73743a206578616d706c652e636f6d0d0a",
        "geoip": {
            "country_iso_code": "CN",
            "country_name": "China",
            "city_name": "Shanghai",
            "asn": 4134,
            "organization": "ChinaNet",
        },
        "attack_connection": {"dst_port": 8081, "protocol": "tcp"},
    }

    # parse + correlate both
    drive_event = parser.parse(driveby_doc)
    subs_event = parser.parse(substantive_doc)
    assert drive_event and subs_event, "parse failed"

    drive_sessions = parser.correlate([drive_event])
    subs_sessions = parser.correlate([subs_event])
    assert len(drive_sessions) == 1 and len(subs_sessions) == 1

    drive_session = drive_sessions[0]
    subs_session = subs_sessions[0]

    drive_has = parser.has_substance(drive_session)
    subs_has = parser.has_substance(subs_session)
    print(f"drive-by has_substance:   {drive_has}  (expected False)")
    print(f"substantive has_substance: {subs_has}  (expected True)")
    assert drive_has is False
    assert subs_has is True

    # Need a Config to build STIX. Per refactor, the orchestrator dispatches
    # substantive Honeytrap sessions to builder.build_honeytrap_probe(s).
    from tpot2cti.parsers.base import _smoketest_env
    _smoketest_env()
    from tpot2cti.config import load_config
    from tpot2cti.stix.builder import STIXBuilder

    cfg = load_config()

    # Drive-by: orchestrator would call builder.build_driveby_session()
    builder1 = STIXBuilder(cfg)
    drive_objs = builder1.build_driveby_session(drive_session)
    drive_counts: dict[str, int] = {}
    for o in drive_objs:
        drive_counts[o["type"]] = drive_counts.get(o["type"], 0) + 1
    print(f"\ndrive-by STIX objects ({len(drive_objs)}):")
    for t, n in sorted(drive_counts.items(), key=lambda x: -x[1]):
        print(f"  {t:25s} {n}")

    # Substantive: orchestrator would call builder.build_honeytrap_probe()
    builder2 = STIXBuilder(cfg)
    subs_objs = builder2.build_honeytrap_probe(subs_session)
    subs_counts: dict[str, int] = {}
    for o in subs_objs:
        subs_counts[o["type"]] = subs_counts.get(o["type"], 0) + 1
    print(f"\nsubstantive STIX objects ({len(subs_objs)}):")
    for t, n in sorted(subs_counts.items(), key=lambda x: -x[1]):
        print(f"  {t:25s} {n}")

    # Per LESSONS §7.1 (post-refactor): Honeytrap no longer emits
    # a per-probe Note. The per-probe summary now lives on the Sighting's
    # `description` field. Verify both ends of the contract.
    assert not any(o["type"] == "note" for o in subs_objs), (
        "Honeytrap should NOT emit Notes anymore — summary goes in "
        "Sighting.description per LESSONS §7.1"
    )
    sightings = [o for o in subs_objs if o["type"] == "sighting"]
    assert sightings, "substantive bundle missing Sighting"
    sdesc = sightings[0].get("description") or ""
    assert sdesc, "Sighting must carry a per-burst description string"
    # New (full-squeeze) format: burst-level scan summary with the port
    # surfaced and an HTTP fingerprint for this payload.
    assert "Honeytrap" in sdesc, f"unexpected sighting description: {sdesc!r}"
    assert "tcp/8081" in sdesc, f"port not surfaced in sighting: {sdesc!r}"
    assert "HTTP" in sdesc, f"HTTP fingerprint missing: {sdesc!r}"
    # Drive-by bundle still has no Note (unchanged from before)
    assert not any(o["type"] == "note" for o in drive_objs), \
        "drive-by bundle should have no Note"

    # ── Case 3: vertical port scan — the headline behavior ─────────────
    # One IP sweeping the cPanel/WHM port range in a burst must collapse to
    # ONE session whose indicator advertises the scan shape + target family.
    cpanel_ports = [2082, 2083, 2086, 2087, 2095, 2096]
    scan_events = []
    for i, p in enumerate(cpanel_ports):
        ev = parser.parse({
            "@timestamp": now.isoformat(),
            "type": "Honeytrap",
            "src_ip": "203.0.113.99",
            "src_port": 40000 + i,
            "dest_port": p,
            "proto": "tcp",
            "t-pot_hostname": "node1",
            "attack_connection": {"payload": {"data_hex": "", "length": 0}, "protocol": "tcp"},
        })
        assert ev is not None
        scan_events.append(ev)

    scan_sessions = parser.correlate(scan_events)
    assert len(scan_sessions) == 1, \
        f"burst should collapse to 1 session, got {len(scan_sessions)}"
    scan_session = scan_sessions[0]
    assert scan_session.dst_ports == set(cpanel_ports)
    # Empty payloads but a real sweep → substantive via the port threshold.
    assert parser.has_substance(scan_session) is True

    builder3 = STIXBuilder(cfg)
    scan_objs = builder3.build_honeytrap_probe(scan_session)
    inds = [o for o in scan_objs if o["type"] == "indicator"]
    assert inds, "scan bundle missing indicator"
    ind = inds[0]
    assert "scan:vertical" in ind["labels"], ind["labels"]
    assert "target:cpanel" in ind["labels"], ind["labels"]
    assert "Honeytrap scan" in ind["name"] and "6 ports" in ind["name"], ind["name"]
    assert "cPanel" in (ind.get("description") or ""), ind.get("description")
    # One indicator for the whole sweep, not six.
    assert len(inds) == 1, f"expected 1 indicator for the burst, got {len(inds)}"
    print(f"\nvertical-scan indicator: {ind['name']!r} labels={ind['labels']}")

    print("\nSmoke test passed.")
