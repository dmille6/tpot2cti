"""Smoke test for the dicompot parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.dicompot as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_dicompot_smoke():
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = DicompotParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: C-ECHO ping from a scanner ─────────────────────────────
    echo_doc = {
        "@timestamp": now.isoformat(),
        "type": "Dicompot",
        "src_ip": "203.0.113.50",
        "src_port": 51234,
        "dst_port": 11112,
        "t-pot_hostname": "node1",
        "aet_called": "ANY-SCP",
        "aet_calling": "FINDSCU",
        "command_type": "c-echo",
        "geoip": {
            "country_iso_code": "CN",
            "country_name": "China",
            "asn": 4134,
            "organization": "ChinaNet",
        },
    }

    # ── Case 2: C-FIND query (substantive even if results empty) ───────
    find_doc = {
        "@timestamp": now.isoformat(),
        "type": "Dicompot",
        "src_ip": "198.51.100.20",
        "dst_port": 11112,
        "aet_called": "PACS",
        "aet_calling": "QRSCU",
        "command_type": "C-FIND",
    }

    # ── Case 3: minimal probe — just a connection, no AET ──────────────
    minimal_doc = {
        "@timestamp": now.isoformat(),
        "type": "Dicompot",
        "src_ip": "192.0.2.7",
    }

    docs = [echo_doc, find_doc, minimal_doc]
    events = [parser.parse(d) for d in docs]
    assert all(e is not None for e in events), "parse() returned None unexpectedly"
    print(f"parsed {len(events)} Dicompot events")
    for e in events:
        print(
            f"  src_ip={e.src_ip:<16} command_type={e.meta.get('command_type')!r:<10} "
            f"aet_called={e.meta.get('aet_called')!r}"
        )

    # Confirm command_type was upper-cased
    assert events[0].meta["command_type"] == "C-ECHO", (
        f"command_type should be uppercased; got {events[0].meta['command_type']!r}"
    )

    sessions = parser.correlate(events)
    assert len(sessions) == 3, f"expected 3 sessions, got {len(sessions)}"
    print(f"\ncorrelated into {len(sessions)} session(s)")

    for s in sessions:
        print(
            f"  session src_ip={s.src_ip:<16} "
            f"command_type={s.meta.get('command_type')!r:<10}"
        )

    # Session for echo_doc should carry aet/command on session.meta.
    s0 = sessions[0]
    assert s0.meta.get("command_type") == "C-ECHO"
    assert s0.meta.get("aet_called") == "ANY-SCP"
    assert s0.meta.get("aet_calling") == "FINDSCU"

    # Malformed docs return None
    assert parser.parse({}) is None
    assert parser.parse({"src_ip": "1.2.3.4"}) is None

    print("\nOK")
