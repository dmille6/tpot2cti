"""Smoke test for the conpot parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
has_substance/STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.conpot as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_conpot_smoke():
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = ConPotParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: Modbus probe (substantive — every ICS probe is) ────────
    modbus_doc = {
        "@timestamp": now.isoformat(),
        "type": "ConPot",
        "src_ip": "203.0.113.7",
        "src_port": 51111,
        "dst_port": 502,
        "protocol": "modbus",
        "t-pot_hostname": "node1",
        "request": {
            "function_code": 3,
            "start_address": 0,
            "quantity": 10,
        },
        "geoip": {
            "country_iso_code": "RU",
            "country_name": "Russia",
            "asn": 12389,
            "organization": "Rostelecom",
        },
    }

    # ── Case 2: S7Comm probe with empty request (still substantive!) ───
    s7_doc = {
        "@timestamp": now.isoformat(),
        "type": "ConPot",
        "src_ip": "198.51.100.11",
        "src_port": 41010,
        "dst_port": 102,
        "protocol": "s7comm",
        "t-pot_hostname": "node1",
        "request": "",
    }

    # ── Case 3: IPMI probe with raw payload string ─────────────────────
    ipmi_doc = {
        "@timestamp": now.isoformat(),
        "type": "ConPot",
        "src_ip": "192.0.2.99",
        "dst_port": 623,
        "protocol": "ipmi",
        "request": "06 00 ff 07 00 00 00 00 00 00 00 00 09 20 18 c8 81 00 38 8e",
    }

    docs = [modbus_doc, s7_doc, ipmi_doc]
    events = [parser.parse(d) for d in docs]
    assert all(e is not None for e in events), "parse() returned None unexpectedly"
    print(f"parsed {len(events)} ConPot events")
    for e in events:
        print(
            f"  src_ip={e.src_ip:<16} protocol={e.protocol:<8} "
            f"request={e.meta.get('request')!r:.80s}"
        )

    sessions = parser.correlate(events)
    assert len(sessions) == 3, f"expected 3 sessions, got {len(sessions)}"
    print(f"\ncorrelated into {len(sessions)} session(s)")

    for s in sessions:
        sub = parser.has_substance(s)
        print(
            f"  session src_ip={s.src_ip:<16} "
            f"protocol={s.meta.get('protocol'):<8} "
            f"event_count={s.event_count} "
            f"has_substance={sub}"
        )
        # Every ConPot session is substantive per V1_SPEC §5.6.
        assert sub is True, f"ConPot session {s.src_ip} not substantive!"
        assert s.dst_ports, "session.dst_ports should be populated"
        assert s.protocols, "session.protocols should be populated"

    # The Modbus and IPMI sessions both carry a non-empty request blob;
    # the S7Comm session carried an empty string so should have no
    # command pushed onto session.commands.
    assert len(sessions[0].commands) == 1, "modbus session.commands missing request"
    assert len(sessions[1].commands) == 0, "s7 session.commands should be empty"
    assert len(sessions[2].commands) == 1, "ipmi session.commands missing request"

    # Malformed docs
    assert parser.parse({}) is None, "empty doc should yield None"
    assert parser.parse({"src_ip": "1.2.3.4"}) is None, "missing ts should yield None"

    print("\nOK")
