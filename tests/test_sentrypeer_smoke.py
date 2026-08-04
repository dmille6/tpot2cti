"""Smoke test for the sentrypeer parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.sentrypeer as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_sentrypeer_smoke():
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = SentryPeerParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: REGISTER probe (no dialed number) ──────────────────────
    register_doc = {
        "@timestamp": now.isoformat(),
        "type": "Sentrypeer",
        "src_ip": "203.0.113.77",
        "src_port": 50050,
        "dst_port": 5060,
        "sip_method": "REGISTER",
        "caller": "1001",
        "t-pot_hostname": "node1",
        "geoip": {
            "country_iso_code": "NL",
            "country_name": "Netherlands",
            "asn": 16276,
            "organization": "OVH",
        },
    }

    # ── Case 2: INVITE to international number (toll-fraud signal) ─────
    invite_intl_doc = {
        "@timestamp": now.isoformat(),
        "type": "Sentrypeer",
        "src_ip": "198.51.100.31",
        "dst_port": 5060,
        "sip_method": "INVITE",
        "called_number": "+447700900123",
        "caller": "9999",
    }

    # ── Case 3: INVITE to domestic number (no intl flag) ───────────────
    invite_local_doc = {
        "@timestamp": now.isoformat(),
        "type": "Sentrypeer",
        "src_ip": "198.51.100.31",
        "dst_port": 5060,
        "sip_method": "INVITE",
        "called_number": "5551234",
    }

    # ── Case 4: bare doc (no method, no number) — still substantive ────
    bare_doc = {
        "@timestamp": now.isoformat(),
        "type": "Sentrypeer",
        "src_ip": "192.0.2.42",
    }

    docs = [register_doc, invite_intl_doc, invite_local_doc, bare_doc]
    events = [parser.parse(d) for d in docs]
    assert all(e is not None for e in events), "parse() returned None unexpectedly"
    print(f"parsed {len(events)} SentryPeer events")
    for e in events:
        print(
            f"  src_ip={e.src_ip:<16} dst_port={e.dst_port} "
            f"method={e.meta.get('sip_method')!r:<10} "
            f"called={e.meta.get('called_number')!r:<18} "
            f"intl={e.meta.get('is_intl_dial')}"
        )

    sessions = parser.correlate(events)
    assert len(sessions) == 4, f"expected 4 sessions, got {len(sessions)}"
    print(f"\ncorrelated into {len(sessions)} session(s)")

    for s in sessions:
        print(
            f"  session src_ip={s.src_ip:<16} "
            f"method={s.meta.get('sip_method')!r:<10}"
        )

    # ── Per-session assertions ─────────────────────────────────────────
    # REGISTER: method present, no called_number, no intl flag
    assert sessions[0].meta.get("sip_method") == "REGISTER"
    assert "called_number" not in sessions[0].meta
    assert sessions[0].meta.get("caller") == "1001"

    # INVITE intl: intl flag set
    assert sessions[1].meta.get("sip_method") == "INVITE"
    assert sessions[1].meta.get("called_number") == "+447700900123"
    assert sessions[1].meta.get("is_intl_dial") is True

    # INVITE local: no intl flag
    assert sessions[2].meta.get("sip_method") == "INVITE"
    assert sessions[2].meta.get("called_number") == "5551234"
    assert "is_intl_dial" not in sessions[2].meta

    # bare doc: no SIP keys on session.meta
    assert "sip_method" not in sessions[3].meta
    assert "called_number" not in sessions[3].meta

    # Method case-normalization
    lowercase_doc = {
        "@timestamp": now.isoformat(),
        "type": "Sentrypeer",
        "src_ip": "192.0.2.99",
        "sip_method": "invite",
    }
    ev_lc = parser.parse(lowercase_doc)
    assert ev_lc is not None
    assert ev_lc.meta.get("sip_method") == "INVITE", \
        f"sip_method not upper-cased: {ev_lc.meta.get('sip_method')!r}"

    # 00-prefix is also treated as international
    intl_00_doc = {
        "@timestamp": now.isoformat(),
        "type": "Sentrypeer",
        "src_ip": "192.0.2.100",
        "sip_method": "INVITE",
        "called_number": "00441234567",
    }
    ev_00 = parser.parse(intl_00_doc)
    assert ev_00 is not None
    assert ev_00.meta.get("is_intl_dial") is True, \
        "00-prefix should be detected as international"

    # Malformed docs return None
    assert parser.parse({}) is None
    assert parser.parse({"src_ip": "1.2.3.4"}) is None  # no @timestamp

    print("\nOK")
