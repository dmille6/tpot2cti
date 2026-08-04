"""Smoke test for the fatt parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.fatt as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_fatt_smoke():
    from datetime import datetime, timedelta, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = FattParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — all fingerprint fields empty ───────────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Fatt",
        "src_ip": "203.0.113.30",
        "src_port": 55555,
        "dst_port": 443,
        "t-pot_hostname": "node1",
        "fatt": {},
        "geoip": {"country_iso_code": "US", "asn": 64500},
    }

    # ── Case 2: substantive — three FATT events for the same attacker,
    #    bursting within the 300s window.  First two carry JA3+JA3S
    #    (TLS handshake), third carries HASSH (SSH handshake on another
    #    port from the same attacker).  Verify FIRST non-empty wins.
    base = {
        "type": "Fatt",
        "src_ip": "198.51.100.50",
        "src_port": 41111,
        "t-pot_hostname": "node1",
        "geoip": {"country_iso_code": "CN", "asn": 4134},
    }
    docs = [
        {**base,
         "@timestamp": now.isoformat(),
         "dst_port": 443,
         "fatt": {
             "ja3": "771,4865-4866-4867,0-23-65281",
             "ja3s": "771,4865",
             "tlsClient": "Chrome/120",
         }},
        {**base,
         "@timestamp": (now + timedelta(seconds=30)).isoformat(),
         "dst_port": 443,
         # Different ja3 — but the aggregator MUST keep the first.
         "fatt": {
             "ja3": "771,SHOULD-NOT-OVERRIDE",
             "ja3s": "771,SHOULD-NOT-OVERRIDE",
         }},
        {**base,
         "@timestamp": (now + timedelta(seconds=60)).isoformat(),
         "dst_port": 22,
         "fatt": {
             "hassh": "0a1b2c3d4e5f6789abcdef",
             "hasshServer": "deadbeefcafef00d",
         }},
    ]

    # parse all
    drive_ev = parser.parse(driveby_doc)
    burst_evs = [parser.parse(d) for d in docs]
    assert drive_ev is not None
    assert all(e is not None for e in burst_evs)

    # correlate
    drive_sessions = parser.correlate([drive_ev])
    burst_sessions = parser.correlate(burst_evs)
    assert len(drive_sessions) == 1, f"got {len(drive_sessions)}"
    assert len(burst_sessions) == 1, (
        f"FATT burst should fold into 1 session, got {len(burst_sessions)}"
    )

    burst_s = burst_sessions[0]

    # FIRST non-empty wins for each fp field
    assert burst_s.ja3 == "771,4865-4866-4867,0-23-65281", (
        f"ja3 first-wins broken: got {burst_s.ja3!r}"
    )
    assert burst_s.ja3s == "771,4865", f"ja3s first-wins broken: got {burst_s.ja3s!r}"
    assert burst_s.hassh == "0a1b2c3d4e5f6789abcdef"
    assert burst_s.meta.get("hasshServer") == "deadbeefcafef00d"
    assert burst_s.meta.get("tlsClient") == "Chrome/120"

    print("OK")
