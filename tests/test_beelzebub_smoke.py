"""Smoke test for the beelzebub parser (migrated from its old
`if __name__` block so CI runs it). Generic parse/correlate/
has_substance/STIX contract is covered in test_parsers.py."""
from __future__ import annotations

import tpot2cti.parsers.beelzebub as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_beelzebub_smoke():
    from datetime import datetime, timedelta, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = BeelzebubParser()
    now = datetime.now(timezone.utc)

    base = {
        "type": "Beelzebub",
        "t-pot_hostname": "node2",
        "src_ip": "165.154.6.130",
        "src_port": "53118",
        "dest_port": "22",
        "protocol": "SSH",
        "service": "LouisianaTech dev01 - SSH interactive (hybrid cache + LLM)",
        "client": "SSH-2.0-libssh_0.9.6",
        "geoip": {
            "country_iso_code": "RU",
            "country_name": "Russia",
            "asn": 12345,
            "organization": "ExampleNet",
        },
    }

    # ── Case A: single Stateless auth attempt — substantive via cred ─
    auth_only_doc = {
        **base,
        "@timestamp": now.isoformat(),
        "session": "auth-1",
        "message": "New SSH attempt",
        "msg": "New SSH attempt",
        "username": "root",
        "password": "root",
        "status": "Stateless",
    }
    ev = parser.parse(auth_only_doc)
    assert ev is not None and ev.session_id == "auth-1"
    sessions = parser.correlate([ev])
    assert len(sessions) == 1
    s0 = sessions[0]
    assert parser.has_substance(s0) is True, (
        "captured credential is always substantive (matches Heralding)"
    )
    assert ("root", "root") in s0.credentials_tried
    print(f"single-auth: creds={len(s0.credentials_tried)} commands={len(s0.commands)} substance=True")

    # ── Case A': blank-username probe → empty meta, no cred → drive-by
    blank_doc = {
        **base,
        "@timestamp": now.isoformat(),
        "session": "blank-1",
        "message": "New SSH attempt",
        # NO username/password keys at all — pure connection probe
        "status": "Stateless",
    }
    blank_ev = parser.parse(blank_doc)
    assert blank_ev is not None
    blank_sessions = parser.correlate([blank_ev])
    assert parser.has_substance(blank_sessions[0]) is False, (
        "pure connect with no auth fields is drive-by"
    )
    print(f"blank-probe: creds={len(blank_sessions[0].credentials_tried)} commands=0 substance=False")

    # ── Case B: Outlaw-style command chain post-auth ──────────────────
    cmd_docs = []
    # Auth
    cmd_docs.append({
        **base,
        "@timestamp": now.isoformat(),
        "session": "outlaw-1",
        "message": "New SSH attempt",
        "username": "fox",
        "password": "123456",
        "status": "Stateless",
    })
    # Three command-execution events
    for i, cmd in enumerate([
        "cd ~; chattr -ia .ssh; lockr -ia .ssh",
        "uname -a",
        "echo 'ssh-rsa AAAAB3...attacker_key' >> ~/.ssh/authorized_keys",
    ]):
        cmd_docs.append({
            **base,
            "@timestamp": (now + timedelta(seconds=1 + i)).isoformat(),
            "session": "outlaw-1",
            "message": "New SSH Inline Session",
            "username": "fox",
            "input": cmd,
            "output": "bash: lockr: command not found\n" if i == 0 else "",
            "status": "Start",
        })

    cmd_events = [parser.parse(d) for d in cmd_docs]
    cmd_events = [e for e in cmd_events if e is not None]
    assert len(cmd_events) == 4
    cmd_sessions = parser.correlate(cmd_events)
    assert len(cmd_sessions) == 1
    cs = cmd_sessions[0]
    assert parser.has_substance(cs) is True
    assert len(cs.commands) == 3
    assert ("fox", "123456") in cs.credentials_tried
    assert cs.ssh_version == "SSH-2.0-libssh_0.9.6"
    assert 22 in cs.dst_ports
    assert "ssh" in cs.protocols
    print(f"outlaw:      creds={len(cs.credentials_tried)} commands={len(cs.commands)} ssh_client={cs.ssh_version} substance=True")
    print(f"             commands: {cs.commands}")

    # ── Case C: credential spray (4 attempts, 0 commands) ─────────────
    spray_docs = []
    for i, (u, p) in enumerate([
        ("root", "root"), ("admin", "admin"),
        ("oracle", "oracle"), ("postgres", "postgres"),
    ]):
        spray_docs.append({
            **base,
            "@timestamp": (now + timedelta(seconds=i)).isoformat(),
            "session": f"spray-{i}",  # different sessions per attempt
            "message": "New SSH attempt",
            "username": u,
            "password": p,
            "status": "Stateless",
        })
    spray_events = [parser.parse(d) for d in spray_docs]
    spray_events = [e for e in spray_events if e is not None]
    spray_sessions = parser.correlate(spray_events)
    # Different session IDs → 4 sessions; each has 1 event + 1 cred,
    # so each is substantive on the credentials_tried branch.
    assert len(spray_sessions) == 4
    assert all(parser.has_substance(s) for s in spray_sessions)
    print(f"spray:       sessions={len(spray_sessions)} all_substantive=True")

    print("OK")
