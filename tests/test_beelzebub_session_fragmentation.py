"""Beelzebub's `session` field does not identify a session.

Its "SSH Inline" mode mints a fresh UUID for every command. Measured on the
live hive, one day: 124,198 docs / 65,523 distinct sessions / 187 source IPs
= 1.90 docs per "session", 350 "sessions" per IP. Cowrie, which emits real
session ids, averages 11.2 commands per session.

Correlating on that field shattered 3,743,838 command events over 35 days
into ~4M one-command fragments — and Beelzebub carries 55x more command
volume than Cowrie (3,743,838 vs 68,362).
"""
from __future__ import annotations

import uuid

from tpot2cti.parsers.beelzebub import BeelzebubParser
from tpot2cti.stix.builder import _signal_score

_CMDS = ["uname -a", "nproc", "nvidia-smi -q | grep 'Product Name'",
         "curl ipinfo.io/org", "cat /etc/shadow"]


def _doc(cmd, i, ip="203.0.113.77"):
    """One command, one fresh session UUID — Beelzebub's real shape."""
    return {
        "type": "Beelzebub", "t-pot_hostname": "sensor01", "src_ip": ip,
        "dest_port": 22, "@timestamp": f"2026-08-05T10:00:{10 + i:02d}.000Z",
        "input": cmd, "output": "ok",
        "session": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{ip}-{i}")),
        "id": f"b{i}",
    }


def _sessions(docs):
    p = BeelzebubParser()
    return p.correlate([e for e in (p.parse(d) for d in docs) if e])


def test_one_burst_is_one_session_not_five():
    """The regression lock. Five commands seconds apart from one IP are one
    attacker doing one thing, not five unrelated events."""
    sessions = _sessions([_doc(c, i) for i, c in enumerate(_CMDS)])
    assert len(sessions) == 1, (
        f"{len(sessions)} sessions from one burst — Beelzebub is still being "
        f"correlated on its per-command session UUID"
    )
    assert sessions[0].commands == _CMDS, "command order or content was lost"


def test_command_order_survives():
    """Order is the intelligence — recon, then capability check, then
    credential theft is a different story than the reverse."""
    s = _sessions([_doc(c, i) for i, c in enumerate(_CMDS)])[0]
    assert s.commands.index("uname -a") < s.commands.index("cat /etc/shadow")


def test_a_multi_command_burst_scores_as_substance():
    """A 1-command fragment and a 5-command transcript must not score the
    same. Fragmentation flattened every Beelzebub session to the former."""
    s = _sessions([_doc(c, i) for i, c in enumerate(_CMDS)])[0]
    assert len(s.commands) == 5
    assert _signal_score(s) > 50


def test_different_ips_stay_separate():
    """The positive control — window correlation must not merge attackers."""
    docs = [_doc(c, i, ip="203.0.113.77") for i, c in enumerate(_CMDS[:3])]
    docs += [_doc(c, i + 10, ip="198.51.100.9") for i, c in enumerate(_CMDS[:2])]
    sessions = _sessions(docs)
    assert len(sessions) == 2, "two attackers were merged into one session"
    assert {len(s.commands) for s in sessions} == {2, 3}


def test_bursts_far_apart_stay_separate():
    """Same IP, hours apart, is two visits — the window must still bound."""
    docs = [_doc("uname -a", 0)]
    late = _doc("cat /etc/shadow", 1)
    late["@timestamp"] = "2026-08-05T18:00:00.000Z"   # 8h later
    docs.append(late)
    assert len(_sessions(docs)) == 2


def test_the_session_id_is_still_available_on_events():
    """We stop correlating on it; we do not throw it away."""
    s = _sessions([_doc(c, i) for i, c in enumerate(_CMDS)])[0]
    assert len({e.session_id for e in s.events}) == 5, (
        "the raw per-command session ids were discarded"
    )
