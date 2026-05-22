"""Defensive-read helpers from parsers/base.py.

Per audit #10-11: T-Pot's logstash pipelines have shipped some fields
under multiple names across versions (dest_port vs dst_port, etc.).
The pick/pick_int/pick_str helpers MUST honour the dual-spelling rule
without losing the canonical-first ordering or zero-vs-absent
distinction.
"""

from __future__ import annotations

from tpot2cti.parsers.base import BaseParser


def test_pick_returns_first_present():
    """pick walks fields in order; first non-None wins."""
    doc = {"dest_port": 22, "dst_port": 9999}
    assert BaseParser.pick(doc, "dest_port", "dst_port") == 22


def test_pick_falls_through_to_legacy_spelling():
    """When canonical is absent the legacy name is honoured."""
    doc = {"dst_port": 22}
    assert BaseParser.pick(doc, "dest_port", "dst_port") == 22


def test_pick_returns_default_when_none_present():
    """Default propagates when no field matches."""
    assert BaseParser.pick({}, "a", "b", default="fallback") == "fallback"


def test_pick_preserves_zero():
    """``0`` is a real value (ICMP probes have dst_port=0) — keep it."""
    doc = {"dest_port": 0}
    assert BaseParser.pick(doc, "dest_port", "dst_port") == 0


def test_pick_preserves_empty_string():
    """Empty string is a real value too — pick uses ``is not None``."""
    doc = {"dest_ip": ""}
    assert BaseParser.pick(doc, "dest_ip", "dst_ip", default="?") == ""


def test_pick_int_coerces():
    """pick_int parses string ints from ES (logstash sometimes ships strings)."""
    assert BaseParser.pick_int({"dest_port": "22"}, "dest_port", "dst_port") == 22


def test_pick_int_returns_default_on_garbage():
    """A non-int string yields the default, not a TypeError."""
    assert BaseParser.pick_int({"dest_port": "deadbeef"}, "dest_port", default=-1) == -1


def test_pick_int_returns_default_on_missing():
    """Absent fields fall through to default."""
    assert BaseParser.pick_int({}, "dest_port", default=42) == 42


def test_pick_str_coerces():
    """pick_str returns the str() of whatever it finds."""
    assert BaseParser.pick_str({"dest_ip": 4242}, "dest_ip") == "4242"


def test_pick_str_returns_default_on_missing():
    """pick_str default propagates."""
    assert BaseParser.pick_str({}, "x", default="?") == "?"


def test_dual_spelled_dest_port_dst_port_canonical_first():
    """Conflicting canonical+legacy fields: canonical wins.

    Guards the audit #10-11 rule "always pass the CANONICAL T-Pot spelling
    first; the helper falls through to legacy names in order".
    """
    doc = {"dest_port": 22, "dst_port": 80}
    assert BaseParser.pick_int(doc, "dest_port", "dst_port") == 22
