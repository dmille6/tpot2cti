"""Parameterized sweep across every registered parser.

Each parser is exercised end-to-end on a minimal synthetic doc:
  1. parse() returns a ParsedEvent with the right shape
  2. correlate() returns at least one AttackSession
  3. has_substance() returns a bool (drive-by suppression discipline)
  4. The matching builder method emits at least one valid STIX object

This is the sweep that would have caught the dst_port/dest_port regression
(commit decc6df) had it existed — every parser is exercised in the same
test path with the canonical T-Pot field shape.
"""

from __future__ import annotations

import pytest

from tpot2cti.parsers.base import AttackSession, ParsedEvent


# ---------------------------------------------------------------------------
# parse()
# ---------------------------------------------------------------------------

def _all_parser_types():
    # Lazy import so conftest's _smoketest_env() has fired first.
    import tpot2cti.parsers as P
    return P.registered_types() + ["__fallback__"]


@pytest.mark.parametrize("type_name", _all_parser_types())
def test_parse_returns_event(type_name, parser_docs, parser_registry):
    """parse() on a minimal valid doc returns a ParsedEvent with src_ip."""
    parser = parser_registry[type_name]
    event = parser.parse(parser_docs[type_name])
    assert isinstance(event, ParsedEvent)
    assert event.src_ip == "203.0.113.42"
    assert event.timestamp is not None
    assert event.sensor_hostname == "node1"


@pytest.mark.parametrize("type_name", _all_parser_types())
def test_parse_reads_dest_port(type_name, parser_docs, parser_registry):
    """Every parser MUST read dst_port from T-Pot's canonical ``dest_port``.

    Regression guard for commit decc6df (10 parsers read ``dst_port`` while
    T-Pot ships ``dest_port``).  If a parser doesn't surface dst_port from
    a dest_port doc, it falls through here.
    """
    parser = parser_registry[type_name]
    event = parser.parse(parser_docs[type_name])
    # Fallback parser intentionally does not set dst_port from this doc
    # shape (it routes via meta).  Skip it; every dedicated parser MUST.
    if type_name == "__fallback__":
        return
    assert event.dst_port == 22, (
        f"{type_name}: expected dst_port=22 from dest_port=22; "
        f"got {event.dst_port}.  Has the parser drifted back to "
        f"reading dst_port only?"
    )


@pytest.mark.parametrize("type_name", _all_parser_types())
def test_parse_missing_src_ip_returns_none_or_empty(type_name, parser_docs, parser_registry):
    """A doc with no src_ip either returns None or yields empty src_ip.

    Each parser is allowed to choose: Suricata/Cowrie return None (they
    can't sight without a source IP); Fallback emits an event with
    src_ip="" so the ``no-src-ip`` Note path still fires.
    """
    parser = parser_registry[type_name]
    doc = dict(parser_docs[type_name])
    doc.pop("src_ip", None)
    event = parser.parse(doc)
    if event is not None:
        assert event.src_ip == "" or event.src_ip is None


# ---------------------------------------------------------------------------
# correlate() + has_substance()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("type_name", _all_parser_types())
def test_correlate_returns_sessions(type_name, parser_docs, parser_registry):
    """correlate() on a single event returns a non-empty list of AttackSession."""
    parser = parser_registry[type_name]
    event = parser.parse(parser_docs[type_name])
    sessions = parser.correlate([event])
    assert sessions and all(isinstance(s, AttackSession) for s in sessions)


@pytest.mark.parametrize("type_name", _all_parser_types())
def test_has_substance_returns_bool(type_name, parser_docs, parser_registry):
    """has_substance() must return a bool — not None, not a truthy non-bool."""
    parser = parser_registry[type_name]
    event = parser.parse(parser_docs[type_name])
    s = parser.correlate([event])[0]
    assert isinstance(parser.has_substance(s), bool)


# ---------------------------------------------------------------------------
# build path — at least one valid STIX object emitted
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("type_name", _all_parser_types())
def test_build_path_emits_stix(type_name, parser_docs, parser_registry, builder):
    """Driveby OR full-graph build emits at least one STIX object with a
    valid ``<type>--<uuid>`` id.

    Dispatch mirrors tpot2cti.main._PARSER_DISPATCH; replicated inline
    to keep this test free of the elasticsearch import chain.
    """
    _dispatch = {
        "Cowrie":       "build_cowrie_session",
        "Suricata":     "build_suricata_alert",
        "Honeytrap":    "build_honeytrap_probe",
        "__fallback__": "build_fallback_event",
    }
    parser = parser_registry[type_name]
    event = parser.parse(parser_docs[type_name])
    s = parser.correlate([event])[0]
    method_name = _dispatch.get(type_name)
    if method_name:
        objs = getattr(builder, method_name)(s)
    else:
        objs = builder.build_driveby_session(s)
    assert objs, f"{type_name}: build path emitted zero objects"
    for o in objs:
        assert "id" in o and "--" in o["id"], f"{type_name}: invalid id {o.get('id')!r}"
        assert "type" in o
