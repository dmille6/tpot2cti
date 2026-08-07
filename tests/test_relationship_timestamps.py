"""A relationship with no time is not evidence of a sequence.

Measured on the live corpus 2026-08-06, BEFORE this existed: 100% of emitted
relationships carried the epoch sentinel 1970-01-01 —

    related-to  59,644 / 59,644
    based-on    34,563 / 34,563
    indicates   31,425 / 31,425

The highest-degree attacker's 3,014 edges had a `start_time` cardinality of
ONE. "What did attacker X do, in order" was unanswerable by construction, and
OpenCTI's decay model had nothing real to decay against.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tpot2cti.parsers.base import AttackSession

FIRST = datetime(2026, 8, 6, 10, 0, tzinfo=timezone.utc)
LAST = FIRST + timedelta(minutes=7)


def _session():
    return AttackSession(src_ip="203.0.113.5", session_id="s1",
                         sensor_hostname="sensor01", event_type="Cowrie",
                         first_seen=FIRST, last_seen=LAST)


def test_an_explicit_session_times_the_edge(builder):
    r = builder.build_relationship("ipv4-addr--a", "related-to", "url--b",
                                   session=_session())
    assert r["start_time"] == FIRST.isoformat()
    assert r["stop_time"] == LAST.isoformat()


def test_the_session_context_times_every_edge_inside_it(builder):
    """The choke point. One `with` in the orchestrator must time every SRO a
    builder emits, without threading an argument through ~40 call sites."""
    with builder.session_context(_session()):
        a = builder.build_relationship("ipv4-addr--a", "related-to", "url--x")
        b = builder.build_relationship("ipv4-addr--a", "indicates", "ap--y")
    for r in (a, b):
        assert r["start_time"] == FIRST.isoformat(), "edge left untimed"
    assert builder.untimed_relationships == 0


def test_an_explicit_session_beats_the_context(builder):
    other = _session()
    other.first_seen = FIRST - timedelta(days=1)
    other.last_seen = FIRST - timedelta(days=1)
    with builder.session_context(_session()):
        r = builder.build_relationship("a--1", "related-to", "b--2",
                                       session=other)
    assert r["start_time"] == other.first_seen.isoformat()


def test_the_context_is_restored_afterwards(builder):
    """Nested/sequential sessions must not leak into each other — a stale
    context would stamp one attacker's edges with another's window."""
    with builder.session_context(_session()):
        pass
    r = builder.build_relationship("a--3", "related-to", "b--4")
    assert "start_time" not in r
    assert builder.untimed_relationships == 1


def test_an_untimed_edge_is_counted_not_silent(builder):
    """A rising count means a producer emits edges outside any session and the
    graph is quietly losing its time dimension again."""
    builder.build_relationship("a--5", "related-to", "b--6")
    builder.build_relationship("a--7", "related-to", "b--8")
    assert builder.untimed_relationships == 2


def test_the_counter_reaches_the_cycle_summary():
    import inspect
    from tpot2cti import main
    src = inspect.getsource(main.run_cycle)
    assert "untimed_relationships" in src, (
        "untimed relationships are not reported — the regression would be "
        "invisible"
    )
    assert "builder.session_context(session)" in src, (
        "the dispatch is no longer wrapped in a session context; every edge "
        "reverts to the 1970 epoch sentinel"
    )
