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


# ── The window is the union of observations, not the first one ────────────
#
# A relationship id is (source, target, type) — deliberately, so the same fact
# seen twice is one edge. But start_time/stop_time describe an OBSERVATION and
# there are many observations per edge. Dropping the duplicate published the
# FIRST session's window as if it were the whole story.
#
# Found by codex reviewing this PR: an attacker hitting the same URL at 10:00
# and again at 14:00 got an edge claiming activity ended at 10:05. That is a
# bound nothing established — the same defect class this repo keeps hitting,
# introduced here by adding times to an id that was never per-observation.

def _win(builder, src, dst, first, last):
    from tpot2cti.parsers.base import AttackSession
    s = AttackSession(src_ip="203.0.113.1", session_id="x", sensor_hostname="s1",
                      event_type="Cowrie", first_seen=first, last_seen=last)
    return builder.build_relationship(src, "related-to", dst, session=s)


def test_a_repeated_edge_widens_its_window(builder):
    from datetime import datetime, timezone
    A = "ipv4-addr--00000000-0000-5000-8000-000000000001"
    B = "url--00000000-0000-5000-8000-000000000002"
    t = lambda h, m: datetime(2026, 8, 7, h, m, tzinfo=timezone.utc)

    kept = _win(builder, A, B, t(10, 0), t(10, 5))
    assert kept is not None, "guard: first observation must be emitted"
    later = _win(builder, A, B, t(14, 0), t(14, 2))
    assert later is None, "guard: the duplicate edge must not be emitted twice"

    assert kept["start_time"] == t(10, 0).isoformat(), "start should stay earliest"
    assert kept["stop_time"] == t(14, 2).isoformat(), (
        "the edge still claims activity stopped at the first observation — "
        "a bound nothing established"
    )


def test_an_earlier_observation_moves_the_start_back(builder):
    """Sessions do not arrive in time order; out-of-order must still widen."""
    from datetime import datetime, timezone
    A = "ipv4-addr--00000000-0000-5000-8000-000000000003"
    B = "url--00000000-0000-5000-8000-000000000004"
    t = lambda h: datetime(2026, 8, 7, h, 0, tzinfo=timezone.utc)

    kept = _win(builder, A, B, t(12), t(13))
    _win(builder, A, B, t(9), t(10))
    assert kept["start_time"] == t(9).isoformat(), "start did not move back"
    assert kept["stop_time"] == t(13).isoformat(), "stop should stay latest"


def test_widening_does_not_invent_a_window_where_there_was_none(builder):
    """An untimed edge must not acquire a window from a later duplicate.

    It could be argued either way, but silently attaching one session's times
    to an edge that was emitted without any is exactly the kind of unearned
    assertion this change is supposed to remove.
    """
    from datetime import datetime, timezone
    A = "ipv4-addr--00000000-0000-5000-8000-000000000005"
    B = "url--00000000-0000-5000-8000-000000000006"
    kept = builder.build_relationship(A, "related-to", B)   # no session
    assert "start_time" not in kept, "guard: this edge must start untimed"
    _win(builder, A, B, datetime(2026, 8, 7, 9, tzinfo=timezone.utc),
         datetime(2026, 8, 7, 10, tzinfo=timezone.utc))
    assert "start_time" not in kept


def test_the_salvage_graph_edges_are_timed(builder, cfg):
    """build_unattributed_payload_objects built a synthetic session for its
    timestamps and then never used it for the edges.

    The comment said the session carries first/last seen, which read as though
    the edges did too. They did not: every relationship there was emitted
    outside any session context and came out untimed. Found by codex.
    """
    from datetime import datetime, timezone
    from tpot2cti.parsers.base import ParsedEvent
    now = datetime(2026, 8, 7, 11, 0, tzinfo=timezone.utc)
    ev = ParsedEvent(src_ip="203.0.113.77", timestamp=now, sensor_hostname="s1",
                     event_type="Suricata", dst_port=443)
    ev.meta = {"jndi_payloads": [{"url": "ldap://evil.example/a",
                                  "host": "evil.example"}],
               "signature": "ET EXPLOIT log4j", "signature_id": 2010}
    before = builder.untimed_relationships
    objs = builder.build_unattributed_payload_objects([ev])
    rels = [o for o in objs if o.get("type") == "relationship"]
    assert rels, "guard: the salvage graph must emit edges at all"
    untimed = [r for r in rels if "start_time" not in r]
    assert not untimed, (
        f"{len(untimed)} of {len(rels)} salvage edges have no window despite "
        "a synthetic session carrying one"
    )
    assert builder.untimed_relationships == before, \
        "the untimed counter rose — some edge still escapes the context"


def test_an_inverted_window_publishes_no_stop_time(builder):
    """STIX 2.1 requires stop_time >= start_time and OpenCTI rejects the bundle.

    Correlators sort ascending so this should not arise, but
    build_relationship accepts ANY session from ANY caller, and a rejected
    bundle is an expensive way to discover a bad one. An inverted pair means
    we do not actually know the window, so publish the start and say nothing
    about the end rather than assert one that is wrong.
    """
    from datetime import datetime, timezone
    from tpot2cti.parsers.base import AttackSession
    s = AttackSession(
        src_ip="203.0.113.1", session_id="inv", sensor_hostname="s1",
        event_type="Cowrie",
        first_seen=datetime(2026, 8, 7, 14, tzinfo=timezone.utc),
        last_seen=datetime(2026, 8, 7, 10, tzinfo=timezone.utc),   # earlier!
    )
    rel = builder.build_relationship(
        "ipv4-addr--00000000-0000-5000-8000-00000000000a",
        "related-to",
        "url--00000000-0000-5000-8000-00000000000b",
        session=s,
    )
    assert rel["start_time"] == s.first_seen.isoformat(), "start should survive"
    assert "stop_time" not in rel, (
        "published stop_time < start_time — STIX-invalid, and OpenCTI rejects "
        "the whole bundle over it"
    )
