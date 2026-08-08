"""`BaseParser._parse_timestamp` returns an AWARE UTC datetime, or None.

The docstring said so for a long time before the code did.  `fromisoformat`
hands back whatever the input carried: a tz-less string parses NAIVE, and a
string with `+02:00` keeps `+02:00`.  Both leaked out through every
`ParsedEvent.timestamp`, hence every `AttackSession.first_seen`/`last_seen`,
hence relationship `start_time`/`stop_time` and indicator
`valid_from`/`valid_until` in the published graph.

Two distinct failures, so two distinct kinds of test here:

  * NAIVE vs AWARE — Python raises TypeError on `naive < aware`.  Any sort
    or subtraction over a mixed batch crashes.  `correlator` does both.
  * A SURVIVING OFFSET — chronological order and lexicographic order of the
    ISO strings disagree, and a lot of downstream comparison is on the
    string (`state.py`'s first_seen/last_seen merge and its
    `last_seen >= ? AND first_seen <= ?` window query, `campaigns.py`'s
    min()/max() over rows).

Fixtures below are deliberately built so string order DISAGREES with
chronological order.  A test whose two timestamps sort the same way either
way passes against the broken code and proves nothing.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

import pytest

from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent
from tpot2cti.parsers.honeytrap import HoneytrapParser
from tpot2cti.session.correlator import (
    correlate_by_session_id,
    correlate_by_window,
)

UTC = timezone.utc
PLUS2 = timezone(timedelta(hours=2))
MINUS7 = timezone(timedelta(hours=-7))


def P(ts):
    """Parse one `@timestamp` value the way a parser does."""
    return BaseParser._parse_timestamp({"@timestamp": ts})


# ---------------------------------------------------------------------------
# The contract itself
# ---------------------------------------------------------------------------

def test_tz_less_input_is_read_as_utc():
    """No offset in the string means UTC, not "local", not naive."""
    dt = P("2026-08-07T09:00:00")
    assert dt is not None
    assert dt.tzinfo is not None, "a tz-less @timestamp parsed NAIVE"
    assert dt.utcoffset() == timedelta(0)
    assert dt == datetime(2026, 8, 7, 9, tzinfo=UTC)


def test_non_utc_offset_is_converted_not_preserved():
    """+02:00 must become the same instant expressed in UTC.

    Non-vacuous by construction: 10:30+02:00 is 08:30Z, so the wall-clock
    digits CHANGE.  A test using +00:00 dressed up as an offset would pass
    either way.
    """
    dt = P("2026-08-07T10:30:00+02:00")
    assert dt is not None
    assert dt.utcoffset() == timedelta(0), (
        f"offset survived: {dt.isoformat()} — downstream string comparison "
        "then disagrees with chronological order"
    )
    assert dt == datetime(2026, 8, 7, 8, 30, tzinfo=UTC)
    assert dt.hour == 8 and dt.minute == 30, (
        "converted to UTC in name only — the wall clock still reads 10:30"
    )


def test_negative_offset_is_converted():
    dt = P("2026-08-07T02:00:00-07:00")
    assert dt == datetime(2026, 8, 7, 9, tzinfo=UTC)
    assert dt.utcoffset() == timedelta(0)


def test_z_suffix_is_utc():
    dt = P("2026-08-07T09:00:00Z")
    assert dt == datetime(2026, 8, 7, 9, tzinfo=UTC)
    assert dt.tzinfo is not None and dt.utcoffset() == timedelta(0)


def test_sub_second_precision_survives_normalisation():
    """Microseconds must not be rounded away by the tz conversion."""
    dt = P("2026-08-07T09:00:00.123456Z")
    assert dt == datetime(2026, 8, 7, 9, 0, 0, 123456, tzinfo=UTC)
    assert dt.microsecond == 123456

    # …and through an offset conversion too.
    dt = P("2026-08-07T11:00:00.000789+02:00")
    assert dt == datetime(2026, 8, 7, 9, 0, 0, 789, tzinfo=UTC)
    assert dt.microsecond == 789


@pytest.mark.parametrize("junk", [
    None, "", 0, [], {},                       # falsy → None, no exception
    "not-a-date", "2026-13-45T99:99:99", "T09:00:00",
    "2026/08/07 09:00:00", object(),
])
def test_malformed_input_is_none_not_an_exception(junk):
    """This runs inside the per-doc parse loop; a raise loses the cycle."""
    assert P(junk) is None


def test_missing_field_is_none():
    assert BaseParser._parse_timestamp({}) is None


def test_datetime_instances_are_normalised_too():
    """ES clients can hand back real datetimes, not only strings.

    The `isinstance(ts, datetime)` branch had the same offset-preserving
    bug: it filled in UTC for a naive value but passed an aware +02:00
    value straight through.
    """
    aware_other = datetime(2026, 8, 7, 10, 30, tzinfo=PLUS2)
    dt = P(aware_other)
    assert dt.utcoffset() == timedelta(0), (
        f"datetime branch kept the offset: {dt.isoformat()}"
    )
    assert dt == datetime(2026, 8, 7, 8, 30, tzinfo=UTC)

    naive = datetime(2026, 8, 7, 9, 0)
    assert P(naive) == datetime(2026, 8, 7, 9, tzinfo=UTC)
    assert P(naive).tzinfo is not None


# ---------------------------------------------------------------------------
# Why it matters #1: string order must equal chronological order
# ---------------------------------------------------------------------------

def test_iso_strings_sort_chronologically_across_mixed_sources():
    """`state.py` merges attacker_activity bounds with `<=` on the STRINGS.

    Fixture is chosen so the two orders DISAGREE before the fix:
    10:30+02:00 is 08:30Z — EARLIER than 09:00Z — but "…T10:30:00+02:00"
    sorts AFTER "…T09:00:00+00:00".  A merge keyed on the string would
    therefore record the later value as first_seen.
    """
    earlier = P("2026-08-07T10:30:00+02:00")   # 08:30Z
    later = P("2026-08-07T09:00:00Z")          # 09:00Z
    assert earlier < later, "fixture is wrong: these are not in that order"

    assert earlier.isoformat() < later.isoformat(), (
        f"{earlier.isoformat()!r} does not sort before {later.isoformat()!r} "
        "— string comparison in state.py/campaigns.py would invert them"
    )


def test_naive_and_aware_iso_strings_sort_chronologically():
    """Same trap, the naive flavour.

    "2026-08-07T09:00:00" (naive, 09:00Z) sorts BEFORE
    "2026-08-07T08:30:00+00:00" purely because the shorter string is a
    prefix-wise smaller value — while being half an hour later.
    """
    earlier = P("2026-08-07T08:30:00Z")
    later = P("2026-08-07T09:00:00")           # tz-less
    assert earlier < later
    assert earlier.isoformat() < later.isoformat(), (
        f"{earlier.isoformat()!r} !< {later.isoformat()!r} — a tz-less doc "
        "and an offset-carrying doc produce unorderable strings"
    )


def test_every_emitted_iso_string_has_the_same_shape():
    """All-same-offset is what makes lexicographic == chronological."""
    forms = [
        "2026-08-07T09:00:00Z",
        "2026-08-07T09:00:00",
        "2026-08-07T11:00:00+02:00",
        "2026-08-07T02:00:00-07:00",
        datetime(2026, 8, 7, 11, tzinfo=PLUS2),
    ]
    suffixes = {P(f).isoformat()[-6:] for f in forms}
    assert suffixes == {"+00:00"}, f"mixed offsets reach downstream: {suffixes}"


# ---------------------------------------------------------------------------
# Why it matters #2: the correlator sorts and subtracts
# ---------------------------------------------------------------------------

def _honeytrap_doc(ts, port=22, ip="203.0.113.9"):
    return {
        "@timestamp": ts,
        "src_ip": ip,
        "dest_port": port,
        "t-pot_hostname": "sensor-a",
        "proto": "tcp",
    }


def test_mixed_naive_and_aware_docs_reach_the_correlator_without_crashing():
    """One sensor writes `Z`, another writes tz-less. Both hit one burst.

    `correlate_by_window` does `sorted(...)` and then subtracts two
    timestamps. Naive-vs-aware raises TypeError on both operations, killing
    the cycle for every event in the batch, not just the odd one.
    """
    p = HoneytrapParser()
    events = [
        p.parse(_honeytrap_doc("2026-08-07T09:00:00Z", port=22)),
        p.parse(_honeytrap_doc("2026-08-07T09:01:00", port=23)),     # tz-less
        p.parse(_honeytrap_doc("2026-08-07T11:02:00+02:00", port=80)),  # 09:02Z
    ]
    assert all(e is not None for e in events)

    sessions = correlate_by_window(events, window_seconds=300)

    assert len(sessions) == 1, (
        f"three probes 60s apart became {len(sessions)} bursts — the window "
        "arithmetic read the offsets as wall-clock"
    )
    s = sessions[0]
    assert s.dst_ports == {22, 23, 80}
    assert s.first_seen == datetime(2026, 8, 7, 9, tzinfo=UTC)
    assert s.last_seen == datetime(2026, 8, 7, 9, 2, tzinfo=UTC)


def test_window_gap_is_measured_in_real_elapsed_time():
    """A +02:00 doc two minutes later must not look like two hours later.

    Before the fix these are 09:00Z and 11:02+02:00; subtracting them as
    written (both aware, so no TypeError — this is the OFFSET bug, not the
    naive one) gives 2 minutes only if the offset is honoured. Pin the
    window at 60s so the burst SPLITS if the arithmetic is wrong, and use a
    third probe far enough out that a correct implementation still splits
    exactly once.
    """
    p = HoneytrapParser()
    events = [
        p.parse(_honeytrap_doc("2026-08-07T09:00:00Z", port=22)),
        p.parse(_honeytrap_doc("2026-08-07T11:00:30+02:00", port=23)),  # +30s
        p.parse(_honeytrap_doc("2026-08-07T09:10:00Z", port=443)),      # +9m30s
    ]
    sessions = sorted(
        correlate_by_window(events, window_seconds=60),
        key=lambda s: s.first_seen,
    )
    assert len(sessions) == 2, f"expected 2 bursts, got {len(sessions)}"
    assert sessions[0].dst_ports == {22, 23}, (
        "the +02:00 probe 30 seconds later fell out of a 60-second window"
    )
    assert sessions[1].dst_ports == {443}


def test_session_bounds_come_out_in_chronological_order():
    """first_seen/last_seen must bracket the burst, whatever the sources wrote.

    The tz-less doc is chronologically LAST but its raw string sorts FIRST,
    and the +02:00 doc is chronologically FIRST but its raw string sorts
    LAST — so a fixture that agreed with itself would hide the bug.
    """
    p = HoneytrapParser()
    raw = [
        "2026-08-07T11:00:00+02:00",   # 09:00Z — earliest, sorts last
        "2026-08-07T09:30:00Z",        # 09:30Z
        "2026-08-07T10:00:00",         # 10:00Z — latest, sorts first
    ]
    assert sorted(raw) != [raw[0], raw[1], raw[2]], "fixture is vacuous"

    events = [p.parse(_honeytrap_doc(r, port=1000 + i))
              for i, r in enumerate(raw)]
    sessions = correlate_by_window(events, window_seconds=7200)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.first_seen == datetime(2026, 8, 7, 9, tzinfo=UTC), s.first_seen
    assert s.last_seen == datetime(2026, 8, 7, 10, tzinfo=UTC), s.last_seen
    assert s.first_seen.isoformat() < s.last_seen.isoformat()


def test_session_id_sort_is_chronological_not_lexicographic():
    """`correlate_by_session_id` sorts a group before taking [0] and [-1]."""
    p = HoneytrapParser()   # only used for its inherited _parse_timestamp
    mk = lambda ts: ParsedEvent(
        src_ip="203.0.113.9", timestamp=P(ts), sensor_hostname="sensor-a",
        event_type="Heralding", session_id="sess-1", dst_port=22,
    )
    events = [mk("2026-08-07T10:00:00"), mk("2026-08-07T11:00:00+02:00")]
    sessions = correlate_by_session_id(events)
    assert len(sessions) == 1
    assert sessions[0].first_seen == datetime(2026, 8, 7, 9, tzinfo=UTC)
    assert sessions[0].last_seen == datetime(2026, 8, 7, 10, tzinfo=UTC)


def test_synthetic_session_id_does_not_depend_on_the_host_timezone(monkeypatch):
    """`_build_session` seeds a synthetic id with `.timestamp() * 1000`.

    `datetime.timestamp()` on a NAIVE value interprets it in the host's
    local zone, so the same T-Pot doc produced a different session id on a
    container running TZ=America/Los_Angeles than on one running UTC — and
    the id is what dedup keys on.
    """
    if not hasattr(time, "tzset"):
        pytest.skip("no tzset on this platform")
    monkeypatch.setitem(os.environ, "TZ", "America/Los_Angeles")
    time.tzset()
    try:
        e = ParsedEvent(
            src_ip="203.0.113.9", timestamp=P("2026-08-07T09:00:00"),
            sensor_hostname="sensor-a", event_type="Honeytrap", dst_port=22,
        )
        s = correlate_by_window([e], window_seconds=300)[0]
        expected_ms = int(datetime(2026, 8, 7, 9, tzinfo=UTC).timestamp() * 1000)
        assert s.session_id.endswith(str(expected_ms)), (
            f"session id {s.session_id!r} was built from a local-time reading "
            f"of a UTC document (expected …{expected_ms})"
        )
    finally:
        os.environ.pop("TZ", None)
        time.tzset()


# ---------------------------------------------------------------------------
# Why it matters #3: what lands in the published graph
# ---------------------------------------------------------------------------

def test_published_relationship_window_is_utc(builder):
    """first_seen/last_seen flow into relationship start_time/stop_time."""
    b = builder
    p = HoneytrapParser()
    events = [
        p.parse(_honeytrap_doc("2026-08-07T11:00:00+02:00", port=22)),  # 09:00Z
        p.parse(_honeytrap_doc("2026-08-07T10:00:00", port=80)),        # 10:00Z
    ]
    session = correlate_by_window(events, window_seconds=7200)[0]

    A = "ipv4-addr--00000000-0000-5000-8000-0000000000a1"
    B = "url--00000000-0000-5000-8000-0000000000a2"
    rel = b.build_relationship(A, "related-to", B, session=session)

    assert rel["start_time"].endswith("+00:00"), rel["start_time"]
    assert rel["stop_time"].endswith("+00:00"), rel["stop_time"]
    assert rel["start_time"] < rel["stop_time"], (
        f"start {rel['start_time']} does not sort before stop "
        f"{rel['stop_time']} — a consumer ordering these as strings sees an "
        "edge that ends before it begins"
    )
    assert b._as_dt(rel["start_time"]) == datetime(2026, 8, 7, 9, tzinfo=UTC)
    assert b._as_dt(rel["stop_time"]) == datetime(2026, 8, 7, 10, tzinfo=UTC)


def test_indicator_validity_window_is_utc(builder):
    """`valid_from`/`valid_until` are STIX timestamps, not free text.

    A naive `last_seen` produced `"2026-08-07T09:00:00"` — no timezone
    designator at all, which is not a legal STIX 2.1 timestamp.
    """
    b = builder
    p = HoneytrapParser()
    session = correlate_by_window(
        [p.parse(_honeytrap_doc("2026-08-07T09:00:00", port=22))],
        window_seconds=300,
    )[0]

    ind = b.build_ip_indicator("203.0.113.9", session=session)
    assert ind is not None
    assert ind["valid_from"].endswith("+00:00"), ind["valid_from"]
    assert ind["valid_until"].endswith("+00:00"), ind["valid_until"]
    assert ind["valid_from"] < ind["valid_until"]


# ---------------------------------------------------------------------------
# _as_dt stays as defence in depth
# ---------------------------------------------------------------------------

def test_a_hand_built_naive_session_still_cannot_abort_a_bundle(builder):
    """`build_relationship` takes an AttackSession from ANY caller.

    Normalising in `_parse_timestamp` covers everything that came through a
    parser, which is not everything: tests and any future non-parser producer
    build an AttackSession by hand. Here the SAME edge is observed twice —
    once parser-normalised (aware), once hand-built (naive) — which sends
    `_widen_relationship_window` down the exact `min()`/`max()` path that
    raises TypeError across mixed awareness. So `_as_dt` is not made
    redundant by the fix; it is the second line.
    """
    b = builder
    A = "ipv4-addr--00000000-0000-5000-8000-0000000000b1"
    B = "url--00000000-0000-5000-8000-0000000000b2"

    p = HoneytrapParser()
    from_parser = correlate_by_window(
        [p.parse(_honeytrap_doc("2026-08-07T09:00:00Z", port=22))],
        window_seconds=300,
    )[0]
    kept = b.build_relationship(A, "related-to", B, session=from_parser)
    assert kept is not None, "guard: first observation must be emitted"

    hand_built = AttackSession(
        src_ip="203.0.113.9", session_id="hand", sensor_hostname="s1",
        event_type="Cowrie",
        first_seen=datetime(2026, 8, 7, 11),     # naive, never saw a parser
        last_seen=datetime(2026, 8, 7, 12),
    )
    # Must widen, not raise TypeError comparing naive to aware.
    assert b.build_relationship(A, "related-to", B, session=hand_built) is None, \
        "guard: the duplicate edge must not be emitted twice"

    assert b._as_dt(kept["start_time"]) == datetime(2026, 8, 7, 9, tzinfo=UTC)
    assert b._as_dt(kept["stop_time"]) == datetime(2026, 8, 7, 12, tzinfo=UTC), (
        f"stop is {kept['stop_time']} — the naive observation was dropped "
        "instead of widening the window"
    )
