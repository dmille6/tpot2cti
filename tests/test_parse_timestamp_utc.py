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
    """CHARACTERISATION, not a regression test — `Z` already worked.

    It is here because `Z` is what T-Pot's logstash actually writes, so it
    is the shape that must not break while the other shapes are fixed.
    """
    dt = P("2026-08-07T09:00:00Z")
    assert dt == datetime(2026, 8, 7, 9, tzinfo=UTC)
    assert dt.tzinfo is not None and dt.utcoffset() == timedelta(0)


def test_lowercase_z_is_utc_not_a_dropped_document():
    """RFC 3339's UTC designator is case-INSENSITIVE.

    `fromisoformat` does not accept a lowercase `z`, and the old
    `.replace("Z", "+00:00")` only matched the uppercase form — so a doc
    written "…T09:00:00z" parsed to None and the event was skipped
    entirely, logged at DEBUG and counted nowhere.
    """
    assert P("2026-08-07T09:00:00z") == datetime(2026, 8, 7, 9, tzinfo=UTC)


def test_basic_format_offset_without_a_colon():
    """"+0200" is legal ISO 8601 and some emitters use it."""
    assert P("2026-08-07T11:00:00+0200") == datetime(2026, 8, 7, 9, tzinfo=UTC)


def test_date_only_is_midnight_utc():
    assert P("2026-08-07") == datetime(2026, 8, 7, 0, 0, tzinfo=UTC)


def test_named_zone_datetimes_convert_by_actual_offset_including_dst():
    """A zoneinfo tzinfo is not a fixed offset — the shift depends on the date.

    `astimezone` asks the zone; `replace(tzinfo=utc)` would not. Europe/Berlin
    is +02:00 in August and +01:00 in January, and both of these are 09:00Z.
    """
    from zoneinfo import ZoneInfo
    berlin = ZoneInfo("Europe/Berlin")
    assert P(datetime(2026, 8, 7, 11, tzinfo=berlin)) == datetime(
        2026, 8, 7, 9, tzinfo=UTC)
    assert P(datetime(2026, 1, 7, 10, tzinfo=berlin)) == datetime(
        2026, 1, 7, 9, tzinfo=UTC)


def test_epoch_millis_are_not_supported():
    """CHARACTERISATION. ES date fields accept epoch millis; T-Pot's logstash
    writes ISO strings, and neither the old code nor the new one parses a
    number. Pinned so that if a sensor ever ships epoch millis this fails
    loudly here rather than silently skipping every one of its documents."""
    assert P(1754557200000) is None
    assert P("1754557200000") is None


def test_sub_second_precision_survives_normalisation():
    """Microseconds must not be rounded away by the tz conversion.

    Equality alone would NOT catch a surviving offset — 11:00:00.000789+02:00
    IS equal to 09:00:00.000789Z as an instant, and its `.microsecond` is 789
    either way. So assert the offset and the wall clock too.
    """
    dt = P("2026-08-07T09:00:00.123456Z")
    assert dt == datetime(2026, 8, 7, 9, 0, 0, 123456, tzinfo=UTC)
    assert dt.microsecond == 123456

    # …and through an offset conversion too.
    dt = P("2026-08-07T11:00:00.000789+02:00")
    assert dt == datetime(2026, 8, 7, 9, 0, 0, 789, tzinfo=UTC)
    assert dt.microsecond == 789
    assert dt.utcoffset() == timedelta(0), f"offset survived: {dt.isoformat()}"
    assert dt.hour == 9, "converted in name only — wall clock still reads 11"


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
    """The window must be measured on INSTANTS, not on wall-clock digits.

    Scope note, so this test is not read as proving more than it does: two
    AWARE datetimes already subtract correctly whatever offsets they carry,
    so this does NOT catch a merely-surviving `+02:00`. What it catches is a
    normalisation that stamps UTC on an aware value WITHOUT shifting the
    clock (`replace(tzinfo=utc)` where `astimezone(utc)` was meant) — which
    moves the instant by the offset and is the easy wrong fix here. The
    third probe mixes in a tz-less doc so the naive/aware asymmetry is in
    play too. Window pinned at 60s so a wrong reading SPLITS the burst.
    """
    p = HoneytrapParser()
    events = [
        p.parse(_honeytrap_doc("2026-08-07T09:00:00Z", port=22)),
        p.parse(_honeytrap_doc("2026-08-07T11:00:30+02:00", port=23)),  # +30s
        p.parse(_honeytrap_doc("2026-08-07T09:10:00", port=443)),       # +9m30s
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


# ---------------------------------------------------------------------------
# Identity seeds must key on the instant, not on how it was spelled
# ---------------------------------------------------------------------------

def test_suricata_session_id_keys_on_the_instant_not_the_spelling():
    """`_session_id_for` seeded a deterministic id from the RAW @timestamp.

    Suricata has no session concept, so the id IS flow+signature+time — and
    the Sighting id downstream is derived from it. Reading the raw field made
    the id a function of how the sensor spelled the instant: the same alert
    written "…T09:00:00Z" by one sensor and "…T11:00:00+02:00" by another
    produced two ids, two sessions, two Sightings for one event.
    """
    from tpot2cti.parsers.suricata import SuricataParser

    p = SuricataParser()
    doc = lambda ts: {
        "@timestamp": ts, "src_ip": "203.0.113.9", "flow_id": 12345,
        "t-pot_hostname": "sensor-a",
        "alert": {"signature": "ET SCAN", "signature_id": 2001},
    }
    a = p.parse(doc("2026-08-07T09:00:00Z"))
    b = p.parse(doc("2026-08-07T11:00:00+02:00"))
    c = p.parse(doc("2026-08-07T09:00:00"))          # tz-less, same instant
    assert a is not None and b is not None and c is not None
    assert a.session_id == b.session_id == c.session_id, (
        f"one instant produced {len({a.session_id, b.session_id, c.session_id})} "
        f"session ids: {a.session_id!r} / {b.session_id!r} / {c.session_id!r}"
    )


def test_a_relationship_publishes_the_normalised_time_not_the_raw_one(builder):
    """Guarding the COMPARISON is not the same as guarding the VALUE.

    `build_relationship` compared through `_as_dt` but then wrote
    `first.isoformat()` straight out, so a hand-built naive session put
    "2026-08-07T09:00:00" — no timezone designator, not a legal STIX 2.1
    timestamp — on the published edge.
    """
    A = "ipv4-addr--00000000-0000-5000-8000-0000000000c1"
    B = "url--00000000-0000-5000-8000-0000000000c2"
    naive = AttackSession(
        src_ip="203.0.113.9", session_id="c", sensor_hostname="s1",
        event_type="Cowrie",
        first_seen=datetime(2026, 8, 7, 9), last_seen=datetime(2026, 8, 7, 10),
    )
    rel = builder.build_relationship(A, "related-to", B, session=naive)
    assert rel["start_time"].endswith("+00:00"), rel["start_time"]
    assert rel["stop_time"].endswith("+00:00"), rel["stop_time"]

    # …and an offset-carrying one is published in UTC, so two consumers
    # ordering edges as strings agree with each other.
    C = "url--00000000-0000-5000-8000-0000000000c3"
    offset = AttackSession(
        src_ip="203.0.113.9", session_id="d", sensor_hostname="s1",
        event_type="Cowrie",
        first_seen=datetime(2026, 8, 7, 11, tzinfo=PLUS2),   # 09:00Z
        last_seen=datetime(2026, 8, 7, 12, tzinfo=PLUS2),    # 10:00Z
    )
    rel2 = builder.build_relationship(A, "related-to", C, session=offset)
    assert rel2["start_time"] == rel["start_time"], (
        f"{rel2['start_time']} vs {rel['start_time']} — one instant, two "
        "spellings on the published graph"
    )
    assert rel2["stop_time"] == rel["stop_time"]


# ── the Suricata session id, which this PR changed but did not pin ────────
#
# `_session_id_for` used to interpolate the RAW `@timestamp` string, making
# the id a function of how a sensor SPELLED an instant rather than of the
# instant. This PR passes the normalised timestamp instead. Nothing asserted
# it: blanking the normalised value in `_session_id_for` failed zero tests,
# so the fix would have regressed in silence.
#
# CORRECTION: an earlier version of this comment, and the PR's own comment in
# suricata.py, said the Sighting id derives from the session id. It does not.
# Sighting ids come from (sensor, target, day, discriminator) -- checked on
# main, flagged by codex. What the session id actually drives is distinct-
# session accounting (hence fallback Sighting counts) and any session Note
# built from these sessions. Still worth pinning, just not for the stated
# reason; overstating the blast radius is the same habit as understating it.

def test_one_instant_spelled_two_ways_is_one_suricata_session():
    from tpot2cti.parsers.base import BaseParser
    from tpot2cti.parsers.suricata import SuricataParser

    def doc(ts):
        return {"@timestamp": ts, "src_ip": "203.0.113.1", "dest_ip": "10.0.0.1",
                "src_port": 4444, "dest_port": 80,
                "alert": {"signature_id": 2001}, "flow_id": 12345}

    z, off = doc("2026-09-16T09:00:00Z"), doc("2026-09-16T11:00:00+02:00")
    t_z = BaseParser._parse_timestamp(z)
    t_off = BaseParser._parse_timestamp(off)
    assert t_z == t_off, "guard: the fixture must be ONE instant, two spellings"

    assert SuricataParser._session_id_for(z, t_z) == \
        SuricataParser._session_id_for(off, t_off), (
        "the same alert at the same instant produced two session ids because "
        "the sensors spelled the timestamp differently"
    )


def test_different_instants_still_get_different_suricata_sessions():
    """Positive control — collapsing everything would also pass the above."""
    from tpot2cti.parsers.base import BaseParser
    from tpot2cti.parsers.suricata import SuricataParser

    def doc(ts):
        return {"@timestamp": ts, "src_ip": "203.0.113.1", "dest_ip": "10.0.0.1",
                "src_port": 4444, "dest_port": 80,
                "alert": {"signature_id": 2001}, "flow_id": 12345}

    a, b = doc("2026-09-16T09:00:00Z"), doc("2026-09-16T09:00:01Z")
    assert SuricataParser._session_id_for(a, BaseParser._parse_timestamp(a)) != \
        SuricataParser._session_id_for(b, BaseParser._parse_timestamp(b))


# ── the upgrade path: rows written BEFORE normalisation ──────────────────
#
# Normalising new writes to UTC is right, but the SQLite rows already on disk
# carry whatever offset their source used. state.py merged activity bounds by
# STRING comparison, so a stored "10:30+02:00" (= 08:30Z) sorts after a new
# "09:00+00:00" (= 09:00Z) while being earlier. The merge then stores
# first_seen LATER than last_seen -- corrupting rows that were correct before
# the upgrade. Reproduced by codex on review of #45.

def test_merging_across_the_offset_boundary_does_not_invert_the_window():
    from datetime import datetime
    from tpot2cti.state import _earlier, _later

    stored = "2026-09-16T10:30:00+02:00"   # 08:30Z, written pre-normalisation
    fresh = "2026-09-16T09:00:00+00:00"    # 09:00Z, written post-normalisation
    assert stored > fresh, "guard: the fixture must disagree lexicographically"

    first, last = _earlier(stored, fresh), _later(stored, fresh)
    assert datetime.fromisoformat(first) <= datetime.fromisoformat(last), (
        f"first_seen {first} is AFTER last_seen {last} — an inverted window"
    )
    assert first == stored, "the earlier instant is the +02:00 row"
    assert last == fresh


def test_a_malformed_stored_timestamp_never_beats_a_valid_one():
    """One bad row must not take down the cycle — and must not WIN it either.

    The first version of this asserted only `is not None`, which passes
    whichever value wins and so asserted nothing. codex reproduced
    `_later("not-a-date", valid) -> "not-a-date"` through an actual upsert.
    Junk that wins a max() pins the bound to a string with no chronological
    meaning, and every later comparison against it is arbitrary.
    """
    from tpot2cti.state import _earlier, _later
    valid = "2026-09-16T09:00:00+00:00"

    # Junk on BOTH sides of the sort order, on purpose. "not-a-date" sorts
    # AFTER a 2026 timestamp, so a broken string-comparison implementation
    # still returns the right answer for it and the assertion proves nothing
    # — the mutation run caught exactly that. "!" sorts BEFORE, which is what
    # discriminates.
    for junk in ("not-a-date", "!", "0000-bad", "zzz"):
        assert _earlier(junk, valid) == valid, f"_earlier lost to {junk!r}"
        assert _earlier(valid, junk) == valid, f"_earlier lost to {junk!r}"
        assert _later(junk, valid) == valid, f"_later lost to {junk!r}"
        assert _later(valid, junk) == valid, f"_later lost to {junk!r}"

    # two unparseable values: no chronological answer exists, just be stable
    assert _earlier("x", "y") == "x"
    assert _later("x", "y") == "y"


def test_an_out_of_range_timestamp_returns_none_not_an_exception():
    """astimezone() raises OverflowError near the datetime boundary, and the
    contract here is 'a datetime or None'."""
    from tpot2cti.parsers.base import BaseParser
    assert BaseParser._parse_timestamp(
        {"@timestamp": "0001-01-01T00:00:00+01:00"}) is None
    assert BaseParser._parse_timestamp({"@timestamp": "garbage"}) is None
    assert BaseParser._parse_timestamp({"@timestamp": ""}) is None


def test_a_null_bound_never_wins_the_comparison():
    """A NULL first_seen sorts before every real timestamp, which would pin
    the activity window open forever if it were allowed to win."""
    from tpot2cti.state import _earlier, _later
    real = "2026-09-16T09:00:00+00:00"
    assert _earlier(None, real) == real
    assert _earlier(real, None) == real
    assert _later(None, real) == real
    assert _later("", real) == real


def test_the_real_merge_path_does_not_invert_an_upgraded_row(tmp_path):
    """Exercises upsert_attacker_activity, not just the helpers.

    Testing `_earlier`/`_later` alone proved nothing about the call site:
    reverting state.py's merge to the old string comparison failed ZERO tests
    until this one existed. The helper being right does not make the caller
    use it — that is the whole shape of this defect class.
    """
    from datetime import datetime, timezone
    from tpot2cti.state import CycleState
    from tpot2cti.parsers.base import AttackSession, ParsedEvent

    st = CycleState(db_path=tmp_path / "state.db")
    ip = "203.0.113.77"

    def sess(dt):
        ev = ParsedEvent(src_ip=ip, timestamp=dt, sensor_hostname="s1",
                         event_type="Cowrie", dst_port=22)
        ev.meta = {}
        s = AttackSession.from_event(ev)
        s.first_seen = s.last_seen = dt
        return s

    # Seed a row, then hand-write it back in the PRE-normalisation spelling:
    # an offset-bearing timestamp, exactly as rows on disk still carry.
    st.upsert_attacker_activity(sess(datetime(2026, 9, 16, 8, 30, tzinfo=timezone.utc)))
    with st._conn() as c:
        c.execute("UPDATE attacker_activity SET first_seen = ?, last_seen = ?",
                  ("2026-09-16T10:30:00+02:00", "2026-09-16T10:30:00+02:00"))

    # A later observation, written post-normalisation as +00:00.
    st.upsert_attacker_activity(sess(datetime(2026, 9, 16, 9, 0, tzinfo=timezone.utc)))

    with st._conn() as c:
        first, last = c.execute(
            "SELECT first_seen, last_seen FROM attacker_activity").fetchone()
    assert datetime.fromisoformat(first) <= datetime.fromisoformat(last), (
        f"stored window is inverted: first_seen={first} last_seen={last}"
    )


# ── the queries, not just the merge ──────────────────────────────────────
#
# Fixing upsert_attacker_activity left the real exposure open: the
# comparisons that decide what an analyst SEES happen in SQL, which compares
# TEXT and cannot call a Python helper. A correctly-merged row whose
# first_seen kept a legacy "+02:00" spelling is still omitted from a window
# query it belongs in. codex reproduced exactly that. So the fix is to
# normalise the DATA on open, which makes lexicographic order equal
# chronological order again for every one of those call sites at once.

def test_a_legacy_offset_row_is_found_by_the_window_query(tmp_path):
    from datetime import datetime, timezone
    from tpot2cti.state import CycleState
    from tpot2cti.parsers.base import AttackSession, ParsedEvent

    db = tmp_path / "state.db"
    st = CycleState(db_path=db)

    def sess(dt, ip="203.0.113.88"):
        ev = ParsedEvent(src_ip=ip, timestamp=dt, sensor_hostname="s1",
                         event_type="Cowrie", dst_port=22)
        ev.meta = {}
        s = AttackSession.from_event(ev)
        s.first_seen = s.last_seen = dt
        return s

    st.upsert_attacker_activity(sess(datetime(2026, 9, 16, 8, 30, tzinfo=timezone.utc)))
    # Rewrite to the PRE-normalisation spelling AND reset the schema version,
    # so this is a database from before the migration existed. The migration
    # is one-time by design (gated on PRAGMA user_version); a fixture that
    # relied on it re-running every open would be testing something the
    # production path never does.
    with st._conn() as c:
        c.execute("UPDATE attacker_activity SET first_seen = ?, last_seen = ?",
                  ("2026-09-16T10:30:00+02:00", "2026-09-16T10:30:00+02:00"))
        c.execute("PRAGMA user_version = 0")

    # Reopening runs the normalisation.
    st2 = CycleState(db_path=db)
    with st2._conn() as c:
        first, last = c.execute(
            "SELECT first_seen, last_seen FROM attacker_activity").fetchone()
    assert first.endswith("+00:00"), f"not normalised: {first}"
    assert datetime.fromisoformat(first) == datetime(
        2026, 9, 16, 8, 30, tzinfo=timezone.utc), "normalisation moved the instant"

    # And the text-comparison window query now finds it.
    with st2._conn() as c:
        hit = c.execute(
            "SELECT COUNT(*) FROM attacker_activity "
            "WHERE last_seen >= ? AND first_seen <= ?",
            ("2026-09-16T08:00:00+00:00", "2026-09-16T09:30:00+00:00"),
        ).fetchone()[0]
    assert hit == 1, (
        "the attacker is inside 08:00Z–09:30Z but the text window query "
        "missed it — legacy offset spelling still breaks SQL comparison"
    )


def test_normalisation_is_idempotent_and_spares_unparseable_rows(tmp_path):
    """Running it twice must not drift, and a junk row must survive rather
    than be destroyed by a migration it cannot satisfy."""
    from tpot2cti.state import CycleState
    from tpot2cti.parsers.base import AttackSession, ParsedEvent
    from datetime import datetime, timezone

    db = tmp_path / "state.db"
    st = CycleState(db_path=db)
    ev = ParsedEvent(src_ip="203.0.113.99", timestamp=datetime(2026, 9, 16, 8, tzinfo=timezone.utc),
                     sensor_hostname="s1", event_type="Cowrie", dst_port=22)
    ev.meta = {}
    s = AttackSession.from_event(ev)
    s.first_seen = s.last_seen = ev.timestamp
    st.upsert_attacker_activity(s)
    with st._conn() as c:
        c.execute("UPDATE attacker_activity SET first_seen = ?", ("not-a-date",))
        c.execute("PRAGMA user_version = 0")

    once = CycleState(db_path=db)
    with once._conn() as c:
        a = c.execute("SELECT first_seen, last_seen FROM attacker_activity").fetchone()
    twice = CycleState(db_path=db)
    with twice._conn() as c:
        b = c.execute("SELECT first_seen, last_seen FROM attacker_activity").fetchone()

    assert a == b, "normalisation is not idempotent"
    assert a[0] == "not-a-date", "an unparseable value was destroyed, not skipped"


def test_the_migration_runs_once_and_is_version_gated(tmp_path):
    """It must not rescan every table on every open.

    Several containers open this file; a full scan per open is both wasted
    work and a window for the concurrent-clobber this migration was rewritten
    to avoid.
    """
    from tpot2cti.state import CycleState
    db = tmp_path / "state.db"
    st = CycleState(db_path=db)
    with st._conn() as c:
        assert c.execute("PRAGMA user_version").fetchone()[0] == \
            CycleState._SCHEMA_VERSION, "version not stamped on first open"

    # A legacy value written AFTER the migration ran is left alone — the real
    # path cannot produce one, because the parser normalises at the source.
    with st._conn() as c:
        c.execute("INSERT INTO attacker_activity "
                  "(src_ip, parser, sensor, first_seen, last_seen) "
                  "VALUES ('203.0.113.5','Cowrie','s1',?,?)",
                  ("2026-09-16T10:30:00+02:00", "2026-09-16T10:30:00+02:00"))
    CycleState(db_path=db)
    with st._conn() as c:
        got = c.execute("SELECT first_seen FROM attacker_activity "
                        "WHERE src_ip='203.0.113.5'").fetchone()[0]
    assert got == "2026-09-16T10:30:00+02:00", (
        "the migration re-ran on an already-migrated database"
    )


def test_a_concurrent_write_is_not_clobbered_by_the_migration(tmp_path):
    """The first version read the whole table, then wrote row-by-row on an
    autocommit connection — a writer committing in between had its newer
    value overwritten by the migration's stale snapshot. Reproduced by codex.

    BEGIN IMMEDIATE takes the write lock before the read, so the other writer
    is excluded rather than raced.
    """
    import sqlite3
    from tpot2cti.state import CycleState
    db = tmp_path / "state.db"
    st = CycleState(db_path=db)
    with st._conn() as c:
        c.execute("INSERT INTO attacker_activity "
                  "(src_ip, parser, sensor, first_seen, last_seen) "
                  "VALUES ('203.0.113.6','Cowrie','s1',?,?)",
                  ("2026-09-16T10:30:00+02:00", "2026-09-16T10:30:00+02:00"))
        c.execute("PRAGMA user_version = 0")

    other = sqlite3.connect(db, isolation_level=None, timeout=1)
    other.execute("BEGIN IMMEDIATE")          # hold the write lock
    try:
        with pytest.raises(sqlite3.OperationalError):
            CycleState(db_path=db)            # must block then fail, not clobber
    finally:
        other.execute("ROLLBACK")
        other.close()

    with st._conn() as c:
        still = c.execute("SELECT first_seen FROM attacker_activity "
                          "WHERE src_ip='203.0.113.6'").fetchone()[0]
        ver = c.execute("PRAGMA user_version").fetchone()[0]
    assert still == "2026-09-16T10:30:00+02:00", "row changed despite the lock"
    assert ver == 0, "version was bumped without the migration committing"
