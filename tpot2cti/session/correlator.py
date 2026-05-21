"""tpot2cti — generic session-correlation helpers.

Three reusable correlators that parsers can compose in their
`BaseParser.correlate()` override.  Each takes an iterable of ParsedEvents
and returns a list of AttackSessions.

Per V1_SPEC.md §3 step 3:

    3. Correlate events into sessions
       - Group by (session_id, sensor) for protocols that have sessions
         (Cowrie, Heralding, ...)
       - One-event-per-session for protocols without (Suricata alerts,
         single ConPot probes)
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import timedelta
from typing import Callable, Iterable, Optional

from tpot2cti.parsers.base import AttackSession, ParsedEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper: build a session from a group of events (sorted by timestamp)
# ---------------------------------------------------------------------------

def _build_session(
    events: list[ParsedEvent],
    session_id: Optional[str] = None,
    aggregator: Optional[Callable[[AttackSession, list[ParsedEvent]], None]] = None,
) -> AttackSession:
    """Construct an AttackSession from a sorted list of events.

    `events` must be non-empty and sorted ascending by timestamp.
    `session_id` overrides the synthetic ID derived from the first event.
    `aggregator` is an optional callback (session, events) → None that
    populates protocol-specific session attributes (commands, malware
    hashes, etc.) — parsers pass this in to customize aggregation
    without overriding the whole correlator.
    """
    first = events[0]
    last = events[-1]
    sid = session_id or first.session_id or (
        f"{first.sensor_hostname}:{first.src_ip}:"
        f"{int(first.timestamp.timestamp() * 1000)}"
    )

    session = AttackSession(
        src_ip=first.src_ip,
        sensor_hostname=first.sensor_hostname,
        session_id=sid,
        event_type=first.event_type,
        first_seen=first.timestamp,
        last_seen=last.timestamp,
        events=list(events),
    )

    # Default aggregation: populate dst_ports / dst_ips / protocols
    for e in events:
        if e.dst_port is not None:
            session.dst_ports.add(e.dst_port)
        if e.dst_ip:
            session.dst_ips.add(e.dst_ip)
        if e.protocol:
            session.protocols.add(e.protocol)

    # Optional parser-specific aggregation
    if aggregator is not None:
        try:
            aggregator(session, events)
        except Exception as ex:
            logger.warning(
                f"session aggregator failed for session_id={sid}: {ex}"
            )

    return session


# ---------------------------------------------------------------------------
# Correlators
# ---------------------------------------------------------------------------

def one_event_per_session(
    events: Iterable[ParsedEvent],
) -> list[AttackSession]:
    """Trivial correlator: one event → one session.

    Used by parsers for protocols without native session IDs
    (Suricata, ConPot, single-shot probe protocols).
    """
    return [AttackSession.from_event(e) for e in events]


def correlate_by_session_id(
    events: Iterable[ParsedEvent],
    *,
    aggregator: Optional[Callable[[AttackSession, list[ParsedEvent]], None]] = None,
) -> list[AttackSession]:
    """Group events sharing a `(session_id, sensor)` key from the same
    source IP.

    Used by Cowrie, Heralding, Mailoney — protocols where T-Pot emits
    multiple events per logical attack session and stamps them with
    a shared session_id.

    Events without a session_id become single-event sessions (treated
    like `one_event_per_session` for those).
    """
    events_list = list(events)
    by_key: dict[tuple, list[ParsedEvent]] = defaultdict(list)
    singletons: list[ParsedEvent] = []

    for e in events_list:
        if not e.session_id:
            singletons.append(e)
            continue
        key = (e.session_id, e.sensor_hostname, e.src_ip)
        by_key[key].append(e)

    sessions = []
    for key, group in by_key.items():
        group.sort(key=lambda x: x.timestamp)
        sessions.append(_build_session(group, session_id=key[0], aggregator=aggregator))

    # Singletons (events with no session_id) get one-event treatment
    for e in singletons:
        sessions.append(AttackSession.from_event(e))

    return sessions


def correlate_by_window(
    events: Iterable[ParsedEvent],
    *,
    window_seconds: int = 300,
    aggregator: Optional[Callable[[AttackSession, list[ParsedEvent]], None]] = None,
) -> list[AttackSession]:
    """Group events from the same `(src_ip, sensor)` that fall within
    `window_seconds` of each other.

    Useful for protocols where T-Pot doesn't emit session IDs but the
    attacker's behavior is naturally bursty — Honeytrap port scans,
    FATT fingerprint observations across multiple connections in quick
    succession.

    The "window" extends each time a new event is added — a continuous
    burst stays in one session until there's a >`window_seconds` gap.
    This mirrors the V0 importer's session correlator (which set
    `max_gap_seconds: 300` by default).
    """
    events_list = sorted(events, key=lambda e: e.timestamp)
    by_attacker: dict[tuple, list[list[ParsedEvent]]] = defaultdict(list)
    gap = timedelta(seconds=window_seconds)

    for e in events_list:
        key = (e.src_ip, e.sensor_hostname)
        bursts = by_attacker[key]
        if bursts and (e.timestamp - bursts[-1][-1].timestamp) <= gap:
            bursts[-1].append(e)
        else:
            bursts.append([e])

    sessions = []
    for bursts in by_attacker.values():
        for burst in bursts:
            sessions.append(_build_session(burst, aggregator=aggregator))

    return sessions


if __name__ == "__main__":
    # Smoke test
    import logging as _logging
    from datetime import datetime, timezone

    _logging.basicConfig(level=_logging.INFO, format="%(levelname)s %(message)s")
    now = datetime.now(timezone.utc)

    def mk(ip, sid, ts_offset_sec, sensor="n1", port=22):
        return ParsedEvent(
            src_ip=ip, timestamp=now + timedelta(seconds=ts_offset_sec),
            sensor_hostname=sensor, event_type="Cowrie",
            session_id=sid, dst_port=port,
        )

    events = [
        mk("1.2.3.4", "sess-A", 0),
        mk("1.2.3.4", "sess-A", 30),     # same session
        mk("1.2.3.4", "sess-B", 60),     # different session, same IP
        mk("5.6.7.8", "sess-C", 0),      # different IP
        mk("9.9.9.9", None, 90),         # no session_id → singleton
    ]
    sessions = correlate_by_session_id(events)
    assert len(sessions) == 4, f"expected 4 sessions, got {len(sessions)}"
    print(f"OK correlate_by_session_id: 5 events → {len(sessions)} sessions")

    sessions = one_event_per_session(events)
    assert len(sessions) == 5
    print(f"OK one_event_per_session: 5 events → {len(sessions)} sessions")

    # Window correlator
    burst_events = [
        mk("1.1.1.1", None, 0),
        mk("1.1.1.1", None, 100),   # within 300s — same burst
        mk("1.1.1.1", None, 200),   # within 300s — same burst
        mk("1.1.1.1", None, 700),   # >300s gap — new burst
    ]
    sessions = correlate_by_window(burst_events, window_seconds=300)
    assert len(sessions) == 2, f"expected 2 bursts, got {len(sessions)}"
    print(f"OK correlate_by_window: 4 events → {len(sessions)} burst sessions")
    print("Smoke test passed.")
