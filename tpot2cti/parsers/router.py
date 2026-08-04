"""Router parser — honeypot-router (Telnet console) emulator.

See docs/parsers/router.md for protocol/ES-field/STIX/substance notes.
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
