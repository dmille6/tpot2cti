"""Redishoneypot parser — fake Redis honeypot.

See docs/parsers/redishoneypot.md for protocol/ES-field/STIX/substance notes.
"""

from __future__ import annotations

import logging
from typing import Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Command sets
# ---------------------------------------------------------------------------

#: Recon-only Redis commands.  A session that issues ONLY these is
#: drive-by background radiation (mass scanners fingerprinting open
#: Redis instances).  Per V1_SPEC §5.12 we suppress these from the
#: full STIX graph and route them to the one-Sighting drive-by path.
_RECON_REDIS_CMDS: frozenset[str] = frozenset({"INFO", "PING", "COMMAND"})

#: Suspicious Redis commands — the high-value RCE / abuse vectors that
#: real attackers chain.  This set is documentation more than gate
#: logic: anything NOT in `_RECON_REDIS_CMDS` is treated as substance,
#: but we surface this set explicitly because it's what the Note
#: highlights and what we expect to see most often.  Per V1_SPEC §5.12.
_SUSPICIOUS_REDIS_CMDS: frozenset[str] = frozenset({
    "CONFIG",        # CONFIG SET dir / dbfilename — write-where primitive
    "SLAVEOF",       # replication-of malicious master → RCE via dlmalloc
    "REPLICAOF",     # SLAVEOF rename in newer Redis
    "EVAL",          # Lua sandbox surface
    "EVALSHA",
    "MODULE",        # MODULE LOAD → arbitrary native code
    "SCRIPT",        # SCRIPT LOAD pre-stage for EVALSHA chains
    "DEBUG",         # DEBUG SLEEP / OBJECT for DoS + leaks
    "FLUSHALL",      # destructive
    "FLUSHDB",
    "BGSAVE",        # write-where via RDB
    "SAVE",
    "AUTH",          # password guessing
    "SET",           # used to plant authorized_keys when chained with CONFIG SET dir
    "KEYS",          # KEYS * data enumeration
    "CLUSTER",       # CLUSTER RESET, CLUSTER FORGET — disruption
})


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class RedishoneypotParser(BaseParser):
    """Parser for T-Pot's Redishoneypot fake-Redis honeypot."""

    type_name = "Redishoneypot"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert a Redishoneypot ES doc into a ParsedEvent.

        Returns None for malformed docs (missing src_ip or @timestamp).
        Per V1_SPEC §5.12 we only consume src_ip + commands_received;
        the rest of the doc rides along on raw_doc.
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("redishoneypot: doc missing src_ip; skipping")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug(
                "redishoneypot: doc missing/unparseable @timestamp; skipping"
            )
            return None

        # Per 2026-05-22 field-name audit vs real ES exports: T-Pot's
        # actual Redis honeypot ships one doc per command with `action`
        # holding the command verb (NewConnect / PING / SET / INFO / ...)
        # at 100% of real docs. The `msg` field (also 100% present) is
        # usually empty for these connect/command events but can carry
        # an argument string for commands like SET / GET.  The legacy
        # `commands_received` array shape never appears in real data —
        # kept as a defensive read for cross-version safety.
        commands = self._normalize_commands(doc.get("commands_received"))
        if not commands:
            action = doc.get("action")
            msg = doc.get("msg")
            if isinstance(action, str) and action.strip():
                # Pre-2026-05-22 the parser dropped every Redis event
                # because it only looked at the (never-populated)
                # commands_received list. Now we synthesize a command
                # string from action [+ msg argument] so the substance
                # filter and the Note both see real signal.
                if isinstance(msg, str) and msg.strip():
                    commands = [f"{action.strip()} {msg.strip()}"]
                else:
                    commands = [action.strip()]

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="Redishoneypot",
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int(doc.get("dst_port") or doc.get("dest_port") or 6379),
            dst_ip=doc.get("dst_ip") or doc.get("dest_ip"),
            protocol="redis",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # Stash the full normalized command list in meta — the builder
        # uses this verbatim to render the Note body.
        event.meta["commands_received"] = commands

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — default one-event-per-session is correct
    # ──────────────────────────────────────────────────────────────────
    # The Redishoneypot index already aggregates commands per connection
    # into a single doc, so there's nothing further to merge.  We also
    # mirror the command list onto session.commands so downstream
    # consumers can introspect via the session directly.

    def correlate(self, events):
        """One-event-per-session, copying commands_received onto
        session.commands so the substance signal lives on the session.
        """
        sessions: list[AttackSession] = []
        for e in events:
            s = AttackSession.from_event(e)
            cmds = e.meta.get("commands_received") or []
            if cmds:
                s.commands.extend(cmds)
            sessions.append(s)
        return sessions
    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_commands(raw) -> list[str]:
        """Coerce `commands_received` to a list[str].

        T-Pot can encode this as a list of strings, a list of arrays
        (RESP-style ``[["CONFIG", "SET", "dir", "/tmp"], ...]``), or a
        single string.  We collapse each to a single line of text so
        the substance filter can do verb extraction and the Note can
        render it verbatim.
        """
        if raw is None:
            return []
        if isinstance(raw, str):
            return [raw]
        if isinstance(raw, list):
            out: list[str] = []
            for item in raw:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, list):
                    # RESP-array form → "CONFIG SET dir /tmp"
                    out.append(" ".join(str(x) for x in item))
                else:
                    out.append(str(item))
            return out
        return [str(raw)]

    @staticmethod
    def _command_verb(command: str) -> str:
        """Return the leading verb of a Redis command line, uppercased.

        Handles plain `"INFO"`, `"INFO server"`, `"  CONFIG  SET dir"`,
        etc.  Returns an empty string if the command line is empty.
        """
        if not command:
            return ""
        return command.strip().split(maxsplit=1)[0].upper() if command.strip() else ""

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


# Register on import
register(RedishoneypotParser())
