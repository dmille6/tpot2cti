"""Beelzebub parser — LLM-driven SSH/HTTP/TCP honeypot.

See docs/parsers/beelzebub.md for protocol/ES-field/STIX/substance notes.
"""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent
from tpot2cti.session import correlate_by_session_id

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class BeelzebubParser(BaseParser):
    """Parser for T-Pot's Beelzebub LLM-driven honeypot."""

    type_name = "Beelzebub"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("beelzebub: skipping doc with no src_ip")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            # Logstash should add @timestamp; if it didn't, try the
            # engine's own `timestamp` field as a fallback.
            raw_ts = doc.get("timestamp")
            if raw_ts:
                # Re-shim into the helper's expected key.
                ts = self._parse_timestamp({"@timestamp": raw_ts})
        if ts is None:
            logger.debug("beelzebub: skipping doc with no parseable timestamp")
            return None

        protocol = doc.get("protocol")
        protocol = str(protocol).lower() if protocol else None

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="Beelzebub",
            session_id=(doc.get("session") or None),
            src_port=self._safe_int(doc.get("src_port")),
            # Beelzebub writes dest_port as a string in raw JSON ("22").
            # Logstash will keep it as string; we coerce.
            dst_port=self._safe_int(doc.get("dest_port") or doc.get("dst_port")),
            dst_ip=(doc.get("dest_ip") or doc.get("dst_ip")),
            protocol=protocol,
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── per-event signals stashed in meta ──────────────────────────
        # The correlator's aggregator rolls these up into session fields.
        msg = doc.get("message") or doc.get("msg") or ""
        event.meta["beelzebub_msg"] = str(msg)

        if (uname := doc.get("username")) is not None:
            event.meta["username"] = str(uname)
        if (pwd := doc.get("password")) is not None:
            event.meta["password"] = str(pwd)

        # Interactive command execution.  Beelzebub stuffs the attacker's
        # full input here (one event per command line); `output` is what
        # the cache+LLM returned.
        if (cmd := doc.get("input")):
            event.meta["command"] = str(cmd)
        if (out := doc.get("output")):
            event.meta["output"] = str(out)

        # SSH client version string (signal for client-tooling fingerprint:
        # libssh_0.9.6 = Outlaw, PuTTY = manual, OpenSSH_X.Y = legit
        # client, Go = stand-alone scanner, etc.).
        if (client := doc.get("client")):
            event.meta["ssh_client"] = str(client)

        # Beelzebub's service-name label ("ExampleCorp dev01 - SSH
        # interactive (hybrid cache + LLM)") is useful as a label.
        if (svc := doc.get("service")):
            event.meta["beelzebub_service"] = str(svc)

        # Status field: "Stateless" = bare auth, "Start"/"End" = inline session.
        if (status := doc.get("status")):
            event.meta["beelzebub_status"] = str(status)

        if (environ := doc.get("environ")):
            event.meta["environ"] = str(environ)

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — group by (session_id, sensor, src_ip)
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events: Iterable[ParsedEvent]) -> list[AttackSession]:
        return correlate_by_session_id(events, aggregator=self._aggregate_session)

    def _aggregate_session(
        self, session: AttackSession, events: list[ParsedEvent]
    ) -> None:
        """Roll up per-event Beelzebub signals onto the session."""
        seen_creds: set[tuple[str, str]] = set()
        for e in events:
            meta = e.meta

            # Credentials
            uname = meta.get("username")
            pwd = meta.get("password")
            if uname is not None and pwd is not None:
                pair = (str(uname), str(pwd))
                if pair not in seen_creds:
                    seen_creds.add(pair)
                    session.credentials_tried.append(pair)

            # Commands the attacker typed (interactive session input).
            if cmd := meta.get("command"):
                if cmd not in session.commands:
                    session.commands.append(cmd)

            # SSH client banner → ssh_version (used as a fingerprint label).
            if client := meta.get("ssh_client"):
                if session.ssh_version is None:
                    session.ssh_version = client

            # dst_port + protocol top-up (in case the event-level field
            # was missing but meta has it).
            if (port := e.dst_port) is not None:
                session.dst_ports.add(port)
            if proto := (e.protocol or meta.get("protocol")):
                session.protocols.add(str(proto))
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
register(BeelzebubParser())
