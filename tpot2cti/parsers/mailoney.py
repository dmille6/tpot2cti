"""Mailoney parser — fake SMTP / spam-relay probe honeypot.

See docs/parsers/mailoney.md for protocol/ES-field/STIX/substance notes.
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

#: SMTP verbs considered no-op chatter — a session whose verbs are a
#: subset of this set (and which captured no credentials / no DATA) is
#: drive-by noise.  Everything outside this set (MAIL, RCPT, DATA, VRFY,
#: EXPN, AUTH, STARTTLS, …) is substantive.
_NOOP_SMTP_VERBS: frozenset[str] = frozenset({"EHLO", "HELO", "QUIT", "NOOP", "RSET"})

#: Session-correlator fallback window when Mailoney docs lack session_id.
_FALLBACK_WINDOW_SECONDS: int = 300


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class MailoneyParser(BaseParser):
    """Parser for T-Pot's Mailoney fake-SMTP honeypot."""

    type_name = "Mailoney"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert a Mailoney ES doc into a normalized ParsedEvent.

        Tolerates the two shapes T-Pot has emitted across versions:
          - one doc per SMTP command (`commands` is a single verb str
            OR a one-element list)
          - one doc per SMTP transaction (`commands` is a list of verbs
            and `data` carries the eventual DATA body bytes).
        Missing `src_ip` or `@timestamp` aborts parsing.
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("mailoney: skipping doc with no src_ip")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("mailoney: skipping doc with unparseable @timestamp")
            return None

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="Mailoney",
            session_id=doc.get("session_id"),
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int((doc.get("dest_port") or doc.get("dst_port"))),
            dst_ip=(doc.get("dest_ip") or doc.get("dst_ip")),
            protocol="smtp",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── commands ──────────────────────────────────────────────────
        # Normalize to a list of UPPERCASE verbs.  `commands` may be a
        # single string ("EHLO example.com"), a list of strings, or
        # absent.  We split the first whitespace-delimited token from
        # each entry — Mailoney sometimes inlines the argument.
        cmds_raw = doc.get("commands")
        commands: list[str] = []
        if isinstance(cmds_raw, str):
            commands = [self._smtp_verb(cmds_raw)]
        elif isinstance(cmds_raw, list):
            for c in cmds_raw:
                if isinstance(c, str):
                    commands.append(self._smtp_verb(c))
        commands = [c for c in commands if c]
        if commands:
            event.meta["commands"] = commands

        # ── DATA body ─────────────────────────────────────────────────
        # `data` is the SMTP message body sent after `DATA\r\n` — bytes,
        # str, or absent.  We just record the length and whether it was
        # non-empty; the Phase 5/6 builders don't ship raw message
        # bodies (PII / spam content) anywhere downstream.
        data = doc.get("data")
        data_len = 0
        if isinstance(data, (bytes, bytearray)):
            data_len = len(data)
        elif isinstance(data, str):
            data_len = len(data)
        event.meta["has_data"] = data_len > 0
        if data_len:
            event.meta["data_len"] = data_len

        # ── credentials ───────────────────────────────────────────────
        # auth_user / auth_pass — preserve None vs empty-string semantics
        # the same way Heralding/Cowrie do.
        if (auth_user := doc.get("auth_user")) is not None:
            event.meta["auth_user"] = str(auth_user)
        if (auth_pass := doc.get("auth_pass")) is not None:
            event.meta["auth_pass"] = str(auth_pass)

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — session_id when available, time-window otherwise
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events: Iterable[ParsedEvent]) -> list[AttackSession]:
        """Group Mailoney events into sessions.

        If any event in the batch carries a `session_id`, we use
        `correlate_by_session_id` (which falls back to one-event-per-
        session for the events that don't have one).  If NO events
        carry a session_id we use `correlate_by_window(300s)` to glue
        contiguous bursts together — mirrors the V0 importer's
        `max_gap_seconds=300` default and avoids fragmenting a single
        SMTP transaction into per-verb singleton sessions.
        """
        events_list = list(events)
        any_session_id = any(e.session_id for e in events_list)
        if any_session_id:
            return correlate_by_session_id(
                events_list, aggregator=self._aggregate_session,
            )
        return correlate_by_window(
            events_list,
            window_seconds=_FALLBACK_WINDOW_SECONDS,
            aggregator=self._aggregate_session,
        )

    def _aggregate_session(self, session: AttackSession, events: list[ParsedEvent]) -> None:
        """Roll up commands, data presence, and credentials onto the
        AttackSession.

        Commands are appended in chronological order, preserving every
        verb (we don't dedup — repeated `RCPT TO` is itself a signal).
        Credential pairs are deduplicated to avoid bloating the daily
        Note when the same `AUTH PLAIN` is replayed by a scanner.
        """
        seen_creds: set[tuple[str, str]] = set()
        any_data = False
        total_data_len = 0
        for e in events:
            meta = e.meta
            for verb in meta.get("commands") or []:
                session.commands.append(str(verb))
            if meta.get("has_data"):
                any_data = True
                total_data_len += int(meta.get("data_len") or 0)
            auth_user = meta.get("auth_user")
            auth_pass = meta.get("auth_pass")
            if auth_user is not None and auth_pass is not None:
                pair = (str(auth_user), str(auth_pass))
                if pair not in seen_creds:
                    seen_creds.add(pair)
                    session.credentials_tried.append(pair)

        session.meta["has_data"] = any_data
        if total_data_len:
            session.meta["data_len_total"] = total_data_len
    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _smtp_verb(token: str) -> str:
        """Return the leading whitespace-stripped SMTP verb (uppercase).

        Mailoney sometimes records the full command line ("MAIL FROM:
        <attacker@example.com>") instead of the bare verb.  We keep only
        the first whitespace-delimited token so substance checks
        compare apples to apples against `_NOOP_SMTP_VERBS`.
        """
        if not token:
            return ""
        first = token.strip().split(None, 1)[0] if token.strip() else ""
        return first.upper()

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


# Register on import
register(MailoneyParser())
