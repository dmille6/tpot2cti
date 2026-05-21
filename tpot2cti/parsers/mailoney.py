"""Mailoney parser — fake SMTP / spam-relay probe honeypot.

Mailoney emulates an open SMTP relay on port 25 (and friends).  Most
of what it catches is internet-background scanners checking whether
the host will relay spam — EHLO/HELO followed by an immediate QUIT.
The substantive subset is attackers who actually try to push a
message body through (`DATA` with non-empty content) or who probe
authentication with `AUTH LOGIN` / `AUTH PLAIN` credential pairs.

Per V1_SPEC.md §5.10:

  T-Pot doc fields used:
    src_ip, commands (SMTP verbs), data (message body),
    auth_user, auth_pass,
    session_id  (when Mailoney provides one)

  Event correlation:
    Mailoney's behavior re session_id varies by version — some emit a
    per-connection `session_id`, others don't.  We try
    `correlate_by_session_id` first and fall back to
    `correlate_by_window(window=300s)` when no events in the batch
    carry a session_id.  The window mirrors the V0 importer's
    `max_gap_seconds=300` default.

  Substance filter (per docs/LESSONS_LEARNED_FROM_V0.md §2):
    A Mailoney session is substantive iff
      - it issued SMTP commands beyond the no-op set {EHLO, HELO, QUIT}
        (so MAIL FROM, RCPT TO, DATA, VRFY, AUTH, ... count), OR
      - at least one credential pair was captured, OR
      - non-zero DATA-body bytes were observed.
    Pure EHLO/QUIT relay-probes are drive-by noise and get the
    one-Sighting drive-by path.

Per V1_SPEC.md §6 (credentials handling):
    `auth_user` / `auth_pass` pairs are NEVER emitted as User-Account
    SCOs.  They flow into `AttackSession.credentials_tried`; the
    Phase 6 daily Note aggregator consumes that list.
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
            dst_port=self._safe_int(doc.get("dst_port")),
            dst_ip=doc.get("dst_ip"),
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
    # has_substance() — substance filter per V1_SPEC §5.10
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """A Mailoney session is substantive iff
          - it issued any SMTP verb outside `_NOOP_SMTP_VERBS`, OR
          - it captured at least one credential pair, OR
          - the attacker pushed any DATA bytes.

        Drive-by noise: a session whose verbs are a subset of
        {EHLO, HELO, QUIT, NOOP, RSET} with no creds and no DATA.
        """
        non_noop = any(
            v.upper() not in _NOOP_SMTP_VERBS for v in session.commands
        )
        return bool(
            non_noop
            or session.credentials_tried
            or session.meta.get("has_data")
        )

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


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timedelta, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = MailoneyParser()
    now = datetime.now(timezone.utc)

    base = {
        "type": "Mailoney",
        "t-pot_hostname": "node1",
        "src_ip": "198.51.100.5",
        "src_port": 44444,
        "dst_port": 25,
        "geoip": {
            "country_iso_code": "RU", "country_name": "Russia",
            "asn": 12345, "organization": "ExampleNet",
        },
    }

    # ── Case 1: drive-by — EHLO + QUIT only, no creds, no DATA ─────────
    driveby_docs = [
        {**base, "@timestamp": now.isoformat(),
         "session_id": "drv-1", "commands": "EHLO scan.example.com"},
        {**base, "@timestamp": (now + timedelta(seconds=1)).isoformat(),
         "session_id": "drv-1", "commands": "QUIT"},
    ]
    drive_events = [parser.parse(d) for d in driveby_docs]
    drive_events = [e for e in drive_events if e is not None]
    drive_sessions = parser.correlate(drive_events)
    assert len(drive_sessions) == 1
    drive = drive_sessions[0]
    drive_has = parser.has_substance(drive)
    print(f"drive-by:    commands={drive.commands} creds={len(drive.credentials_tried)} has_data={drive.meta.get('has_data')} substance={drive_has}  (expected False)")
    assert drive_has is False

    # ── Case 2: substantive by commands — MAIL/RCPT/DATA ───────────────
    sub_docs = [
        {**base, "@timestamp": now.isoformat(),
         "session_id": "sub-1", "commands": ["EHLO bad.example.com"]},
        {**base, "@timestamp": (now + timedelta(seconds=1)).isoformat(),
         "session_id": "sub-1", "commands": ["MAIL FROM:<a@b.com>"]},
        {**base, "@timestamp": (now + timedelta(seconds=2)).isoformat(),
         "session_id": "sub-1", "commands": ["RCPT TO:<v@victim.org>"]},
        {**base, "@timestamp": (now + timedelta(seconds=3)).isoformat(),
         "session_id": "sub-1", "commands": ["DATA"],
         "data": "Subject: test\r\n\r\nhello\r\n.\r\n"},
        {**base, "@timestamp": (now + timedelta(seconds=4)).isoformat(),
         "session_id": "sub-1", "commands": ["QUIT"]},
    ]
    sub_events = [parser.parse(d) for d in sub_docs]
    sub_events = [e for e in sub_events if e is not None]
    sub_sessions = parser.correlate(sub_events)
    assert len(sub_sessions) == 1
    sub = sub_sessions[0]
    sub_has = parser.has_substance(sub)
    print(f"substantive: commands={sub.commands} has_data={sub.meta.get('has_data')} substance={sub_has}  (expected True)")
    assert sub_has is True
    assert "MAIL" in sub.commands and "RCPT" in sub.commands and "DATA" in sub.commands

    # ── Case 3: substantive by credentials — AUTH attempt ──────────────
    auth_docs = [
        {**base, "@timestamp": now.isoformat(),
         "session_id": "auth-1", "commands": "EHLO x"},
        {**base, "@timestamp": (now + timedelta(seconds=1)).isoformat(),
         "session_id": "auth-1", "commands": "AUTH LOGIN",
         "auth_user": "postmaster", "auth_pass": "password123"},
        {**base, "@timestamp": (now + timedelta(seconds=2)).isoformat(),
         "session_id": "auth-1", "commands": "QUIT"},
    ]
    auth_events = [parser.parse(d) for d in auth_docs]
    auth_events = [e for e in auth_events if e is not None]
    auth_sessions = parser.correlate(auth_events)
    assert len(auth_sessions) == 1
    auth = auth_sessions[0]
    auth_has = parser.has_substance(auth)
    print(f"auth:        commands={auth.commands} creds={auth.credentials_tried} substance={auth_has}  (expected True)")
    assert auth_has is True
    assert ("postmaster", "password123") in auth.credentials_tried

    # ── Case 4: no session_id → window correlator path ─────────────────
    win_docs = [
        {**base, "@timestamp": now.isoformat(), "commands": "EHLO w"},
        {**base, "@timestamp": (now + timedelta(seconds=10)).isoformat(),
         "commands": "MAIL FROM:<x@y>"},
        {**base, "@timestamp": (now + timedelta(seconds=20)).isoformat(),
         "commands": "QUIT"},
    ]
    win_events = [parser.parse(d) for d in win_docs]
    win_events = [e for e in win_events if e is not None]
    assert all(e.session_id is None for e in win_events)
    win_sessions = parser.correlate(win_events)
    assert len(win_sessions) == 1, f"window correlator should collapse to 1 session, got {len(win_sessions)}"
    win = win_sessions[0]
    win_has = parser.has_substance(win)
    print(f"window:      events={win.event_count} commands={win.commands} substance={win_has}  (expected True)")
    assert win_has is True

    print("OK")
