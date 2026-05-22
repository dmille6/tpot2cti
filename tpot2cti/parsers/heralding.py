"""Heralding parser — multi-protocol credential capture honeypot.

Heralding listens on a handful of authentication-bearing TCP services
(SSH, Telnet, FTP, POP3, IMAP, SMTP, HTTP-Basic, etc.) and records
every `(username, password)` pair an attacker submits.  Unlike Cowrie
it offers no shell — its sole purpose is harvesting credential-spray
attempts — so the substance signal is dominated by `credentials_tried`
plus the sheer event count of repeated probes on the same session.

Per V1_SPEC.md §5.5:

  T-Pot doc fields used:
    src_ip, dst_port, protocol,
    username, password,
    session_id

  Event correlation:
    Heralding stamps every credential-attempt event with a session_id;
    we group events sharing `(session_id, sensor, src_ip)` via the
    shared `correlate_by_session_id` helper.  This collapses bursty
    multi-attempt probes from the same attacker into a single
    AttackSession whose `credentials_tried` field captures every pair.

  Substance filter (per docs/LESSONS_LEARNED_FROM_V0.md §2):
    A Heralding session is substantive iff
      - it captured at least one credential pair, OR
      - event_count > 2 (more than just open + close — repeated
        protocol-layer probing without a credential is still worth
        the full SDO graph).
    Pure single-touch sessions with no credentials are drive-by noise
    and get the one-Sighting drive-by treatment.

Per V1_SPEC.md §6 (credentials handling):
    Heralding credential pairs are NEVER emitted as User-Account SCOs
    (that would flood OpenCTI with one SCO per attempted password).
    They go into `AttackSession.credentials_tried` as `(username,
    password)` tuples; the Phase 6 daily Note aggregator consumes that
    list to produce one summary Note per attacker per day.
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

class HeraldingParser(BaseParser):
    """Parser for T-Pot's Heralding multi-protocol credential honeypot."""

    type_name = "Heralding"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert a Heralding ES doc into a normalized ParsedEvent.

        Heralding emits one document per credential-attempt event; the
        `session_id` field ties multiple attempts on the same TCP
        connection together.  Missing `src_ip` or `@timestamp` aborts
        parsing (logged at DEBUG, doc skipped).
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("heralding: skipping doc with no src_ip")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("heralding: skipping doc with unparseable @timestamp")
            return None

        # Protocol comes through as the application-layer service name
        # ("ssh", "ftp", "smtp", "pop3", ...).  We lowercase to match
        # the convention used elsewhere in the codebase.
        # Per 2026-05-22 field-name audit vs real ES exports: T-Pot
        # actually ships this as `proto` (100% of real Heralding docs)
        # NOT `protocol`. Same dual-spelling bug class as dest_port.
        protocol = doc.get("proto") or doc.get("protocol")
        protocol = str(protocol).lower() if protocol else None

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="Heralding",
            session_id=doc.get("session_id"),
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int((doc.get("dest_port") or doc.get("dst_port"))),
            dst_ip=(doc.get("dest_ip") or doc.get("dst_ip")),
            protocol=protocol,
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # Stash credentials + protocol in meta — the correlator
        # aggregator promotes them onto session.credentials_tried etc.
        # We preserve `None` distinctly from empty string in meta so
        # the aggregator can decide whether a field is "present".
        if (uname := doc.get("username")) is not None:
            event.meta["username"] = str(uname)
        if (pwd := doc.get("password")) is not None:
            event.meta["password"] = str(pwd)
        if protocol:
            event.meta["protocol"] = protocol

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — group by (session_id, sensor, src_ip)
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events: Iterable[ParsedEvent]) -> list[AttackSession]:
        """Group Heralding events by their native session_id.

        Delegates to the shared `correlate_by_session_id` helper and
        installs `_aggregate_session` as the per-session callback that
        populates `credentials_tried`, `dst_ports`, and `protocols`.
        """
        return correlate_by_session_id(events, aggregator=self._aggregate_session)

    def _aggregate_session(self, session: AttackSession, events: list[ParsedEvent]) -> None:
        """Walk per-event meta and roll up session-level substance signals.

        - `(username, password)` pairs → `session.credentials_tried`
          (deduplicated; preserves first-seen order).
        - `dst_port` → `session.dst_ports` (already populated by the
          shared `_build_session` helper from the event field; we top up
          here for events that carried dst_port only in meta).
        - `protocol` → `session.protocols` (likewise already populated
          from the event field).
        """
        seen_creds: set[tuple[str, str]] = set()
        for e in events:
            meta = e.meta
            uname = meta.get("username")
            pwd = meta.get("password")
            # Per V1_SPEC §6: both halves required (an empty username or
            # empty password is still a credential attempt and worth
            # recording — only None means "field absent from doc").
            if uname is not None and pwd is not None:
                pair = (str(uname), str(pwd))
                if pair not in seen_creds:
                    seen_creds.add(pair)
                    session.credentials_tried.append(pair)
            # dst_port + protocol are populated by _build_session from
            # the event's typed field, but if a parser ever stashed
            # them only in meta we top up here.
            if (port := e.dst_port) is not None:
                session.dst_ports.add(port)
            if proto := (e.protocol or meta.get("protocol")):
                session.protocols.add(str(proto))

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — substance filter per V1_SPEC §5.5
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """A Heralding session is substantive when it captured credentials
        OR generated more than two events (>2 — i.e., the attacker did
        more than open + close).

        Per docs/LESSONS_LEARNED_FROM_V0.md §2, drive-by sessions still
        get an IP-Addr + Sighting via the drive-by path; only substantive
        sessions get the full SDO graph (Indicator, AttackPattern, the
        eventual daily credentials Note).
        """
        return bool(session.credentials_tried) or session.event_count > 2

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
register(HeraldingParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timedelta, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = HeraldingParser()
    now = datetime.now(timezone.utc)

    base_doc = {
        "type": "Heralding",
        "t-pot_hostname": "node1",
        "src_ip": "203.0.113.10",
        "src_port": 55555,
        "dst_port": 22,
        "protocol": "ssh",
        "geoip": {
            "country_iso_code": "CN", "country_name": "China",
            "asn": 4134, "organization": "ChinaNet",
        },
    }

    # ── Case 1: drive-by — single touch, no credential captured ────────
    driveby_doc = {
        **base_doc,
        "@timestamp": now.isoformat(),
        "session_id": "drv-sess-1",
        # no username/password — connection opened but no auth attempt
    }

    # ── Case 2: substantive — multiple credential attempts ─────────────
    sub_docs = []
    for i, (u, p) in enumerate([("root", "root"), ("admin", "admin"),
                                 ("root", "123456"), ("user", "password")]):
        sub_docs.append({
            **base_doc,
            "@timestamp": (now + timedelta(seconds=i)).isoformat(),
            "session_id": "sub-sess-1",
            "username": u,
            "password": p,
        })

    # parse + correlate the drive-by
    drive_events = [parser.parse(driveby_doc)]
    drive_events = [e for e in drive_events if e is not None]
    assert len(drive_events) == 1, "drive-by parse failed"
    drive_sessions = parser.correlate(drive_events)
    assert len(drive_sessions) == 1
    drive_session = drive_sessions[0]
    drive_has = parser.has_substance(drive_session)
    print(f"drive-by:       events={drive_session.event_count} creds={len(drive_session.credentials_tried)} substance={drive_has}  (expected False)")
    assert drive_has is False, "drive-by should NOT be substantive"

    # parse + correlate the substantive session
    sub_events = [parser.parse(d) for d in sub_docs]
    sub_events = [e for e in sub_events if e is not None]
    assert len(sub_events) == 4, f"expected 4 substantive events, got {len(sub_events)}"
    sub_sessions = parser.correlate(sub_events)
    assert len(sub_sessions) == 1, f"expected 1 session, got {len(sub_sessions)}"
    sub_session = sub_sessions[0]
    sub_has = parser.has_substance(sub_session)
    print(f"substantive:    events={sub_session.event_count} creds={len(sub_session.credentials_tried)} substance={sub_has}  (expected True)")
    print(f"                credentials_tried: {sub_session.credentials_tried}")
    print(f"                dst_ports:         {sorted(sub_session.dst_ports)}")
    print(f"                protocols:         {sorted(sub_session.protocols)}")
    assert sub_has is True, "substantive session should be substantive"
    assert len(sub_session.credentials_tried) == 4
    assert ("root", "root") in sub_session.credentials_tried
    assert 22 in sub_session.dst_ports
    assert "ssh" in sub_session.protocols

    # ── Case 3: substantive by event_count > 2 with no credentials ─────
    probe_docs = []
    for i in range(3):
        probe_docs.append({
            **base_doc,
            "@timestamp": (now + timedelta(seconds=i)).isoformat(),
            "session_id": "probe-sess-1",
            # no creds, just repeated protocol-layer touches
        })
    probe_events = [parser.parse(d) for d in probe_docs]
    probe_events = [e for e in probe_events if e is not None]
    probe_sessions = parser.correlate(probe_events)
    assert len(probe_sessions) == 1
    probe_session = probe_sessions[0]
    probe_has = parser.has_substance(probe_session)
    print(f"probe-cluster:  events={probe_session.event_count} creds={len(probe_session.credentials_tried)} substance={probe_has}  (expected True)")
    assert probe_has is True, "event_count>2 should be substantive"

    print("OK")
