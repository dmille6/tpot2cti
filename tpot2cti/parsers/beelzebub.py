"""Beelzebub parser — LLM-driven SSH/HTTP/TCP honeypot.

Beelzebub is the LLM-powered honeypot ships with T-Pot's `ai` profile.
We run it on port 22 with a hybrid pre-canned command set + LLM
fallback (configured against an Ollama instance running qwen3:14b).

Per V1_SPEC.md §5 (parser interface), the parser converts T-Pot ES
docs into normalized `ParsedEvent`s + correlates per session.

Beelzebub emits TWO event flavors per session:
  1. "New SSH attempt"           — auth-time event with username + password
  2. "New SSH Inline Session"    — interactive command execution with
                                    `input` (attacker keystrokes) and
                                    `output` (what we returned).

Logstash adds `type: "Beelzebub"` and `@timestamp` (from the engine's
own `timestamp` ISO string).  Fields the importer relies on:

  Required:  src_ip, @timestamp (logstash) or timestamp (raw)
  Common:    src_port, dest_port (dotted-string in raw log), session,
             username, password, input, output, protocol, status,
             service, client (SSH client version string)

Substance filter:
  - any command execution (input non-empty)              → substantive
  - any credential pair captured                         → substantive
  - more than 2 events in the same session               → substantive
  - bare connect with no auth/command — Beelzebub almost never emits
    these; the "New SSH attempt" event always carries username and
    password (often the empty string), so any successful parse is
    effectively a credential-attempt and routes substantive.
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
    # has_substance()
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Substantive when:
          - any command executed (post-auth shell interaction), OR
          - any credential pair captured, OR
          - more than 2 events on the session (sustained probing).
        Bare single-touch connects with no creds drop to drive-by.
        """
        return (
            bool(session.commands)
            or bool(session.credentials_tried)
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
register(BeelzebubParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timedelta, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = BeelzebubParser()
    now = datetime.now(timezone.utc)

    base = {
        "type": "Beelzebub",
        "t-pot_hostname": "node2",
        "src_ip": "165.154.6.130",
        "src_port": "53118",
        "dest_port": "22",
        "protocol": "SSH",
        "service": "ExampleCorp dev01 - SSH interactive (hybrid cache + LLM)",
        "client": "SSH-2.0-libssh_0.9.6",
        "geoip": {
            "country_iso_code": "RU",
            "country_name": "Russia",
            "asn": 12345,
            "organization": "ExampleNet",
        },
    }

    # ── Case A: single Stateless auth attempt — substantive via cred ─
    auth_only_doc = {
        **base,
        "@timestamp": now.isoformat(),
        "session": "auth-1",
        "message": "New SSH attempt",
        "msg": "New SSH attempt",
        "username": "root",
        "password": "root",
        "status": "Stateless",
    }
    ev = parser.parse(auth_only_doc)
    assert ev is not None and ev.session_id == "auth-1"
    sessions = parser.correlate([ev])
    assert len(sessions) == 1
    s0 = sessions[0]
    assert parser.has_substance(s0) is True, (
        "captured credential is always substantive (matches Heralding)"
    )
    assert ("root", "root") in s0.credentials_tried
    print(f"single-auth: creds={len(s0.credentials_tried)} commands={len(s0.commands)} substance=True")

    # ── Case A': blank-username probe → empty meta, no cred → drive-by
    blank_doc = {
        **base,
        "@timestamp": now.isoformat(),
        "session": "blank-1",
        "message": "New SSH attempt",
        # NO username/password keys at all — pure connection probe
        "status": "Stateless",
    }
    blank_ev = parser.parse(blank_doc)
    assert blank_ev is not None
    blank_sessions = parser.correlate([blank_ev])
    assert parser.has_substance(blank_sessions[0]) is False, (
        "pure connect with no auth fields is drive-by"
    )
    print(f"blank-probe: creds={len(blank_sessions[0].credentials_tried)} commands=0 substance=False")

    # ── Case B: Outlaw-style command chain post-auth ──────────────────
    cmd_docs = []
    # Auth
    cmd_docs.append({
        **base,
        "@timestamp": now.isoformat(),
        "session": "outlaw-1",
        "message": "New SSH attempt",
        "username": "fox",
        "password": "123456",
        "status": "Stateless",
    })
    # Three command-execution events
    for i, cmd in enumerate([
        "cd ~; chattr -ia .ssh; lockr -ia .ssh",
        "uname -a",
        "echo 'ssh-rsa AAAAB3...attacker_key' >> ~/.ssh/authorized_keys",
    ]):
        cmd_docs.append({
            **base,
            "@timestamp": (now + timedelta(seconds=1 + i)).isoformat(),
            "session": "outlaw-1",
            "message": "New SSH Inline Session",
            "username": "fox",
            "input": cmd,
            "output": "bash: lockr: command not found\n" if i == 0 else "",
            "status": "Start",
        })

    cmd_events = [parser.parse(d) for d in cmd_docs]
    cmd_events = [e for e in cmd_events if e is not None]
    assert len(cmd_events) == 4
    cmd_sessions = parser.correlate(cmd_events)
    assert len(cmd_sessions) == 1
    cs = cmd_sessions[0]
    assert parser.has_substance(cs) is True
    assert len(cs.commands) == 3
    assert ("fox", "123456") in cs.credentials_tried
    assert cs.ssh_version == "SSH-2.0-libssh_0.9.6"
    assert 22 in cs.dst_ports
    assert "ssh" in cs.protocols
    print(f"outlaw:      creds={len(cs.credentials_tried)} commands={len(cs.commands)} ssh_client={cs.ssh_version} substance=True")
    print(f"             commands: {cs.commands}")

    # ── Case C: credential spray (4 attempts, 0 commands) ─────────────
    spray_docs = []
    for i, (u, p) in enumerate([
        ("root", "root"), ("admin", "admin"),
        ("oracle", "oracle"), ("postgres", "postgres"),
    ]):
        spray_docs.append({
            **base,
            "@timestamp": (now + timedelta(seconds=i)).isoformat(),
            "session": f"spray-{i}",  # different sessions per attempt
            "message": "New SSH attempt",
            "username": u,
            "password": p,
            "status": "Stateless",
        })
    spray_events = [parser.parse(d) for d in spray_docs]
    spray_events = [e for e in spray_events if e is not None]
    spray_sessions = parser.correlate(spray_events)
    # Different session IDs → 4 sessions; each has 1 event + 1 cred,
    # so each is substantive on the credentials_tried branch.
    assert len(spray_sessions) == 4
    assert all(parser.has_substance(s) for s in spray_sessions)
    print(f"spray:       sessions={len(spray_sessions)} all_substantive=True")

    print("OK")
