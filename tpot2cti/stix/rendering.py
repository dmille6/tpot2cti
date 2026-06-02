"""tpot2cti — STIX text-rendering helpers.

See docs/stix/rendering.md for design notes.
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
#: Per LESSONS §7.1 we no longer emit a separate Note per probe.
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
    approach the PoC used). Per LESSONS §7.1: this is the
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


# ---------------------------------------------------------------------------
# Attacker-profile renderers (per attacker_profile.py).
# ---------------------------------------------------------------------------

#: How many entries from each sample category we render in the profile
#: body. Matches the cap in CycleState._ATTACKER_SAMPLE_CAP — anything
#: beyond becomes an "and N more" marker.
_PROFILE_SAMPLE_RENDER_CAP = 25

#: Cap on the inline command preview within the profile body.
_PROFILE_COMMAND_PREVIEW_BYTES = 4000


def _fmt_int(n) -> str:
    try:
        return f"{int(n):,}"
    except Exception:
        return str(n)


def _render_per_parser_section(row: dict) -> list[str]:
    """One markdown subsection per (parser, sensor) activity row."""
    lines: list[str] = []
    parser = row.get("parser") or "Unknown"
    sensor = row.get("sensor") or "unknown"
    lines.append(f"### {parser} on `{sensor}`")
    lines.append("")
    lines.append(
        f"- **Sessions:** {_fmt_int(row.get('sessions_count'))} "
        f"(**events:** {_fmt_int(row.get('events_count'))})"
    )
    lines.append(
        f"- **First seen:** `{row.get('first_seen')}`  •  "
        f"**Last seen:** `{row.get('last_seen')}`"
    )
    substance_bits: list[str] = []
    if (n := row.get("auth_success_count") or 0):
        substance_bits.append(f"auth-success x{_fmt_int(n)}")
    if (n := row.get("credentials_count") or 0):
        substance_bits.append(f"{_fmt_int(n)} credential attempt(s)")
    if (n := row.get("commands_count") or 0):
        substance_bits.append(f"{_fmt_int(n)} command(s)")
    if (n := row.get("malware_drop_count") or 0):
        substance_bits.append(f"{_fmt_int(n)} file drop(s)")
    if substance_bits:
        lines.append(f"- **Substance signals:** {', '.join(substance_bits)}")
    if (hassh := row.get("hassh")):
        lines.append(f"- **HASSH:** `{hassh}`")
    if (ver := row.get("ssh_version")):
        lines.append(f"- **SSH version:** `{ver}`")
    return lines


def _render_credentials_table(rows: list[dict]) -> list[str]:
    """Aggregated top-25 credentials table across all parsers/sensors."""
    bucket: dict[tuple, int] = {}
    for row in rows:
        for entry in row.get("sample_credentials_json", []) or []:
            if isinstance(entry, list) and len(entry) >= 3:
                u, p, c = entry[0], entry[1], int(entry[-1])
                bucket[(str(u), str(p))] = bucket.get((str(u), str(p)), 0) + c
    if not bucket:
        return []
    top = sorted(bucket.items(), key=lambda kv: (-kv[1], kv[0]))[:_PROFILE_SAMPLE_RENDER_CAP]
    out = [
        "## Top credentials attempted",
        "",
        "| # | Username | Password | Count |",
        "|---|----------|----------|-------|",
    ]
    for i, ((u, p), c) in enumerate(top, start=1):
        u_disp = u.replace("|", "\\|").replace("\n", " ")[:128]
        p_disp = p.replace("|", "\\|").replace("\n", " ")[:128]
        out.append(f"| {i} | `{u_disp}` | `{p_disp}` | {_fmt_int(c)} |")
    remaining = len(bucket) - len(top)
    if remaining > 0:
        out.append(f"_… and {remaining} more credential pair(s)_")
    return out


def _render_commands_section(rows: list[dict]) -> list[str]:
    """Aggregated top-25 commands as a code-fenced block."""
    bucket: dict[str, int] = {}
    for row in rows:
        for entry in row.get("sample_commands_json", []) or []:
            if isinstance(entry, list) and entry:
                cmd, c = entry[0], int(entry[-1])
                bucket[str(cmd)] = bucket.get(str(cmd), 0) + c
    if not bucket:
        return []
    top = sorted(bucket.items(), key=lambda kv: (-kv[1], kv[0]))[:_PROFILE_SAMPLE_RENDER_CAP]
    out = ["## Top commands executed", ""]
    block: list[str] = []
    total_bytes = 0
    for cmd, c in top:
        line = f"[{c}x] {cmd}"
        total_bytes += len(line.encode("utf-8")) + 1
        if total_bytes > _PROFILE_COMMAND_PREVIEW_BYTES:
            block.append("... [truncated for size]")
            break
        block.append(line)
    out.append("```")
    out.extend(block)
    out.append("```")
    remaining = len(bucket) - len(top)
    if remaining > 0:
        out.append(f"_… and {remaining} more command(s)_")
    return out


def _render_unique_section(
    rows: list[dict], col: str, heading: str, fence: bool = False,
) -> list[str]:
    """Render a deduplicated list from one JSON column across parser rows."""
    seen: list = []
    seen_set: set = set()
    for row in rows:
        for v in row.get(col, []) or []:
            key = repr(v)
            if key in seen_set:
                continue
            seen_set.add(key)
            seen.append(v)
    if not seen:
        return []
    rendered = seen[:_PROFILE_SAMPLE_RENDER_CAP]
    out = [f"## {heading}", ""]
    if fence:
        out.append("```")
        for v in rendered:
            out.append(str(v))
        out.append("```")
    else:
        for v in rendered:
            out.append(f"- `{v}`")
    remaining = len(seen) - len(rendered)
    if remaining > 0:
        out.append(f"_… and {remaining} more_")
    return out


def render_attacker_profile_body(
    ip: str,
    rows: list[dict],
    *,
    cadence: str = "live",
    window_label: str = "all-time",
    max_bytes: int = 64 * 1024,
) -> str:
    """Render the markdown body of an attacker-profile Note.

    ``rows`` is the list produced by ``CycleState.get_attacker_activity(ip)``
    — one row per (parser, sensor). Empty list returns the empty string
    so the caller can skip emission.

    ``cadence`` is one of ``"live"`` / ``"daily"`` / ``"weekly"`` and
    selects the heading. ``window_label`` is the human-readable window
    descriptor (e.g. ``"2026-05-21 (UTC)"`` for daily, ``"ISO week
    2026-W21"`` for weekly).

    Sections (each omitted when empty):
      - Header (IP / window / country / AS / totals)
      - Per-parser activity (one subsection per parser+sensor row)
      - Top credentials attempted (aggregated table)
      - Top commands executed (aggregated code-fenced block)
      - Files dropped (sha256 list)
      - URLs / domains referenced
      - Suricata signatures
      - MITRE techniques
      - Honeytrap ports probed
      - SSH client fingerprints

    Truncated to ``max_bytes`` with a "[truncated]" marker (matches the
    cap in stix/builder.py:MAX_NOTE_BODY_BYTES).
    """
    if not rows:
        return ""

    # Aggregate header bits.
    total_sessions = sum(int(r.get("sessions_count") or 0) for r in rows)
    total_events = sum(int(r.get("events_count") or 0) for r in rows)
    first_seen = min((r["first_seen"] for r in rows if r.get("first_seen")), default="?")
    last_seen = max((r["last_seen"] for r in rows if r.get("last_seen")), default="?")
    country = next((r.get("geoip_country") for r in rows if r.get("geoip_country")), None)
    asn = next((r.get("geoip_asn") for r in rows if r.get("geoip_asn")), None)
    as_org = next((r.get("geoip_as_org") for r in rows if r.get("geoip_as_org")), None)
    parsers = sorted({r.get("parser") for r in rows if r.get("parser")})

    if cadence == "daily":
        title = f"Daily attacker snapshot — {ip} — {window_label}"
    elif cadence == "weekly":
        title = f"Weekly attacker snapshot — {ip} — {window_label}"
    else:
        title = f"Attacker profile — {ip} (live)"

    lines: list[str] = [
        f"# {title}",
        "",
        f"- **IP:** `{ip}`",
        f"- **Window:** {window_label}",
        f"- **First seen:** `{first_seen}`",
        f"- **Last seen:** `{last_seen}`",
        f"- **Parsers observed:** {', '.join(parsers) if parsers else '(none)'}",
        f"- **Total sessions:** {_fmt_int(total_sessions)}  •  "
        f"**total events:** {_fmt_int(total_events)}",
    ]
    if country or asn or as_org:
        geo_bits: list[str] = []
        if country:
            geo_bits.append(f"country: {country}")
        if asn:
            geo_bits.append(f"AS{asn}" + (f" ({as_org})" if as_org else ""))
        lines.append(f"- **Geo:** {' • '.join(geo_bits)}")

    # Per-parser activity
    lines.append("")
    lines.append("## Per-parser activity")
    lines.append("")
    for r in rows:
        lines.extend(_render_per_parser_section(r))
        lines.append("")

    # Top credentials, commands, files, urls, domains, signatures, mitre, ports
    lines.extend(_render_credentials_table(rows))
    if lines and lines[-1] != "":
        lines.append("")
    lines.extend(_render_commands_section(rows))
    if lines and lines[-1] != "":
        lines.append("")
    lines.extend(_render_unique_section(rows, "sample_hashes_json", "Files dropped (sha256)"))
    if lines and lines[-1] != "":
        lines.append("")
    lines.extend(_render_unique_section(rows, "sample_urls_json", "URLs referenced"))
    if lines and lines[-1] != "":
        lines.append("")
    lines.extend(_render_unique_section(rows, "sample_domains_json", "Domains referenced"))
    if lines and lines[-1] != "":
        lines.append("")
    lines.extend(_render_unique_section(rows, "sample_signatures_json", "Suricata signatures"))
    if lines and lines[-1] != "":
        lines.append("")
    lines.extend(_render_unique_section(rows, "sample_mitre_json", "MITRE techniques"))
    if lines and lines[-1] != "":
        lines.append("")
    lines.extend(_render_unique_section(rows, "sample_dst_ports_json", "Destination ports probed"))

    body = "\n".join(lines).rstrip() + "\n"

    # Hard cap. Match the stix/builder.py MAX_NOTE_BODY_BYTES truncation
    # marker so analysts recognize the pattern.
    encoded = body.encode("utf-8")
    if len(encoded) > max_bytes:
        body = encoded[: max_bytes - 32].decode("utf-8", errors="ignore") + "\n... [truncated]\n"
    return body


__all__ = [
    "MAX_RAW_DOC_BYTES",
    "SIGHTING_DESC_PREVIEW_CAP",
    "render_attacker_profile_body",
    "render_cowrie_session_note_body",
    "render_cowrie_sighting_description",
    "render_fallback_no_ip_note_body",
    "render_fallback_sighting_description",
    "render_honeytrap_sighting_description",
]
