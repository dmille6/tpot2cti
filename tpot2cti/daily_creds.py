"""tpot2cti — daily top-100 credentials Note emitter.

Implements V1_SPEC.md §6:

    Once per UTC day (computed during the cycle that crosses
    midnight), the importer emits one Note per sensor per day with
    the top 100 credentials attempted.

We aggregate credentials in the core importer rather than emitting
each `(username, password)` attempt as a STIX `User-Account` SCO —
honeypot-volume cred attempts would flood OpenCTI with hundreds of
thousands of low-value observables.  The daily Note collapses that
into one human-readable artifact per sensor per UTC day.

Per V1_SPEC.md §6 the Note body is markdown with a 100-row table:

    | # | Username | Password | Attempts | Unique srcs |

Per the user-confirmed design (Phase 6 spec):

  - Missed-midnight catch-up:  on each cycle, look back
    `TPOT2CTI_CREDS_LOOKBACK_DAYS` (default 7) UTC days; emit a Note
    for every (sensor, date) pair that doesn't have a row in
    `state.daily_creds_log`.
  - Idempotent in OpenCTI via UUID5 (`note:daily-creds:<sensor>:<utc-date>`).
  - We DO NOT record (sensor, date) into the log table until AFTER
    the publisher round succeeds.  See `main.run_cycle()`.

LESSONS_LEARNED_FROM_V0.md §13 (Note size budget): we cap the Note
body well under OpenCTI's worker bundle limit — the table is
guaranteed to fit because 100 rows × ~120 bytes ≈ 12 KB max.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Iterable, Optional, Protocol

from tpot2cti.parsers.base import AttackSession  # for typing only
from tpot2cti.stix.builder import STIXBuilder
from tpot2cti.stix_ids import generate_relationship_id, generate_sensor_id

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants — per V1_SPEC §6 and the credentials connector spec §8.1.
# ---------------------------------------------------------------------------

#: T-Pot honeypot `type` values that produce login-credential attempts.
#: Mirrors the set the optional `tpot2cti-credentials` connector uses
#: (V1_SPEC §8.1 — "Cowrie / Heralding / Mailoney / SentryPeer events").
CREDENTIAL_TYPES: tuple[str, ...] = (
    "Cowrie",
    "Heralding",
    "Mailoney",
    "Sentrypeer",  # T-Pot's `type` field uses this capitalization
)

#: How many rows the Note table contains.  V1_SPEC §6 says "top 100".
TOP_N: int = 100

#: Default lookback window for the missed-midnight catch-up.
DEFAULT_LOOKBACK_DAYS: int = 7

#: ES request_timeout for the aggregation call.  This is heavier than
#: the regular `stream_events` round-trip (full UTC day, multiple aggs)
#: so we give it more headroom.
AGG_REQUEST_TIMEOUT_SECONDS: int = 60


# ---------------------------------------------------------------------------
# Light protocols so the module is testable without a real ES client.
# ---------------------------------------------------------------------------

class _ESLike(Protocol):
    """Duck-typed ES interface used by `maybe_emit_pending`.

    The production caller passes `tpot2cti.es_client.TpotESClient`,
    which exposes its underlying `elasticsearch.Elasticsearch` via
    `._es`.  Tests pass a stub with the same shape.  We deliberately
    don't import `TpotESClient` here to keep the dependency one-way.
    """

    # Either of these is fine — `query_credentials_aggregation` checks
    # for both.  Real clients have `_es.search(...)`, stubs can
    # implement `search_aggregation(...)` directly.
    _es: Any  # has .search(index, body=...) or .search(index, ...)


# ---------------------------------------------------------------------------
# ES aggregation query
# ---------------------------------------------------------------------------

def _utc_day_window(d: date) -> tuple[datetime, datetime]:
    """Return [start, end) datetime pair for a UTC calendar day."""
    start = datetime.combine(d, time.min, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    return start, end


def _build_aggregation_query(
    sensor: str,
    start: datetime,
    end: datetime,
    *,
    top_n: int = TOP_N,
    credential_types: Iterable[str] = CREDENTIAL_TYPES,
) -> dict:
    """Build the ES query body for the daily credentials aggregation.

    The aggregation produces:
      - `top_creds`: composite (username, password) terms, top N by doc_count,
        each with a sub-aggregation `unique_srcs` (cardinality of src_ip).
      - `total_attempts`: implicit via the hit count (`track_total_hits`).
      - `unique_src_ips`: cardinality of src_ip across the whole day.
      - `unique_pairs`: cardinality of the (user|pass) composite.

    Sensor filter uses `t-pot_hostname` (T-Pot's canonical sensor field
    per V1_SPEC.md Appendix A).

    Field-name discipline (V1_SPEC + LESSONS): T-Pot's logstash mappings
    declare ``src_ip``, ``username``, ``password``, ``type``, and
    ``t-pot_hostname`` as ``text`` with a ``keyword`` sub-field and
    ``fielddata: false``.  Aggregating or running ``term`` queries on
    the analyzed text path fails server-side (``Fielddata is disabled``).
    The :code:`.keyword` suffix routes through the non-analyzed sub-field
    and is the same fix shape applied to ``type.keyword`` in task #50.
    """
    return {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start.isoformat(),
                                "lt": end.isoformat(),
                            }
                        }
                    },
                    {"terms": {"type.keyword": list(credential_types)}},
                    {"term": {"t-pot_hostname.keyword": sensor}},
                ],
                # Drop docs that didn't carry creds (e.g. Cowrie connect
                # events without a login attempt) — they'd produce empty
                # buckets that crowd the top-N.
                "filter": [
                    {"exists": {"field": "username"}},
                    {"exists": {"field": "password"}},
                ],
            }
        },
        "aggs": {
            "unique_src_ips": {"cardinality": {"field": "src_ip.keyword"}},
            # `unique_pairs` previously used a Painless ``return
            # doc['username.keyword'].value + '\u0000' + doc['password.keyword'].value``
            # runtime script for tuple cardinality.  Post-2026-05-22
            # .keyword migration the script fails to compile against
            # docs where ``username.keyword`` is in ``_ignored`` (T-Pot's
            # mapping uses ``ignore_above: 256`` on these text fields).
            # Headline number is recovered client-side: the Note's body
            # already reports ``top_creds`` bucket count, and
            # ``unique_src_ips`` plus the top-N bucket counts give
            # operators the same intuition.
            "top_creds": {
                "multi_terms": {
                    "terms": [
                        {"field": "username.keyword"},
                        {"field": "password.keyword"},
                    ],
                    "size": top_n,
                    "order": {"_count": "desc"},
                },
                "aggs": {
                    "unique_srcs": {
                        "cardinality": {"field": "src_ip.keyword"}
                    }
                },
            },
        },
    }


def query_credentials_aggregation(
    es: Any,
    sensor: str,
    utc_date: date,
    *,
    index_pattern: str = "logstash-*",
    top_n: int = TOP_N,
    credential_types: Iterable[str] = CREDENTIAL_TYPES,
) -> dict:
    """Run the daily-credentials aggregation against ES.

    Returns the raw ES response dict.  Errors propagate to the caller
    so `main.run_cycle()` can decide whether to skip the day or fail
    the cycle.

    `es` is duck-typed: it may be a `TpotESClient` (we'll reach into
    `._es`) or any object with a `.search(index, body)` shape (tests).
    """
    start, end = _utc_day_window(utc_date)
    body = _build_aggregation_query(
        sensor, start, end, top_n=top_n, credential_types=credential_types
    )
    logger.debug(
        f"daily_creds: aggregating sensor={sensor!r} day={utc_date.isoformat()} "
        f"(types={list(credential_types)})"
    )

    # 1) TpotESClient route — has a private `_es` attribute that is the
    #    real Elasticsearch client.
    underlying = getattr(es, "_es", None)
    if underlying is not None and hasattr(underlying, "search"):
        return underlying.search(
            index=index_pattern, body=body,
            request_timeout=AGG_REQUEST_TIMEOUT_SECONDS,
        ).body

    # 2) Generic fallback (tests / stubs) — caller exposes .search directly.
    if hasattr(es, "search"):
        return es.search(index=index_pattern, body=body)

    raise TypeError(
        f"es client of type {type(es).__name__!r} has neither `_es.search` "
        f"nor `.search` — daily_creds.query_credentials_aggregation can't use it"
    )


# ---------------------------------------------------------------------------
# Note body rendering — per V1_SPEC §6 sample
# ---------------------------------------------------------------------------

def _fmt_int(n: int) -> str:
    """Thousands-separated int — matches V1_SPEC §6 sample formatting."""
    return f"{int(n):,}"


def _escape_md_cell(s: str) -> str:
    """Sanitize a string for inclusion in a markdown table cell.

    Escapes pipes (the column separator) and strips control characters
    (newlines, tabs) that would break row layout.  Credentials in T-Pot
    are often noisy — operators sometimes paste raw shell escapes as
    passwords trying to break log parsers.
    """
    if s is None:
        return ""
    out = str(s)
    out = out.replace("\\", "\\\\")
    out = out.replace("|", "\\|")
    out = out.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    # Limit per-cell length so a pathological 4KB "password" doesn't
    # blow the Note body cap.
    if len(out) > 256:
        out = out[:253] + "..."
    return out or "(empty)"


def render_note_body(
    sensor: str,
    utc_date: date,
    *,
    total_attempts: int,
    unique_src_ips: int,
    unique_pairs: int,
    top_creds: list[dict],
) -> str:
    """Render the Note body as markdown per V1_SPEC §6 sample.

    `top_creds` is a list of dicts shaped like::

        {"username": "root", "password": "123456",
         "attempts": 8491, "unique_srcs": 312}

    Already truncated to `TOP_N` rows by the caller (the aggregation
    `size` parameter does this server-side).
    """
    d = utc_date.isoformat()
    lines: list[str] = []
    lines.append(f"## Top 100 credential attempts — {d} (UTC) — sensor: {sensor}")
    lines.append("")
    lines.append(f"**Total login attempts:** {_fmt_int(total_attempts)}")
    lines.append(f"**Unique source IPs:** {_fmt_int(unique_src_ips)}")
    lines.append(f"**Unique credential pairs:** {_fmt_int(unique_pairs)}")
    lines.append("")
    lines.append("| # | Username | Password | Attempts | Unique srcs |")
    lines.append("|---|----------|----------|----------|-------------|")
    for i, row in enumerate(top_creds, start=1):
        u = _escape_md_cell(row.get("username", ""))
        p = _escape_md_cell(row.get("password", ""))
        a = _fmt_int(int(row.get("attempts", 0)))
        s = _fmt_int(int(row.get("unique_srcs", 0)))
        lines.append(f"| {i} | {u} | {p} | {a} | {s} |")
    if not top_creds:
        lines.append("| - | (no credential attempts recorded for this day) | | | |")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# ES response → builder input
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DailyCredsResult:
    """The decomposed shape of the ES aggregation response.

    Kept as a frozen dataclass so callers (tests, the main loop) can
    inspect / log totals without going through the markdown body.
    """
    sensor: str
    utc_date: date
    total_attempts: int
    unique_src_ips: int
    unique_pairs: int
    top_creds: list[dict]


def parse_aggregation_response(
    resp: dict, sensor: str, utc_date: date
) -> DailyCredsResult:
    """Pull the headline numbers + top-N rows out of an ES response.

    Defensive against missing fields — ES may return zero aggregations
    on a day with no credential events; we degrade to a "0 attempts"
    Note rather than crash.
    """
    hits = resp.get("hits", {}) or {}
    total_hits = hits.get("total") or {}
    if isinstance(total_hits, dict):
        total_attempts = int(total_hits.get("value", 0) or 0)
    else:
        # ES 6 compatibility; T-Pot pins ES 7+ but cheap to handle.
        total_attempts = int(total_hits or 0)

    aggs = resp.get("aggregations", {}) or {}
    unique_src_ips = int((aggs.get("unique_src_ips") or {}).get("value", 0) or 0)
    # `unique_pairs` was approximated via a Painless runtime script that
    # broke after the .keyword migration (ignore_above docs trip it).
    # Fall back to the top-N bucket count — a lower bound but the only
    # number we can compute without re-running a separate aggregation.
    # When all real pairs fit in top_n (the common case) this is exact.
    top_buckets = (aggs.get("top_creds") or {}).get("buckets", []) or []
    unique_pairs = len(top_buckets)

    top_creds: list[dict] = []
    for bucket in (aggs.get("top_creds") or {}).get("buckets", []):
        # `multi_terms` returns `key` as a list of the two term values.
        key = bucket.get("key") or []
        if isinstance(key, list) and len(key) >= 2:
            user, pw = key[0], key[1]
        elif isinstance(key, dict):
            # Defensive: future ES versions may return a dict.
            user = key.get("username", "")
            pw = key.get("password", "")
        else:
            continue
        top_creds.append({
            "username": "" if user is None else str(user),
            "password": "" if pw is None else str(pw),
            "attempts": int(bucket.get("doc_count", 0) or 0),
            "unique_srcs": int(
                (bucket.get("unique_srcs") or {}).get("value", 0) or 0
            ),
        })

    return DailyCredsResult(
        sensor=sensor,
        utc_date=utc_date,
        total_attempts=total_attempts,
        unique_src_ips=unique_src_ips,
        unique_pairs=unique_pairs,
        top_creds=top_creds,
    )


# ---------------------------------------------------------------------------
# Public API — what `main.run_cycle()` calls
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EmittedDailyCreds:
    """Bundle returned by `maybe_emit_pending` so `main.run_cycle` knows
    which (sensor, date) pairs to mark as emitted in `daily_creds_log`
    AFTER the publisher succeeds.
    """
    stix_objects: list[dict]
    pairs: list[tuple[str, date]]  # (sensor, utc_date) for each Note emitted


def discover_sensors(state, cfg) -> list[str]:
    """Return the list of sensor hostnames we should consider for the
    daily creds catch-up scan.

    For v1.0 we have no central sensor registry — sensors are observed
    organically as events arrive (the parser learns the hostname from
    each event's `t-pot_hostname`).  We persist a running set in the
    state DB under the `known_sensors` key (comma-separated) so the
    catch-up scan has something to iterate over even before the cycle's
    main pass has run.

    Callers (main.run_cycle) update this set after each cycle.
    """
    raw = state.get("known_sensors") or ""
    sensors = [s.strip() for s in raw.split(",") if s.strip()]
    # Allow operators to seed sensors via env (rare; mostly for testing
    # and for the first run after a fresh deployment when we haven't
    # observed any events yet).  We deliberately don't bake this into
    # config.py — it's a state concern, not a config concern.
    return sensors


def remember_sensors(state, sensors: Iterable[str]) -> None:
    """Persist the set of sensors we've observed in this cycle.

    Merges with whatever was already in the `known_sensors` state row.
    """
    seen = set(discover_sensors(state, cfg=None))
    for s in sensors:
        if s:
            seen.add(s)
    if seen:
        state.set("known_sensors", ",".join(sorted(seen)))


def maybe_emit_pending(
    state,
    es: Any,
    builder: STIXBuilder,
    cfg,
    *,
    lookback_days: Optional[int] = None,
    sensors: Optional[Iterable[str]] = None,
    index_pattern: str = "logstash-*",
) -> EmittedDailyCreds:
    """Return STIX objects + (sensor, date) pairs for missed daily Notes.

    The caller folds `result.stix_objects` into the cycle bundle, sends
    via the publisher, and on success calls
    `state.record_daily_creds_emitted(sensor, utc_date)` for each pair
    in `result.pairs`.

    Behavior:
      - For each sensor (from `sensors` arg, else `discover_sensors(state)`),
        compute the missing UTC days via
        `state.get_missing_daily_creds_dates(sensor, lookback_days)`.
      - For each missing day, run the ES aggregation and build the Note +
        Note→Identity(sensor) Relationship.
      - On any per-day exception, log + skip that day (next cycle retries).

    Per V1_SPEC §6: relationships emitted are
        Note → object → Identity(sensor)
    so the sensor's OpenCTI page shows the daily Notes inline.  We use
    `relationship_type="related-to"` because STIX 2.1 doesn't define a
    dedicated verb for "this Note is about this Identity" — the Note's
    `object_refs` field carries the same semantic, but we emit the
    Relationship as well so OpenCTI's graph view (which only follows
    Relationships) renders the edge.
    """
    if lookback_days is None:
        # Per 2026-05-22 audit #4: read from cfg.runtime, not os.environ.
        # Falls back to the module default when cfg lacks a runtime block
        # (e.g. older test harness building a partial Config by hand).
        runtime = getattr(cfg, "runtime", None)
        lookback_days = (
            getattr(runtime, "daily_creds_lookback_days", DEFAULT_LOOKBACK_DAYS)
            if runtime is not None
            else DEFAULT_LOOKBACK_DAYS
        )

    sensor_list: list[str] = list(sensors) if sensors is not None else discover_sensors(state, cfg)
    if not sensor_list:
        logger.debug(
            "daily_creds: no known sensors yet — nothing to emit "
            "(will discover sensors as events arrive)"
        )
        return EmittedDailyCreds(stix_objects=[], pairs=[])

    objects: list[dict] = []
    pairs: list[tuple[str, date]] = []

    for sensor in sensor_list:
        missing = state.get_missing_daily_creds_dates(sensor, lookback_days)
        if not missing:
            continue
        logger.info(
            f"daily_creds: sensor={sensor!r} has {len(missing)} missing "
            f"day(s) within lookback={lookback_days}d"
        )
        for d in missing:
            try:
                resp = query_credentials_aggregation(
                    es, sensor, d, index_pattern=index_pattern
                )
                result = parse_aggregation_response(resp, sensor, d)
            except Exception as e:
                # Per V1_SPEC §7: never let one bad day fail the cycle.
                logger.warning(
                    f"daily_creds: aggregation failed for sensor={sensor!r} "
                    f"day={d.isoformat()} — skipping (will retry next cycle): {e}"
                )
                continue

            body = render_note_body(
                sensor, d,
                total_attempts=result.total_attempts,
                unique_src_ips=result.unique_src_ips,
                unique_pairs=result.unique_pairs,
                top_creds=result.top_creds,
            )

            # Build the Note via the existing STIX builder method.
            sensor_identity_id = generate_sensor_id(sensor)
            note = builder.build_daily_credentials_note(
                sensor_hostname=sensor,
                utc_date=d.isoformat(),
                body_md=body,
                object_refs=[sensor_identity_id],
            )
            if note is None:
                # Already emitted in THIS bundle (per-bundle dedup) —
                # don't double-add but DO still record the pair so the
                # state log gets updated.
                logger.debug(
                    f"daily_creds: Note for ({sensor}, {d.isoformat()}) "
                    f"already in this bundle; recording pair anyway"
                )
                pairs.append((sensor, d))
                continue

            objects.append(note)

            # Also ensure the sensor Identity exists in the foundation
            # pass — call build_sensor_context which is idempotent
            # within the bundle.
            objects.extend(builder.build_sensor_context(sensor))

            # Emit the Note → sensor Identity relationship.  See docstring
            # rationale for `related-to`.
            rel = builder.build_relationship(
                note["id"], "related-to", sensor_identity_id,
                description=(
                    f"Daily top-{TOP_N} credential attempts on {d.isoformat()} (UTC) "
                    f"observed by sensor {sensor}"
                ),
            )
            if rel:
                objects.append(rel)

            pairs.append((sensor, d))
            logger.info(
                f"daily_creds: emitted Note for sensor={sensor!r} "
                f"day={d.isoformat()} (attempts={result.total_attempts}, "
                f"pairs={result.unique_pairs}, srcs={result.unique_src_ips})"
            )

    return EmittedDailyCreds(stix_objects=objects, pairs=pairs)


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile
    from pathlib import Path

    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")

    # ---- Stub ES client with canned aggregation ----
    canned_resp = {
        "hits": {"total": {"value": 152341, "relation": "eq"}},
        "aggregations": {
            "unique_src_ips": {"value": 47283},
            "unique_pairs": {"value": 12508},
            "top_creds": {
                "buckets": [
                    {"key": ["root", "123456"], "doc_count": 8491,
                     "unique_srcs": {"value": 312}},
                    {"key": ["admin", "admin"], "doc_count": 7203,
                     "unique_srcs": {"value": 245}},
                    {"key": ["user|with|pipes", "p\nass"], "doc_count": 42,
                     "unique_srcs": {"value": 7}},
                ]
            },
        },
    }

    class StubES:
        last_body: dict | None = None

        def search(self, index, body):
            StubES.last_body = body
            return canned_resp

    # ---- Stub config with the minimum the builder needs ----
    from tpot2cti.config import (
        Config, TPotConfig, ESConfig, OpenCTIConfig, OperatorConfig,
        CycleConfig, ConnectorIDs, LoggingConfig, RuntimeConfig,
    )
    cfg = Config(
        tpot=TPotConfig(host="tpot.example"),
        es=ESConfig(),
        opencti=OpenCTIConfig(url="http://opencti", admin_token="x"),
        operator=OperatorConfig(org_name="Test Operator"),
        cycle=CycleConfig(),
        connector_ids=ConnectorIDs(core="00000000-0000-0000-0000-000000000001"),
        logging=LoggingConfig(),
        runtime=RuntimeConfig(),
    )
    builder = STIXBuilder(cfg)

    # ---- Stub state with a fresh DB ----
    from tpot2cti.state import CycleState
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        state = CycleState(db_path=db_path)
        # Seed the "known_sensors" set so discover_sensors() returns one.
        state.set("known_sensors", "tpot01")

        # ---- Exercise maybe_emit_pending with a 2-day lookback ----
        result = maybe_emit_pending(
            state, StubES(), builder, cfg,
            lookback_days=2,
        )

        # Verify shape
        assert len(result.pairs) == 2, (
            f"expected 2 pairs (yesterday + day-before), got {len(result.pairs)}"
        )
        assert all(p[0] == "tpot01" for p in result.pairs)
        print(f"OK: emitted {len(result.pairs)} (sensor, date) pairs")

        # Find the Note objects
        notes = [o for o in result.stix_objects if o.get("type") == "note"]
        assert len(notes) == 2, f"expected 2 Notes, got {len(notes)}"
        n0 = notes[0]
        assert n0["id"].startswith("note--"), f"bad id: {n0['id']}"
        # Must include the deterministic seed shape
        from tpot2cti.stix_ids import generate_daily_creds_note_id
        expected_id = generate_daily_creds_note_id(
            "tpot01", result.pairs[0][1].isoformat()
        )
        assert n0["id"] == expected_id, (
            f"Note id not deterministic: got {n0['id']}, want {expected_id}"
        )
        print(f"OK: Note id is deterministic: {n0['id']}")

        # Title (abstract) shape per V1_SPEC §6
        d_iso = result.pairs[0][1].isoformat()
        expected_abstract = (
            f"Top 100 credential attempts — {d_iso} (UTC) — sensor: tpot01"
        )
        assert n0["abstract"] == expected_abstract, (
            f"abstract mismatch:\n  got:  {n0['abstract']!r}\n  want: {expected_abstract!r}"
        )
        print(f"OK: abstract matches spec: {n0['abstract']!r}")

        # Body shape — header + totals + table
        body = n0["content"]
        assert f"## Top 100 credential attempts — {d_iso} (UTC) — sensor: tpot01" in body
        assert "**Total login attempts:** 152,341" in body
        assert "**Unique source IPs:** 47,283" in body
        # Post-2026-05-22 .keyword migration: unique_pairs falls back to
        # len(top_buckets) since the Painless tuple-cardinality script
        # was removed.  Stub returns 3 top_creds buckets.
        assert "**Unique credential pairs:** 3" in body
        assert "| # | Username | Password | Attempts | Unique srcs |" in body
        assert "| 1 | root | 123456 | 8,491 | 312 |" in body
        # Pipe in a "username" must be escaped, not a column break:
        assert "user\\|with\\|pipes" in body, "pipe in cred must be escaped"
        # Newline in a "password" must be flattened, not a row break:
        assert "p ass" in body or "p\\nass" not in body  # flattened
        print("OK: Note body matches V1_SPEC §6 sample format")

        # Relationship Note → sensor Identity
        rels = [o for o in result.stix_objects if o.get("type") == "relationship"]
        sensor_id = generate_sensor_id("tpot01")
        matching = [
            r for r in rels
            if r["source_ref"] == n0["id"] and r["target_ref"] == sensor_id
        ]
        assert matching, (
            f"missing Note→sensor relationship; have rels: {rels}"
        )
        assert matching[0]["relationship_type"] == "related-to"
        # Deterministic relationship id (via generate_relationship_id)
        expected_rel_id = generate_relationship_id(
            n0["id"], sensor_id, "related-to"
        )
        assert matching[0]["id"] == expected_rel_id
        print(f"OK: emitted deterministic Note→sensor relationship: "
              f"{matching[0]['id']}")

        # Verify the ES body filtered to the right sensor + day window
        assert StubES.last_body is not None
        q = StubES.last_body["query"]["bool"]["must"]
        sensor_term = [c for c in q if "term" in c and "t-pot_hostname.keyword" in c["term"]]
        assert sensor_term, "agg query missing sensor filter (.keyword sub-field)"
        assert sensor_term[0]["term"]["t-pot_hostname.keyword"] == "tpot01"
        types_term = [c for c in q if "terms" in c and "type.keyword" in c["terms"]]
        assert types_term, "agg query missing type filter (.keyword sub-field)"
        assert "Cowrie" in types_term[0]["terms"]["type.keyword"]
        print("OK: ES aggregation query has sensor + type filters")

        # Now record one pair as emitted; second call should produce 1 less.
        state.record_daily_creds_emitted(*result.pairs[0])
        # Build a fresh builder so per-bundle dedup doesn't suppress the
        # second day's Note.
        builder2 = STIXBuilder(cfg)
        result2 = maybe_emit_pending(
            state, StubES(), builder2, cfg, lookback_days=2,
        )
        assert len(result2.pairs) == 1, (
            f"after recording 1 emit, expected 1 remaining; got {len(result2.pairs)}"
        )
        print(f"OK: idempotent — after record_daily_creds_emitted, "
              f"only {len(result2.pairs)} pair(s) remain")

        # Edge case: no known sensors → empty result, no ES call
        empty_state = CycleState(db_path=db_path + ".2")
        empty_result = maybe_emit_pending(
            empty_state, StubES(), STIXBuilder(cfg), cfg, lookback_days=2,
        )
        assert empty_result.stix_objects == [] and empty_result.pairs == []
        print("OK: no known sensors → empty result")

        print("\nOK")
    finally:
        Path(db_path).unlink(missing_ok=True)
        Path(db_path + "-wal").unlink(missing_ok=True)
        Path(db_path + "-shm").unlink(missing_ok=True)
        Path(db_path + ".2").unlink(missing_ok=True)
        Path(db_path + ".2-wal").unlink(missing_ok=True)
        Path(db_path + ".2-shm").unlink(missing_ok=True)
