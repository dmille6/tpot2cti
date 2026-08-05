"""Label attacker IPs found on free, no-signup bulk blocklists (Lane A).

Lane A downloads a list once and matches it locally, so it costs **zero
per-object API calls** and scales to any number of observables. That is what
makes the no-signup tier genuinely useful rather than a crippled demo.

**Honest expectations, measured against 14,715 real attacker IPs (2026-08-05):**

| source | matched | note |
|---|---|---|
| FireHOL level 1 | 5.8% | an earlier claim of 24.5% in the spec was wrong |
| Spamhaus DROP | 2.5% | a **strict subset** of FireHOL — adds attribution, not coverage |
| Tor exit list | 0.4% | |
| Feodo Tracker | ~0 | 5 entries, 4 offline; kept because a hit is high value |
| **union** | **6.2%** | 912 addresses |

So this module is a *context* source, not a detector. Its real contribution is
that **550 of those 912 hits land on addresses `noisefloor` left unlabelled** —
for those, a blocklist is the only signal we have. Blocklist membership barely
correlates with our own behavioural classification (9.6% of fan-out addresses,
7.7% of substantive ones, 5.2% of unlabelled ones), which is exactly why it is
worth having: it is independent evidence, not a restatement.

**Health question for this lane: "is the list stale?"** That is different from
Lane B's "is the quota exhausted?" and Lane C's "is the window populated?",
which is why the lanes are separate processes. A blocklist runner that fails to
refresh keeps matching happily against a frozen list and looks perfectly
healthy while its answers rot.

Runs as its own process::

    python -m tpot2cti.enrich.blocklists
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from tpot2cti.config import ConfigError, load_config
from tpot2cti.enrich.sources import (
    Source,
    SourceParseError,
    selected_sources,
)
from tpot2cti.enrich.sweep import ActivityReadError, SweepCursor, read_activity
from tpot2cti.health import HealthServer, parse_iso_duration_seconds
from tpot2cti.log import restore_logging, setup_logging
from tpot2cti.publisher import Publisher
from tpot2cti.state import CycleState
from tpot2cti.stix.builder import STIXBuilder
from tpot2cti.stix.builder import normalize_malware_family
from tpot2cti.stix_ids import attacker_ip_observable_id, generate_malware_id

logger = logging.getLogger(__name__)

SOURCES_ENV = "ENRICH_BLOCKLIST_SOURCES"
DEFAULT_SOURCES = "firehol,spamhaus,tor,feodo"

#: How recently an IP must have been active to be considered. Same semantics
#: as noisefloor: a row-recency filter, not a metric window.
WINDOW_HOURS = max(1, int(os.environ.get("ENRICH_BLOCKLIST_ACTIVE_WITHIN_HOURS", "168")))

#: Sweep page size. Floored at 1 — see enrich/sweep.read_activity for why a
#: non-positive value is catastrophic in two different directions.
MAX_PER_CYCLE = max(1, int(os.environ.get("ENRICH_BLOCKLIST_MAX_PER_CYCLE", "2000")))

STUCK_PAGE_ALERT = max(1, int(os.environ.get("ENRICH_BLOCKLIST_STUCK_PAGE_ALERT", "3")))

STATE_DB_ENV = "ENRICH_BLOCKLIST_STATE_DB"

#: A list older than this is refused for matching. This is the module's whole
#: health question: matching against a frozen list is worse than not matching,
#: because it looks like work. The default allows two missed daily refreshes
#: before answers are withheld.
MAX_LIST_AGE_HOURS = max(1, int(os.environ.get("ENRICH_BLOCKLIST_MAX_AGE_HOURS", "72")))

FETCH_TIMEOUT = max(5, int(os.environ.get("ENRICH_BLOCKLIST_FETCH_TIMEOUT", "60")))

_USER_AGENT = "tpot2cti/2.0 (+https://github.com/dmille6/tpot2cti)"


class ListTooStaleError(RuntimeError):
    """Every configured source is older than `MAX_LIST_AGE_HOURS`.

    Raised rather than matching anyway. A stale-list match is a confident
    answer derived from expired evidence, and it is indistinguishable from a
    fresh one once it reaches the graph.
    """


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def fetch_source(src: Source, *, timeout: int = FETCH_TIMEOUT) -> tuple:
    """Download and parse one source. Returns `(CidrSet, extra)`.

    Raises `SourceParseError` on a transport failure, a non-200, a body that
    will not parse, or a suspiciously short result. That last check matters:
    these feeds are plain text over HTTP, so a captive portal, a rate-limit
    page or an error body parses to *zero* networks perfectly happily, and the
    module would then quietly un-label the internet.
    """
    req = urllib.request.Request(src.url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise SourceParseError(f"{src.key}: HTTP {resp.status}")
            body = resp.read().decode("utf-8", errors="replace")
    except SourceParseError:
        raise
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise SourceParseError(f"{src.key}: fetch failed: {exc}") from exc

    try:
        cidrs, extra = src.parse(body)
    except SourceParseError:
        raise
    except Exception as exc:
        # A parser raising anything else (a renamed field yielding a TypeError,
        # say) would escape past refresh_lists' handler and take down the other
        # three feeds — this function promises per-source isolation, so it has
        # to actually hold for unexpected exceptions too.
        raise SourceParseError(
            f"{src.key}: parser raised {type(exc).__name__}: {exc}") from exc
    if len(cidrs) < src.min_entries:
        raise SourceParseError(
            f"{src.key}: parsed only {len(cidrs)} entries, below the floor of "
            f"{src.min_entries} — the feed has probably changed shape or served "
            f"an error page. Refusing to match against it."
        )
    return cidrs, extra


def refresh_lists(sources: list[Source], state: CycleState, *,
                  previous: Optional[dict] = None,
                  timeout: int = FETCH_TIMEOUT) -> tuple[dict, list[str]]:
    """Fetch every source. Returns `(lists, failed_keys)`.

    A source that fails **keeps its previous copy** rather than vanishing, so
    one flaky feed cannot silently remove a whole dimension of matching. It
    also keeps its previous `bl_fetched_at`, so it goes on aging toward the
    staleness cliff and is eventually dropped by `run_cycle` — degrading to
    "refused because stale" rather than "quietly answering from an old copy".

    Merging into `previous` is the point. An earlier version returned only the
    successes and the caller did `lists = refresh_lists(...) or lists`, which
    replaced the dict wholesale: a single transient failure dropped that
    source's good data entirely, contradicting this docstring.
    """
    out: dict[str, dict] = dict(previous or {})
    failed: list[str] = []
    for src in sources:
        try:
            cidrs, extra = fetch_source(src, timeout=timeout)
            out[src.key] = {"cidrs": cidrs, "extra": extra,
                            "fetched_at": datetime.now(timezone.utc), "fresh": True}
            state.set(f"bl_fetched_at:{src.key}",
                      out[src.key]["fetched_at"].isoformat())
            logger.info("blocklists: %s refreshed — %d entries", src.key, len(cidrs))
        except SourceParseError as exc:
            failed.append(src.key)
            kept = "keeping previous copy" if src.key in out else "no previous copy"
            logger.error("blocklists: %s refresh FAILED (%s): %s",
                         src.key, kept, exc)
    return out, failed


def age_hours(state: CycleState, key: str) -> Optional[float]:
    raw = state.get(f"bl_fetched_at:{key}")
    if not raw:
        return None
    try:
        then = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - then).total_seconds() / 3600.0
    if age < -1.0:
        # A timestamp meaningfully in the future means clock skew or a corrupt
        # value. Reading it as "negative hours old" would make the list pass
        # the staleness cliff forever — an unknown silently becoming the most
        # confident possible answer.
        logger.error("blocklists: %s has a fetch timestamp %.1fh in the future "
                     "— treating as unusable rather than infinitely fresh",
                     key, -age)
        return None
    return max(0.0, age)


# ---------------------------------------------------------------------------
# Matching + build
# ---------------------------------------------------------------------------

def _is_ip(raw_ip) -> bool:
    try:
        ipaddress.ip_address(str(raw_ip))
        return True
    except ValueError:
        return False


def match_ip(raw_ip: str, lists: dict) -> list[tuple[str, dict]]:
    """Return `[(source_key, extra), …]` for every list containing this IP."""
    try:
        ip = ipaddress.ip_address(str(raw_ip))
    except ValueError:
        return []
    hits = []
    for key, entry in lists.items():
        if ip in entry["cidrs"]:
            hits.append((key, entry["extra"]))
    return hits


def build_objects(builder: STIXBuilder, raw_ip: str,
                  hits: list[tuple[str, dict]], sources_by_key: dict) -> list[dict]:
    """Labels onto the observable CORE already created, plus C2 promotion.

    Never emits a floating SDO: a Feodo hit produces a Malware SDO *and* the
    edge tying it to the address. The predecessor created ~1,600 edgeless
    Spamhaus Indicators — unqueryable clutter, worse than a label.
    """
    obs_id = attacker_ip_observable_id(raw_ip)
    if not obs_id:
        return []
    obj = builder.build_ip_observable(str(raw_ip))
    if not obj:
        return []

    labels = sorted({sources_by_key[k].label for k, _ in hits})
    obj["x_opencti_labels"] = sorted(
        set(list(obj.get("x_opencti_labels") or []) + labels)
    )
    # Deliberately NO description. noisefloor's convention is labels-only, the
    # publisher sends update=False, and a second list hit later would rewrite
    # the text to name only the newer source — losing the first either way.
    out = [obj]

    # Feodo online C2 → Malware SDO + edge. Only promotes when the feed names
    # a family; an unnamed C2 gets the label and nothing more.
    for key, extra in hits:
        if not sources_by_key[key].promotes_malware:
            continue
        family = (extra.get("families") or {}).get(str(raw_ip))
        if not family:
            continue
        fam = normalize_malware_family(family)
        if not fam:
            continue
        mal = builder.build_malware(
            family, source="feodo",
            description=(f"Malware family {fam!r} attributed from abuse.ch Feodo "
                         f"Tracker's online C2 list. NOT from a captured sample: "
                         f"this address was matched against a downloaded "
                         f"blocklist."),
        )
        # `mal` is None when the builder already emitted this family THIS cycle.
        # The edge must still be built — a second address sharing a family would
        # otherwise silently lose its relationship, the same shape as the
        # first-matching-label bug, and invisible in the counters.
        if mal:
            out.append(mal)
        rel = builder.build_relationship(
            obs_id, "related-to", generate_malware_id(fam),
            description=(f"Address listed as an online {family} C2 by abuse.ch "
                         f"Feodo Tracker at match time."),
        )
        if rel:
            out.append(rel)
    return out


# ---------------------------------------------------------------------------
# Cycle
# ---------------------------------------------------------------------------

def run_cycle(cfg, state: CycleState, core_db: str, builder_factory,
              publisher, lists: dict, sources_by_key: dict) -> dict:
    cycle_id = state.start_cycle()
    started = time.monotonic()
    state.heartbeat()

    # Unknown age fails CLOSED. `(age or 0)` would read a missing or
    # unparseable fetch timestamp as "zero hours old", i.e. perfectly fresh —
    # the safe-looking default that turns an unknown into a confident answer.
    usable = {}
    for k, v in lists.items():
        age = age_hours(state, k)
        if age is None:
            logger.error("blocklists: %s has no usable fetch timestamp — "
                         "treating as stale rather than assuming it is fresh", k)
            continue
        if age <= MAX_LIST_AGE_HOURS:
            usable[k] = v
    dropped = sorted(set(lists) - set(usable))
    if dropped:
        logger.error("blocklists: dropping stale source(s) %s (older than %dh) "
                     "— stale matches are confident answers from expired "
                     "evidence", ", ".join(dropped), MAX_LIST_AGE_HOURS)
    if not usable:
        # Refusing to match is the correct answer, but it is NOT a successful
        # cycle. Matching zero addresses because every list is stale must never
        # read the same as matching zero because the internet was quiet.
        msg = "every configured blocklist is missing or stale — nothing matched"
        logger.error("blocklists cycle %s: %s", cycle_id, msg)
        state.record_cycle(cycle_id, success=False, events_read=0, events_parsed=0,
                           events_dropped=0, sdos_emitted=0, errors_count=1,
                           duration_seconds=time.monotonic() - started)
        return {"cycle_id": cycle_id, "ips": 0, "matched": 0, "objects": 0,
                "publish_ok": False, "stale": True, "error": msg}

    sweep = SweepCursor(state, "bl", stuck_alert=STUCK_PAGE_ALERT)
    cursor = sweep.position()
    try:
        rows = read_activity(core_db, after_ip=cursor,
                             limit=MAX_PER_CYCLE, window_hours=WINDOW_HOURS)
    except ActivityReadError as exc:
        logger.error("blocklists cycle %s: %s", cycle_id, exc)
        state.record_cycle(cycle_id, success=False, events_read=0, events_parsed=0,
                           events_dropped=0, sdos_emitted=0, errors_count=1,
                           duration_seconds=time.monotonic() - started)
        return {"cycle_id": cycle_id, "ips": 0, "matched": 0, "objects": 0,
                "publish_ok": False, "read_error": str(exc)}

    builder = builder_factory()
    objects: list[dict] = [
        builder.build_operator_identity(),
        builder.build_tlp_marking(),
    ]
    n_foundation = len(objects)
    pending_marks: list[tuple[str, str]] = []
    matched = already = 0
    per_source: dict[str, int] = {}

    malformed = 0
    for row in rows:
        ip = row.get("src_ip")
        if not _is_ip(ip):
            # CORE's telemetry really does contain non-addresses: H0neytr4p
            # stores raw obfuscated Log4Shell JNDI payloads in src_ip (16 in
            # the live window). Skipping is right; skipping invisibly makes
            # them indistinguishable from "matched no list".
            malformed += 1
            continue
        hits = match_ip(ip, usable)
        if not hits:
            continue
        fresh = [(k, e) for k, e in hits if state.get(f"bl:{ip}:{k}") != "1"]
        if not fresh:
            already += 1
            continue
        objs = build_objects(builder, ip, fresh, sources_by_key)
        if not objs:
            continue
        matched += 1
        for k, _ in fresh:
            per_source[k] = per_source.get(k, 0) + 1
            pending_marks.append((f"bl:{ip}:{k}", "1"))
        objects.extend(objs)

    publish_ok = True
    if len(objects) > n_foundation:
        try:
            result = publisher.publish(objects, cycle_id=str(cycle_id))
            errs = list(getattr(result, "errors", []) or [])
            publish_ok = not errs
            if errs:
                logger.error("blocklists: publish reported %d error(s): %s",
                             len(errs), errs[:3])
        except Exception as exc:
            publish_ok = False
            logger.exception("blocklists: publish failed: %s", exc)
    else:
        logger.info("blocklists cycle %s: no new matches in this page", cycle_id)

    swept = False
    if not publish_ok:
        sweep.hold(cursor)
    else:
        for k, v in pending_marks:
            state.set(k, v)
        swept = sweep.advance(rows, MAX_PER_CYCLE)

    duration = time.monotonic() - started
    logger.info(
        "blocklists cycle %s complete in %.1fs — ips=%d matched=%d already=%d "
        "malformed=%d objects=%d per_source=%s publish_ok=%s cursor=%s "
        "sweep_complete=%s",
        cycle_id, duration, len(rows), matched, already, malformed,
        len(objects) - n_foundation, json.dumps(per_source, sort_keys=True),
        publish_ok, (state.get(sweep.cursor_key) or "<start>"), swept,
    )
    state.record_cycle(
        cycle_id, success=publish_ok, events_read=len(rows), events_parsed=matched,
        events_dropped=len(rows) - matched, sdos_emitted=len(objects),
        errors_count=0 if publish_ok else 1, duration_seconds=duration,
    )
    return {"cycle_id": cycle_id, "ips": len(rows), "matched": matched,
            "already": already, "malformed": malformed,
            "objects": len(objects) - n_foundation,
            "per_source": per_source, "publish_ok": publish_ok,
            "sweep_complete": swept, "stale": False,
            "duration_seconds": round(duration, 3)}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> int:
    setup_logging(connector_name="tpot2cti-blocklists")
    try:
        cfg = load_config()
    except ConfigError as exc:
        logger.error("blocklists: configuration error: %s", exc)
        return 2
    try:
        sources = selected_sources(os.environ.get(SOURCES_ENV, DEFAULT_SOURCES))
    except ValueError as exc:
        logger.error("blocklists: %s", exc)
        return 2
    if not sources:
        logger.error("blocklists: no sources configured (%s is empty)", SOURCES_ENV)
        return 2
    sources_by_key = {s.key: s for s in sources}

    interval = parse_iso_duration_seconds(
        os.environ.get("ENRICH_BLOCKLIST_INTERVAL", "PT1H"))
    refresh_every = parse_iso_duration_seconds(
        os.environ.get("ENRICH_BLOCKLIST_REFRESH", "PT24H"))

    core_db = str(cfg.runtime.state_db_path)
    own_db = os.environ.get(
        STATE_DB_ENV,
        str(os.path.join(os.path.dirname(str(cfg.runtime.state_db_path)),
                         "blocklists.db")),
    )
    logger.info(
        "tpot2cti-blocklists starting — sources=%s window=%dh interval=%ds "
        "refresh=%ds max_age=%dh core_db=%s (read-only) own_db=%s",
        ",".join(s.key for s in sources), WINDOW_HOURS, int(interval),
        int(refresh_every), MAX_LIST_AGE_HOURS, core_db, own_db,
    )
    state = CycleState(own_db)

    # Bind /health BEFORE connecting: _connect_opencti waits patiently for a
    # cold platform (up to 300s) while the image's HEALTHCHECK has a 60s start
    # period, so connecting first makes a warming module look unhealthy.
    health = HealthServer(
        state, None, bind=os.environ.get("ENRICH_BLOCKLIST_HEALTH_BIND", ":8080"),
        cycle_interval_seconds=interval,
    )
    health.start_in_background()

    from tpot2cti.main import _connect_opencti
    opencti = _connect_opencti(cfg, connector_id=cfg.connector_ids.core)
    restore_logging()
    publisher = Publisher(opencti, state=state,
                          indexing_delay_seconds=cfg.cycle.indexing_delay_seconds)

    stopping = False

    def _stop(signum, _frame):
        nonlocal stopping
        logger.info("blocklists: signal %s received, finishing current cycle", signum)
        stopping = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    # Retry sooner than the full refresh interval when a fetch fails: a failed
    # source keeps aging toward the staleness cliff, so waiting a whole day
    # after a transient blip spends that budget for nothing.
    retry_after = min(refresh_every, max(interval, 300.0))
    lists: dict = {}
    next_refresh = 0.0
    pending = list(sources)   # what the next fetch attempt covers
    while not stopping:
        try:
            if time.monotonic() >= next_refresh:
                # Retry only the sources that failed. Re-downloading all four
                # every 5 minutes after one flaky feed is 24x/day of needless
                # traffic against volunteer-run infrastructure.
                lists, failed = refresh_lists(pending, state, previous=lists)
                pending = ([s for s in sources if s.key in failed] if failed
                           else list(sources))
                next_refresh = time.monotonic() + (retry_after if failed
                                                   else refresh_every)
                if failed:
                    logger.warning("blocklists: %d source(s) failed to refresh "
                                   "(%s) — retrying in %ds rather than waiting "
                                   "the full %ds refresh interval",
                                   len(failed), ",".join(failed),
                                   int(retry_after), int(refresh_every))
            summary = run_cycle(cfg, state, core_db, lambda: STIXBuilder(cfg),
                                publisher, lists, sources_by_key)
            if summary.get("sweep_complete"):
                logger.info("blocklists: sweep complete — next cycle restarts "
                            "the pass from the beginning of the window")
            elif not summary.get("publish_ok"):
                logger.warning("blocklists: sweep NOT advancing — cursor held "
                               "at %r pending a successful publish",
                               state.get("bl_sweep_cursor") or "<start>")
        except Exception as exc:
            logger.exception("blocklists: cycle failed: %s", exc)
        for _ in range(int(interval)):
            if stopping:
                break
            time.sleep(1)
    health.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
