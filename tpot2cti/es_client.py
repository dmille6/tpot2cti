"""
es_client.py — Elasticsearch client wrapper for tpot2cti core importer.

Implements V1_SPEC.md §3 (core importer cycle, step 1):
    "Query T-Pot ES for events since last_run — via logstash-* index
     pattern — filtered by @timestamp range — paginated with
     search_after."

This module is intentionally stateless. The caller (the main cycle
loop) owns the `last_run` cursor; state persistence lives in
`state.py`. We just take a [start, end) datetime range and yield
documents.

Error-handling policy per V1_SPEC.md §7:
    - ES query timeout      → retry once, then raise
    - Connection drop       → log + raise (caller backs off)
    - Don't swallow errors silently.

Sync-only (no asyncio) per LESSONS §2.4 / V2_HANDOFF §2.4.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Iterator

from elasticsearch import Elasticsearch
from elasticsearch import (
    ApiError,
    ConnectionError as ESConnectionError,
    ConnectionTimeout,
    TransportError,
)

logger = logging.getLogger(__name__)


def _iso_utc(ts: datetime) -> str:
    """
    Format a datetime as an ISO 8601 string in UTC with a Z suffix.

    Elasticsearch's range query accepts ISO 8601 strings and treats
    the trailing `Z` as UTC. Naive datetimes are assumed UTC (the
    cycle loop always works in UTC), and aware datetimes are
    converted to UTC before formatting.
    """
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    else:
        ts = ts.astimezone(timezone.utc)
    # Drop microseconds for cleaner logs; ES doesn't care about sub-ms here.
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


class TpotESClient:
    """
    Thin wrapper around the official `elasticsearch` Python client,
    tuned for the queries tpot2cti makes against T-Pot's logstash
    indices.

    The client is intentionally narrow: it only exposes the operations
    the core importer actually needs (ping, count, stream by time
    range). It does not own any state.
    """

    def __init__(
        self,
        host: str = "tunnel",
        port: int = 64298,
        scheme: str = "http",
        username: str | None = None,
        password: str | None = None,
        verify_certs: bool = False,
        request_timeout: int = 30,
    ) -> None:
        """
        Connect to T-Pot's Elasticsearch.

        Defaults match the docker-compose topology described in
        V1_SPEC.md §2: the `tpot-tunnel` (autossh) container exposes
        T-Pot's ES on the shared Docker network as `tunnel:64298`
        over plain HTTP (the SSH transport provides the security).

        Args:
            host: hostname of the ES endpoint (default: `tunnel`, the
                autossh container name on the shared compose network).
            port: ES port (default: 64298, T-Pot's published ES port).
            scheme: `http` or `https`. Plain HTTP is the default because
                the SSH tunnel already encrypts the transport.
            username: optional basic-auth username for ES.
            password: optional basic-auth password for ES.
            verify_certs: whether to verify TLS certs (only relevant if
                `scheme="https"`). Defaults to False — the tunnel hides
                the connection from the network, and T-Pot ships with a
                self-signed cert by default.
            request_timeout: per-request timeout in seconds. 30s is the
                default; cycles that need a longer count/scroll override
                per-call via the underlying client's options.
        """
        self.host = host
        self.port = port
        self.scheme = scheme
        self.request_timeout = request_timeout

        basic_auth: tuple[str, str] | None = None
        if username is not None and password is not None:
            basic_auth = (username, password)

        # Per 2026-05-22 audit #9: idle SSH tunnel between cycles half-
        # closes the TCP socket; the next ``search`` raises
        # ``ConnectionResetError``.  Two mitigations layered:
        #
        #   1. ``retry_on_timeout=True`` + ``max_retries=2`` — the library
        #      itself retries on connection errors before raising, which
        #      handles the 80% case (one transient socket).
        #
        #   2. The application-level ``_search_with_retry`` wrapper catches
        #      whatever escapes (1) and retries once more with a 2-second
        #      backoff.  Combined, a 15-minute idle gap produces at worst
        #      one warning line, not a cycle failure.
        self._es = Elasticsearch(
            hosts=[{"host": host, "port": port, "scheme": scheme}],
            basic_auth=basic_auth,
            verify_certs=verify_certs,
            request_timeout=request_timeout,
            retry_on_timeout=True,
            max_retries=2,
            # `ssl_show_warn=False` quiets the urllib3 warning when
            # `verify_certs=False`. Not a security choice — the SSH
            # tunnel is what we trust.
            ssl_show_warn=False,
        )

        logger.debug(
            "TpotESClient initialized: %s://%s:%d (verify_certs=%s, timeout=%ds)",
            scheme,
            host,
            port,
            verify_certs,
            request_timeout,
        )

    # ------------------------------------------------------------------ #
    # health
    # ------------------------------------------------------------------ #

    def ping(self) -> bool:
        """
        Return True if Elasticsearch is reachable, False otherwise.

        Used by the cycle loop as its first action (per V1_SPEC §3) and
        by container startup probes. Never raises — a False return is
        the signal to back off.
        """
        try:
            ok = bool(self._es.ping())
        except (ESConnectionError, ConnectionTimeout, TransportError) as exc:
            logger.warning("ES ping failed: %s", exc)
            return False
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("ES ping raised unexpected error: %s", exc)
            return False

        if ok:
            logger.debug("ES ping OK (%s://%s:%d)", self.scheme, self.host, self.port)
        else:
            logger.warning(
                "ES ping returned False (%s://%s:%d)",
                self.scheme,
                self.host,
                self.port,
            )
        return ok

    # ------------------------------------------------------------------ #
    # query building
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_query(
        start: datetime,
        end: datetime,
        ignore_types: list[str] | None,
        suricata_alert_only: bool = False,
    ) -> dict[str, Any]:
        """
        Build the bool query body shared by `stream_events` and
        `count_events`.

        - `@timestamp` in [start, end) — `gte` / `lt`, half-open
          interval, so cycles can chain without overlap.
        - Optional `must_not` term filter on `type` to drop noisy
          honeypot families (e.g. `P0f`, `Tanner`).
        """
        must: list[dict[str, Any]] = [
            {
                "range": {
                    "@timestamp": {
                        "gte": _iso_utc(start),
                        "lt": _iso_utc(end),
                    }
                }
            }
        ]
        must_not: list[dict[str, Any]] = []
        if ignore_types:
            # `type` is a keyword field in T-Pot's logstash mapping, so a
            # `terms` filter is the right primitive.
            # Use `type.keyword` for exact-match: T-Pot's logstash maps
            # `type` as analyzed text (lowercased + tokenized), so
            # `terms: {"type": ["P0f"]}` doesn't match the indexed value
            # "p0f". Confirmed against the live ES on 2026-05-21: the
            # `type` filter let 5,132 P0f docs through per 15-min window
            # despite TPOT2CTI_IGNORE_TYPES=P0f; switching to type.keyword
            # filters them correctly. See LESSONS §8.5 (added in
            # this commit) for the broader pattern.
            must_not.append({"terms": {"type.keyword": list(ignore_types)}})

        if suricata_alert_only:
            # Suricata is ~60% of everything read and ~89% of ITS docs carry no
            # `alert` object (flow / http / tls / dns / ssh records). The
            # Suricata parser's first statement is
            #     alert = doc.get("alert")
            #     if not isinstance(alert, dict): return None
            # so those docs are provably never parsed into anything today —
            # fetching them costs ~1.8M documents/day for nothing.
            #
            # This is a V1 SCOPE decision, not a claim that non-alert Suricata
            # is worthless. Its `tls` records carry JA3 fingerprints measured to
            # have ZERO overlap with FATT's, and `fileinfo`/`http`/`dns` are
            # candidate enrichment sources. Widening the parser therefore means
            # widening THIS filter in the same change — see the guard test in
            # tests/test_suricata_alert_only_query.py, which fails if the
            # parser starts accepting docs the query would have excluded.
            #
            # NOTE the asymmetry: ES can only cheaply test EXISTENCE, while the
            # parser requires `alert` to be a dict. A doc with a malformed
            # (non-dict) `alert` still arrives and is still counted as parser
            # `unparsed`, which is correct — that case must stay visible.
            must_not.append({
                "bool": {
                    "must": [{"term": {"type.keyword": "Suricata"}}],
                    "must_not": [{"exists": {"field": "alert"}}],
                }
            })

        bool_block: dict[str, Any] = {"must": must}
        if must_not:
            bool_block["must_not"] = must_not
        return {"bool": bool_block}

    # ------------------------------------------------------------------ #
    # counting
    # ------------------------------------------------------------------ #

    def count_events(
        self,
        start: datetime,
        end: datetime,
        index_pattern: str = "logstash-*",
        ignore_types: list[str] | None = None,
        suricata_alert_only: bool = False,
    ) -> int:
        """
        Return the number of matching events in [start, end) without
        retrieving them. Useful for cycle-summary logging and for
        rejecting cycles whose volume crosses a sanity threshold
        before doing the expensive paginated read.
        """
        query = self._build_query(start, end, ignore_types, suricata_alert_only)
        logger.debug(
            "ES count: index=%s start=%s end=%s ignore_types=%s",
            index_pattern,
            _iso_utc(start),
            _iso_utc(end),
            ignore_types or [],
        )

        try:
            resp = self._count_with_retry(index=index_pattern, query=query)
        except (ESConnectionError, ConnectionTimeout, TransportError, ApiError) as exc:
            logger.error("ES count failed for index=%s: %s", index_pattern, exc)
            raise

        total = int(resp.get("count", 0))
        logger.debug("ES count result: %d", total)
        return total

    def _count_with_retry(
        self, index: str, query: dict[str, Any]
    ) -> dict[str, Any]:
        """`count` with the §7 retry-once-on-timeout policy."""
        try:
            return self._es.count(index=index, query=query).body
        except ConnectionTimeout as exc:
            logger.warning("ES count timed out, retrying once: %s", exc)
            return self._es.count(index=index, query=query).body

    # ------------------------------------------------------------------ #
    # streaming
    # ------------------------------------------------------------------ #

    def stream_events(
        self,
        start: datetime,
        end: datetime,
        index_pattern: str = "logstash-*",
        batch_size: int = 1000,
        ignore_types: list[str] | None = None,
        suricata_alert_only: bool = False,
    ) -> Iterator[dict]:
        """
        Yield T-Pot ES documents in the @timestamp range [start, end).

        Pagination uses the `search_after` cursor — the ES-recommended
        replacement for the scroll API (which is deprecated as of
        ES 7.10+). We sort by `@timestamp` ascending with a `_id`
        tiebreaker so identical timestamps don't lose documents.

        Each yielded item is the document's `_source` dict — the same
        structure T-Pot's logstash wrote (see V1_SPEC §5.1 for the
        Cowrie field shape, Appendix A for the cross-cutting schema).

        Args:
            start: inclusive lower bound on `@timestamp`.
            end: exclusive upper bound on `@timestamp`.
            index_pattern: ES index pattern; defaults to `logstash-*`.
            batch_size: number of docs per ES page (default 1000, ES
                hard max 10000 without changing index.max_result_window).
            ignore_types: list of `type` values to skip (e.g. `["P0f"]`).
                Implemented as a `must_not` `terms` filter so the work
                stays server-side.

        Raises:
            elasticsearch.ConnectionError: connection dropped mid-stream
                — caller handles backoff per §7.
            elasticsearch.ConnectionTimeout: query timed out twice in a
                row — caller skips the cycle per §7.
        """
        query = self._build_query(start, end, ignore_types, suricata_alert_only)
        # `_doc` is the canonical tiebreaker for search_after pagination in
        # ES 8+. We previously used `_id` here, but ES 8 disables fielddata
        # on _id by default ("all shards failed" / IllegalArgumentException at
        # query time). `_doc` is cheap, stable across a single point-in-time
        # window, and ES-recommended. See first-live-install postmortem.
        sort = [{"@timestamp": "asc"}, {"_doc": "asc"}]

        logger.debug(
            "ES stream: index=%s start=%s end=%s batch=%d ignore_types=%s",
            index_pattern,
            _iso_utc(start),
            _iso_utc(end),
            batch_size,
            ignore_types or [],
        )

        search_after: list[Any] | None = None
        batches = 0
        total = 0

        while True:
            kwargs: dict[str, Any] = {
                "index": index_pattern,
                "query": query,
                "sort": sort,
                "size": batch_size,
                "track_total_hits": False,
            }
            if search_after is not None:
                kwargs["search_after"] = search_after

            try:
                resp = self._search_with_retry(kwargs)
            except (ESConnectionError, ConnectionTimeout) as exc:
                logger.error(
                    "ES stream failed (batches=%d, yielded=%d): %s",
                    batches,
                    total,
                    exc,
                )
                raise

            hits = resp.get("hits", {}).get("hits", [])
            if not hits:
                break

            batches += 1
            for hit in hits:
                source = hit.get("_source")
                if source is None:
                    # Defensive: a hit with no _source shouldn't happen
                    # for logstash-* but we don't want to crash on it.
                    continue
                total += 1
                yield source

            # `sort` on the last hit is the search_after cursor for
            # the next page.
            search_after = hits[-1].get("sort")
            if search_after is None:
                # No sort key on the last hit — can't paginate further.
                logger.warning(
                    "ES stream: last hit had no sort key; "
                    "stopping pagination at batch %d (%d docs yielded)",
                    batches,
                    total,
                )
                break

            # If we got fewer hits than requested, we're at the end and
            # can skip the extra round-trip.
            if len(hits) < batch_size:
                break

        logger.info(
            "ES stream complete: index=%s range=[%s, %s) batches=%d events=%d",
            index_pattern,
            _iso_utc(start),
            _iso_utc(end),
            batches,
            total,
        )

    #: Exception types treated as transient and worth retrying once.
    #: Per 2026-05-22 audit #5: pre-patch we caught only ``ConnectionTimeout``,
    #: but the live cycle 22 ES stream died on ``ConnectionResetError`` →
    #: ``elasticsearch.ConnectionError`` raised by the SSH tunnel idling
    #: between cycles.  We now also retry the broader connection / transport
    #: errors (urllib3 reset, half-open socket from the keepalive gap, etc.),
    #: each with one short backoff before the second attempt.
    _RETRYABLE_EXC = (ConnectionTimeout, ESConnectionError, TransportError)

    def _search_with_retry(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        """`search` with a one-shot retry-on-transient-error policy.

        Per V1_SPEC §7: a single retry is enough to clear the typical
        flake (idle tunnel reset, brief ES GC pause).  More aggressive
        retries belong upstream in the elasticsearch library's own
        ``retry_on_timeout`` config, which we set in ``__init__``.
        """
        import time as _time
        try:
            return self._es.search(**kwargs).body
        except self._RETRYABLE_EXC as exc:
            logger.warning(
                "ES search transient failure (%s); retrying once after 2s "
                "(index=%s, size=%s): %s",
                type(exc).__name__,
                kwargs.get("index"),
                kwargs.get("size"),
                exc,
            )
            _time.sleep(2.0)
            return self._es.search(**kwargs).body

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #

    def close(self) -> None:
        """Close the underlying ES transport. Safe to call multiple times."""
        try:
            self._es.close()
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("ES client close raised (ignored): %s", exc)


# ---------------------------------------------------------------------- #

    def daily_event_counts(self, day_start, upper, index_pattern="logstash-*",
                           ignore_types=None, page=2000, max_pages=40):
        """(src_ip, sensor, YYYY-MM-DD) -> event count for [day_start, upper).

        Exists because OpenCTI REPLACES a Sighting's `count` on upsert rather
        than summing it. That was measured, not assumed: a day-bucketed
        sighting went 22,119 -> 3,484 when a later but NARROWER cycle
        re-covered part of the same day. So a per-cycle count does not merely
        under-report the day, it overwrites a fuller number with a smaller
        one -- and the volume cap makes that MORE frequent, because it
        deliberately produces more, smaller windows per day.

        Writing the day's own total instead is idempotent under replace: it
        only grows as the day fills, so whichever cycle writes last is also
        the one with the most complete number. ES is the source of truth for
        "how many times did we see this address today"; OpenCTI is a
        projection of it.

        `upper` is the cycle's window_end, NOT the wall clock, so the count
        never claims events this connector has not actually imported yet.

        One composite aggregation, paged. Measured at ~0.8s per 2,000
        buckets, so a few seconds per cycle. `max_pages` bounds it: a
        partial map degrades to per-cycle counts for the addresses it did
        not reach, which is the pre-existing behaviour, rather than
        stalling the cycle.
        """
        out: dict = {}
        after = None
        must = [{"range": {"@timestamp": {"gte": _iso_utc(day_start),
                                          "lt": _iso_utc(upper)}}}]
        if ignore_types:
            must.append({"bool": {"must_not": [
                {"terms": {"type.keyword": list(ignore_types)}}]}})
        for _ in range(max_pages):
            comp = {"size": page, "sources": [
                {"ip": {"terms": {"field": "src_ip.keyword"}}},
                {"host": {"terms": {"field": "t-pot_hostname.keyword"}}},
                {"day": {"date_histogram": {"field": "@timestamp",
                                            "calendar_interval": "day",
                                            "format": "yyyy-MM-dd"}}},
            ]}
            if after:
                comp["after"] = after
            resp = self._search_with_retry({
                "index": index_pattern,
                "size": 0,
                "track_total_hits": False,
                "query": {"bool": {"must": must}},
                "aggs": {"pairs": {"composite": comp}},
            })
            agg = resp.get("aggregations", {}).get("pairs", {})
            buckets = agg.get("buckets") or []
            for b in buckets:
                k = b["key"]
                out[(k["ip"], k["host"], k["day"])] = b["doc_count"]
            after = agg.get("after_key")
            if not after or not buckets:
                break
        else:
            logger.warning(
                "daily_event_counts: hit the %d-page cap with %d pair(s) "
                "collected; the remainder fall back to per-cycle counts",
                max_pages, len(out))
        return out
# smoke test
# ---------------------------------------------------------------------- #

if __name__ == "__main__":
    # Minimal smoke test: build a client with defaults, ping, print.
    # Real usage is from the cycle loop; this is just enough to verify
    # the module imports cleanly and the tunnel is up.
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    client = TpotESClient()
    reachable = client.ping()
    print(f"T-Pot ES reachable: {reachable}")
    client.close()
