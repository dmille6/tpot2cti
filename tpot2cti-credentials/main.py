"""tpot2cti-credentials — entrypoint.

Implements V1_SPEC §8.1. Runs an indefinite cycle loop:

    1. Pick cycle window: [last_run, now). On first run, last_run = now - interval.
    2. Stream credential-bearing events from T-Pot ES via the shared tunnel.
    3. For each event: extract (username, password, sensor, src_ip, ts), upsert
       into DuckDB (credentials + credential_sources).
    4. Record the cycle in cycle_log.
    5. touch /tmp/last_cycle_ok (HEALTHCHECK gate).
    6. Sleep `interval_seconds`.

Errors per-doc: log DEBUG, skip, continue. Errors per-cycle: log WARN,
sleep, retry next cycle. No credentials are ever logged (we log counts
and event-level metadata only).
"""

from __future__ import annotations

import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Iterable

from config import CredentialsConfig
from extract import CredentialEvent, extract_credential
from log import setup_logging
from store import CredentialsStore, CycleCounts

logger = logging.getLogger("tpot2cti.credentials")


# ---------------------------------------------------------------------------
# ES client construction
# ---------------------------------------------------------------------------
# We deliberately do NOT import tpot2cti.es_client here — per V1_SPEC §8.1
# the sidecars are independent of the core importer. We construct the
# elasticsearch client ourselves with the same default shape (basic auth,
# http://tunnel:64298, etc.).

def make_es_client(cfg: CredentialsConfig):
    """Construct an Elasticsearch client honoring the sidecar's config."""
    from elasticsearch import Elasticsearch  # local import; sidecar may run smoke-only

    basic_auth = None
    if cfg.es_username and cfg.es_password:
        basic_auth = (cfg.es_username, cfg.es_password)
    return Elasticsearch(
        hosts=[{"host": cfg.es_host, "port": cfg.es_port, "scheme": cfg.es_scheme}],
        basic_auth=basic_auth,
        verify_certs=False,
        request_timeout=cfg.request_timeout,
        ssl_show_warn=False,
    )


# ---------------------------------------------------------------------------
# ES streaming
# ---------------------------------------------------------------------------

def stream_credential_docs(es, cfg: CredentialsConfig, start: datetime, end: datetime) -> Iterable[dict]:
    """Yield ``_source`` dicts for credential-bearing events in [start, end).

    Mirrors the pagination pattern from tpot2cti.es_client.TpotESClient
    (search_after on @timestamp + _id).
    """
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {
                    "gte": start.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "lt": end.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                }}},
                {"terms": {"type": list(cfg.credential_types)}},
            ]
        }
    }
    sort = [{"@timestamp": "asc"}, {"_id": "asc"}]
    search_after = None
    while True:
        kwargs = {
            "index": "logstash-*",
            "query": query,
            "sort": sort,
            "size": 1000,
            "track_total_hits": False,
        }
        if search_after is not None:
            kwargs["search_after"] = search_after
        resp = es.search(**kwargs).body
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            return
        for h in hits:
            src = h.get("_source")
            if src is not None:
                yield src
        search_after = hits[-1].get("sort")
        if search_after is None or len(hits) < 1000:
            return


# ---------------------------------------------------------------------------
# Cycle
# ---------------------------------------------------------------------------

def run_cycle(es, store: CredentialsStore, cfg: CredentialsConfig) -> CycleCounts:
    """Execute one credential ingestion cycle.

    Returns a CycleCounts. Raises on hard failure (caller backs off).
    """
    now = datetime.now(timezone.utc)
    last_run = store.last_run() or (now - timedelta(seconds=cfg.interval_seconds))
    if last_run >= now:
        logger.info("No new window to process (last_run=%s >= now=%s)", last_run, now)
        return CycleCounts()

    logger.info(
        "Cycle starting: window=[%s, %s), types=%s",
        last_run.isoformat(), now.isoformat(), list(cfg.credential_types),
    )

    counts = CycleCounts()
    started_at = datetime.now(timezone.utc)

    # Wrap the upserts in a transaction so a mid-cycle crash leaves the
    # DB in a consistent state and the same window can be re-tried.
    with store.transaction():
        for doc in stream_credential_docs(es, cfg, last_run, now):
            counts.events_processed += 1
            try:
                ev: CredentialEvent | None = extract_credential(doc)
            except Exception as exc:
                logger.debug("extract_credential raised on doc: %s", exc)
                continue
            if ev is None:
                continue
            try:
                is_new_cred, is_new_src = store.upsert_credential(
                    ev.username, ev.password, ev.sensor, ev.src_ip, ev.timestamp,
                )
                if is_new_cred:
                    counts.creds_new += 1
                else:
                    counts.creds_updated += 1
            except Exception as exc:
                logger.debug("upsert_credential failed for sensor=%s: %s", ev.sensor, exc)

        ended_at = datetime.now(timezone.utc)
        store.record_cycle(started_at, ended_at, counts)

    logger.info(
        "Cycle complete: events=%d new=%d updated=%d duration_s=%.1f",
        counts.events_processed, counts.creds_new, counts.creds_updated,
        (ended_at - started_at).total_seconds(),
    )
    return counts


def touch_healthcheck(cfg: CredentialsConfig) -> None:
    try:
        with open(cfg.healthcheck_path, "w") as fh:
            fh.write(datetime.now(timezone.utc).isoformat() + "\n")
    except OSError as exc:
        logger.warning("Could not touch healthcheck file %s: %s", cfg.healthcheck_path, exc)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_forever(cfg: CredentialsConfig) -> int:
    setup_logging(cfg.log_level)
    store = CredentialsStore(cfg.duckdb_path)
    es = make_es_client(cfg)
    logger.info(
        "tpot2cti-credentials starting: es=%s://%s:%d db=%s interval=%.0fs",
        cfg.es_scheme, cfg.es_host, cfg.es_port, cfg.duckdb_path, cfg.interval_seconds,
    )
    try:
        while True:
            try:
                run_cycle(es, store, cfg)
                touch_healthcheck(cfg)
            except Exception as exc:
                logger.warning("Cycle failed: %s", exc, exc_info=True)
            time.sleep(cfg.interval_seconds)
    finally:
        store.close()
    return 0


# ---------------------------------------------------------------------------
# Smoke test (offline, no ES needed)
# ---------------------------------------------------------------------------

def _smoke_test() -> None:
    """Stub ES with canned hits; verify DuckDB schema + upsert + cycle_log row.

    Run via ``python -m main`` or ``python main.py``.
    """
    import tempfile

    setup_logging("INFO", connector_name="tpot2cti-credentials-smoke")

    tmpdir = tempfile.mkdtemp(prefix="creds-smoke-")
    db_path = os.path.join(tmpdir, "credentials.duckdb")

    # Build a CredentialsConfig directly (skip env).
    cfg = CredentialsConfig.from_env({
        "TPOT2CTI_CREDENTIALS_DB": db_path,
        "TPOT2CTI_CREDENTIALS_INTERVAL": "PT60M",
        "LOG_LEVEL": "INFO",
        "TPOT2CTI_HEALTH_TOUCH": os.path.join(tmpdir, "last_cycle_ok"),
    })

    store = CredentialsStore(cfg.duckdb_path)

    # --- Build a fake ES client returning canned hits.
    class FakeES:
        """Minimal stub that mimics elasticsearch.Elasticsearch.search()."""
        def __init__(self) -> None:
            self._calls = 0

        def search(self, **kwargs):
            self._calls += 1
            class _Resp:
                pass
            r = _Resp()
            if self._calls == 1:
                r.body = {"hits": {"hits": [
                    {"_source": {
                        "type": "Cowrie", "username": "root", "password": "toor",
                        "sensor": "honeypot-1", "src_ip": "203.0.113.7",
                        "@timestamp": "2026-05-20T12:00:00.000Z",
                    }, "sort": [1, "a"]},
                    {"_source": {
                        "type": "Cowrie", "username": "root", "password": "toor",
                        "sensor": "honeypot-1", "src_ip": "203.0.113.7",
                        "@timestamp": "2026-05-20T12:01:00.000Z",
                    }, "sort": [2, "b"]},
                    {"_source": {
                        "type": "Cowrie", "username": "root", "password": "toor",
                        "sensor": "honeypot-1", "src_ip": "198.51.100.42",
                        "@timestamp": "2026-05-20T12:02:00.000Z",
                    }, "sort": [3, "c"]},
                    {"_source": {
                        "type": "Heralding", "username": "admin", "password": "1234",
                        "sensor": "honeypot-2", "src_ip": "203.0.113.9",
                        "@timestamp": "2026-05-20T12:03:00.000Z",
                    }, "sort": [4, "d"]},
                    # Missing src_ip — should be skipped
                    {"_source": {
                        "type": "Mailoney", "username": "smtp", "password": "x",
                        "sensor": "honeypot-2",
                        "@timestamp": "2026-05-20T12:04:00.000Z",
                    }, "sort": [5, "e"]},
                ]}}
            else:
                r.body = {"hits": {"hits": []}}
            return r

    es = FakeES()
    counts = run_cycle(es, store, cfg)

    # Assertions
    assert counts.events_processed == 5, f"expected 5 events, got {counts.events_processed}"
    assert counts.creds_new == 2, f"expected 2 new creds, got {counts.creds_new}"
    assert counts.creds_updated == 2, f"expected 2 updates, got {counts.creds_updated}"

    # credentials table content
    rows = store._conn.execute(
        "SELECT username, password, sensor, attempt_count, unique_src_ip_count "
        "FROM credentials ORDER BY username"
    ).fetchall()
    assert len(rows) == 2, f"expected 2 credentials rows, got {len(rows)}: {rows}"
    by_user = {r[0]: r for r in rows}
    assert by_user["root"][3] == 3, f"root attempt_count={by_user['root'][3]} != 3"
    assert by_user["root"][4] == 2, f"root unique_src_ip_count={by_user['root'][4]} != 2"
    assert by_user["admin"][3] == 1

    # credential_sources table
    sources = store._conn.execute(
        "SELECT username, src_ip, attempt_count FROM credential_sources ORDER BY username, src_ip"
    ).fetchall()
    assert len(sources) == 3, f"expected 3 source rows, got {len(sources)}: {sources}"

    # cycle_log
    cyc_rows = store._conn.execute("SELECT * FROM cycle_log").fetchall()
    assert len(cyc_rows) == 1, f"expected 1 cycle_log row, got {len(cyc_rows)}"

    store.close()
    print("OK")


if __name__ == "__main__":
    # Default: smoke test (so `python -m main` / `python main.py` inside the
    # repo with no env exercises the module and prints OK). The Dockerfile
    # overrides this by passing `--serve` so production runs the cycle loop.
    #
    # This intentional dual-purpose matters because:
    #   - The smoke test is the closest thing to a unit test we have offline,
    #     and the build verification script runs `python -m main` (per the
    #     Phase 8 brief);
    #   - The container needs to actually serve in production.
    if "--serve" in sys.argv or os.environ.get("TPOT2CTI_CREDENTIALS_SERVE") == "1":
        cfg = CredentialsConfig.from_env()
        sys.exit(run_forever(cfg))
    _smoke_test()
