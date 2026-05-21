"""tpot2cti-credentials — runtime configuration.

Implements V1_SPEC §8.1 (DuckDB credential analytics sidecar). Config is
read once at process start from environment variables (see V1_SPEC §10).

The dataclass is frozen so cycle code never mutates config mid-run — same
convention as the core importer's ``tpot2cti.config``.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

# ISO 8601 duration: subset PTnH / PTnM / PTnS / combos, per V1_SPEC §10.
_ISO_DURATION_RE = re.compile(
    r"^PT"
    r"(?:(?P<h>\d+(?:\.\d+)?)H)?"
    r"(?:(?P<m>\d+(?:\.\d+)?)M)?"
    r"(?:(?P<s>\d+(?:\.\d+)?)S)?"
    r"$"
)


def _parse_iso_duration_seconds(iso: str, default_seconds: float) -> float:
    """Parse ``PTnH...nM...nS`` into seconds; fall back to ``default_seconds``.

    Same routine as ``tpot2cti.health.parse_iso_duration_seconds`` but
    duplicated locally to keep the sidecar import-free of the core
    importer (per V1_SPEC §8.1 "no coordination with core importer").
    """
    if not iso:
        return default_seconds
    m = _ISO_DURATION_RE.match(iso.strip())
    if not m:
        return default_seconds
    h = float(m.group("h") or 0.0)
    mn = float(m.group("m") or 0.0)
    s = float(m.group("s") or 0.0)
    total = h * 3600.0 + mn * 60.0 + s
    return total if total > 0 else default_seconds


@dataclass(frozen=True)
class CredentialsConfig:
    """Frozen config — populate via :meth:`from_env`."""

    # Elasticsearch connection
    es_host: str
    es_port: int
    es_scheme: str
    es_username: str | None
    es_password: str | None
    request_timeout: int

    # DuckDB path (inside the container)
    duckdb_path: str

    # Cycle behavior
    interval_seconds: float

    # Which T-Pot honeypot `type` values yield credential events
    # (V1_SPEC §8.1: Cowrie, Heralding, Mailoney, SentryPeer)
    credential_types: tuple[str, ...]

    # Logging
    log_level: str

    # Healthcheck touch file (Dockerfile HEALTHCHECK reads this)
    healthcheck_path: str

    # Idle-iteration sleep when no work is queued (small backoff for the
    # first-ever cycle when there is no prior last_run to anchor against).
    idle_sleep_seconds: float

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "CredentialsConfig":
        e = env if env is not None else os.environ
        return cls(
            es_host=e.get("ES_HOST", "tpot-tunnel"),
            es_port=int(e.get("ES_PORT", "9200")),
            es_scheme=e.get("ES_SCHEME", "http"),
            es_username=e.get("ES_USERNAME") or None,
            es_password=e.get("ES_PASSWORD") or None,
            request_timeout=int(e.get("ES_REQUEST_TIMEOUT", "30")),
            duckdb_path=e.get("TPOT2CTI_CREDENTIALS_DB", "/data/credentials.duckdb"),
            interval_seconds=_parse_iso_duration_seconds(
                e.get("TPOT2CTI_CREDENTIALS_INTERVAL", "PT60M"),
                default_seconds=3600.0,
            ),
            credential_types=tuple(
                t.strip()
                for t in e.get(
                    "TPOT2CTI_CREDENTIALS_TYPES",
                    "Cowrie,Heralding,Mailoney,Sentrypeer",
                ).split(",")
                if t.strip()
            ),
            log_level=e.get("LOG_LEVEL", "INFO").upper(),
            healthcheck_path=e.get("TPOT2CTI_HEALTH_TOUCH", "/tmp/last_cycle_ok"),
            idle_sleep_seconds=float(e.get("TPOT2CTI_CREDENTIALS_IDLE_SLEEP", "60")),
        )
