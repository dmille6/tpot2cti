# tpot2cti-credentials — DuckDB-backed credential analytics sidecar.
# Implements V1_SPEC §8.1.
#
# Same shape as the core tpot2cti Dockerfile (Phase 7): python:3.12-slim,
# non-root user, no compile toolchain at runtime.

FROM python:3.12-slim AS base

# Non-root user. uid 1000 matches the host owner of the bind-mounted
# ./data/credentials/ directory (created by setup.sh as the invoking user),
# so DuckDB can write to /data/credentials.duckdb without a host-side chown
# dance. Containers are isolated from each other so sharing a uid with the
# core importer is fine — they only share read-only mounts.
ARG APP_UID=1000
ARG APP_GID=1000
RUN groupadd -g ${APP_GID} app && \
    useradd -u ${APP_UID} -g ${APP_GID} -M -s /usr/sbin/nologin app

WORKDIR /app

# System deps. coreutils for `stat` + `date` (used by HEALTHCHECK below).
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates coreutils && \
    rm -rf /var/lib/apt/lists/*

# Python deps first for layer caching.
#
# Build context note: Phase 7's docker-compose.yml sets `context: ./tpot2cti-credentials`,
# so COPY paths here are relative to THIS directory (not the repo root).
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Application source.
COPY . /app/

# Mount point for the DuckDB file (compose binds host's ./data/credentials/ here).
RUN mkdir -p /data && chown -R ${APP_UID}:${APP_GID} /data /app

USER app:app

# Sidecar healthcheck: the main.py loop touches /tmp/last_cycle_ok at the end
# of every successful cycle. If the touch file is older than 2x the cycle
# interval (default 60min => 7200s threshold), we report unhealthy.
HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=3 \
    CMD [ -f /tmp/last_cycle_ok ] && [ $(( $(date +%s) - $(stat -c %Y /tmp/last_cycle_ok) )) -lt 7200 ] || exit 1

CMD ["python", "-u", "main.py", "--serve"]
