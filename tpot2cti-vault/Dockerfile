# tpot2cti-vault — SFTP malware-sample fetcher sidecar.
# Implements V1_SPEC §8.2.
#
# Same shape as the credentials sidecar: python:3.12-slim, non-root user,
# no compile toolchain at runtime.

FROM python:3.12-slim AS base

# Non-root user (uid 1101). Distinct from the credentials sidecar so the
# two services' file ownership in `data/` is easy to tell apart.
ARG APP_UID=1101
ARG APP_GID=1101
RUN groupadd -g ${APP_GID} app && \
    useradd -u ${APP_UID} -g ${APP_GID} -M -s /usr/sbin/nologin app

WORKDIR /app

# System deps. coreutils for stat/date used by HEALTHCHECK; openssh-client
# is NOT needed — paramiko ships its own SSH transport.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates coreutils && \
    rm -rf /var/lib/apt/lists/*

# Build context note: Phase 7's docker-compose.yml sets `context: ./tpot2cti-vault`,
# so COPY paths here are relative to THIS directory (not the repo root).
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app/

# Mount points: /data (compose binds to ./data/malware-vault/ on host),
# /ssh-keys (read-only mount of the host's ssh-keys/ for the paramiko key).
RUN mkdir -p /data /data/samples && chown -R ${APP_UID}:${APP_GID} /data /app

USER app:app

# Healthcheck: main.py touches /tmp/last_cycle_ok at end of each successful
# cycle. 2x interval (PT15M -> 1800s threshold) — but we set the threshold
# more conservatively (3600s) to absorb slow SFTP runs.
HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=3 \
    CMD [ -f /tmp/last_cycle_ok ] && [ $(( $(date +%s) - $(stat -c %Y /tmp/last_cycle_ok) )) -lt 3600 ] || exit 1

CMD ["python", "-u", "main.py", "--serve"]
