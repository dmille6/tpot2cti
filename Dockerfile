# tpot2cti core importer — V1_SPEC §2 (architecture) + §3 (cycle behavior).
#
# Single-stage build: pycti and elasticsearch are pure-Python wheels with
# small native deps; a multi-stage split saves ~10 MB on a ~200 MB image —
# not worth the build-complexity cost.
#
# Per LESSONS_LEARNED §9.1: when adding new files to this image, rebuild
# with `docker compose build --no-cache tpot2cti` — Docker won't notice
# new files under tpot2cti/ otherwise.

FROM python:3.12-slim

# --- OS layer ---------------------------------------------------------------
# `curl` is required by HEALTHCHECK (python:3.12-slim doesn't ship it).
# `ca-certificates` is needed for HTTPS to OpenCTI / any TLS dest.
# `tini` is a tiny init that reaps zombies and forwards signals — without
# it PID 1 is python, and Ctrl-C / docker stop signal handling gets weird.
# `libmagic1` is required by pycti at import time (its file-type detection
# uses python-magic which wraps libmagic). Without it, `import pycti`
# raises "failed to find libmagic" before tpot2cti's own startup begins.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        tini \
        libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# --- Python tooling ---------------------------------------------------------
# Pin pip/setuptools to avoid build surprises (resolver changes between
# minor versions occasionally break --no-cache-dir installs).
RUN pip install --no-cache-dir --upgrade \
        "pip==24.2" \
        "setuptools==75.1.0" \
        "wheel==0.44.0"

# --- Non-root user ----------------------------------------------------------
# uid 1000 matches the host's first non-root user on most Linux distros,
# so bind-mounted ./data and ./logs end up owned correctly by default.
RUN groupadd --gid 1000 tpot2cti \
    && useradd --uid 1000 --gid 1000 --home /home/tpot2cti --create-home --shell /bin/false tpot2cti

# --- App layer --------------------------------------------------------------
WORKDIR /app

# Copy requirements first so the dependency layer caches independently
# of source changes.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy source.  Per V1_SPEC §2 we only ship the importer source itself
# in this image; sidecar connectors have their own Dockerfiles.
COPY tpot2cti/ /app/tpot2cti/
COPY LICENSE /app/LICENSE

# Pre-create the writable dirs the importer needs, owned by the runtime
# user — they're typically bind-mounted but should exist either way.
RUN mkdir -p /data /var/log/tpot2cti /opt/connector/data \
    && chown -R tpot2cti:tpot2cti /app /data /var/log/tpot2cti /opt/connector

USER tpot2cti

# --- Runtime ----------------------------------------------------------------
# Per V1_SPEC §3 (Health endpoint): /health on internal port 8080.
# NOT bound on the host — only reachable from other containers on the
# opencti_default network (host 8080 is OpenCTI's UI).
EXPOSE 8080

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Per V1_SPEC §3 (Health endpoint) — 200 if last cycle succeeded within
# 2× the cycle interval, else 503.  start_period gives the first cycle
# time to complete before the healthcheck starts failing the container.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=60s \
    CMD curl -fsS http://localhost:8080/health || exit 1

# tini → python so SIGTERM reaches the importer's signal handler
# (which finishes the current cycle then exits cleanly — see main.py).
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "tpot2cti.main"]
