# tpot-tunnel — autossh sidecar that maintains the SSH tunnel to T-Pot's
# Elasticsearch (port 64298) so the core importer can reach it as
# `tunnel:9200` on the opencti_default network.
#
# We build our own minimal image rather than depending on a third-party
# Docker Hub image (jnovack/autossh etc.) — V1_SPEC §2 / settled design
# decision: no external image dependencies.

FROM alpine:3.20

# --- Packages ---------------------------------------------------------------
# autossh        — auto-restarting ssh tunnel
# openssh-client — ssh + ssh-keyscan
# tini           — PID 1 signal/zombie handling (matches the core image)
RUN apk add --no-cache \
        autossh \
        openssh-client \
        tini

# --- Non-root user ----------------------------------------------------------
# uid 1001 to differentiate from the core importer's 1000.  The ssh-keys
# bind mount on the host should be readable by either uid (set 0644).
RUN addgroup -g 1001 -S tunnel \
    && adduser -u 1001 -S -G tunnel -h /home/tunnel -s /bin/sh tunnel \
    && mkdir -p /home/tunnel/.ssh \
    && chown -R tunnel:tunnel /home/tunnel \
    && chmod 700 /home/tunnel/.ssh

# --- Entrypoint -------------------------------------------------------------
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER tunnel
WORKDIR /home/tunnel

# Healthcheck — if autossh isn't running we're not tunneling.  autossh
# itself re-establishes the underlying ssh process on failure, so the
# only thing the healthcheck can usefully detect is autossh itself
# having died.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
    CMD pgrep autossh >/dev/null || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
