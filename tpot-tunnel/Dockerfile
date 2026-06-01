# tpot-tunnel — autossh sidecar that maintains the SSH tunnel to T-Pot's
# Elasticsearch (port 64298) so the core importer can reach it as
# `tunnel:9200` on the opencti_default network.
#
# We build our own minimal image rather than depending on a third-party
# Docker Hub image (jnovack/autossh etc.) — V1_SPEC §2 / settled design
# decision: no external image dependencies.

FROM alpine:3.20

# --- Packages ---------------------------------------------------------------
# autossh         — auto-restarting ssh tunnel
# openssh-client  — ssh + ssh-keyscan
# tini            — PID 1 signal/zombie handling (matches the core image)
# netcat-openbsd  — used by HEALTHCHECK to verify the forwarded port
#                   actually accepts connections.  The 2026-05 outage
#                   surfaced a false-positive: pgrep-only healthcheck
#                   reported `healthy` for 7h while T-Pot was offline,
#                   so the importer kept thrashing ES queries into a
#                   dead socket.  An end-to-end nc on the forward port
#                   fails fast when the underlying SSH session dies.
RUN apk add --no-cache \
        autossh \
        openssh-client \
        tini \
        netcat-openbsd

# --- Non-root user ----------------------------------------------------------
# uid 1000 matches the typical host owner of the ssh-keys bind mount, so
# `id_ed25519` (mode 600 owned by the host's uid 1000) is readable inside
# the container without forcing the host to chmod 644 (which weakens key
# security).  Separate containers are already isolated from each other, so
# sharing a uid with the core importer is fine — they only share the
# read-only /ssh-keys mount on the host.
RUN addgroup -g 1000 -S tunnel \
    && adduser -u 1000 -S -G tunnel -h /home/tunnel -s /bin/sh tunnel \
    && mkdir -p /home/tunnel/.ssh \
    && chown -R tunnel:tunnel /home/tunnel \
    && chmod 700 /home/tunnel/.ssh

# --- Entrypoint -------------------------------------------------------------
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER tunnel
WORKDIR /home/tunnel

# Healthcheck — verify the tunnel ACCEPTS connections on the forwarded
# port, not just that autossh is alive.  `pgrep autossh` (the previous
# check) stayed green during the 2026-05 T-Pot outage: autossh kept
# restarting its child ssh forever while the remote was offline, the
# child kept binding 64298 briefly between failures, and the importer
# thrashed 30+ failed ES cycles before anyone noticed.
#
# `nc -z 127.0.0.1 64298` only completes the local handshake (so it
# doesn't prove the remote side is healthy end-to-end), but it DOES
# fail fast when the autossh child ssh has died and the listener is
# torn down — which is the failure mode we missed before.
#
# Retries=3 + interval=30s tolerates a ~90s reconnect window without
# flipping unhealthy, matching autossh's ServerAliveInterval=30 /
# ServerAliveCountMax=3 in entrypoint.sh.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
    CMD pgrep autossh >/dev/null && nc -z 127.0.0.1 64298 || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
