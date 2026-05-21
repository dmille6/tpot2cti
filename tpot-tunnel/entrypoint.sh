#!/bin/sh
# tpot-tunnel — autossh entrypoint.
#
# Per V1_SPEC §2: maintain an SSH tunnel from this container to T-Pot's
# Elasticsearch on the remote host.  The tunnel listens on
# ${TUNNEL_LOCAL_BIND} inside this container so the core importer can
# reach it via the compose service name `tunnel` on opencti_default.
#
# Env contract (all set from tpot2cti/.env):
#   TPOT_HOST              — required; T-Pot hostname or IP
#   TPOT_SSH_PORT          — default 64295
#   TPOT_SSH_USER          — default "tpot"
#   TPOT_ES_REMOTE_PORT    — default 64298 (T-Pot ES on the remote loopback)
#   TUNNEL_LOCAL_BIND      — default "0.0.0.0:64298" (where we LISTEN in-container —
#                             mirrors the remote port so the core's default ES_PORT
#                             matches without an .env override)
#   AUTOSSH_GATETIME       — default 0  (start immediately, even if first
#                                       connection takes a while)
#   AUTOSSH_POLL           — default 60 (seconds between liveness probes)
#
# SSH key is mounted at /ssh-keys/id_ed25519 (read-only) by docker-compose.
set -eu

TPOT_HOST="${TPOT_HOST:-}"
TPOT_SSH_PORT="${TPOT_SSH_PORT:-64295}"
TPOT_SSH_USER="${TPOT_SSH_USER:-tpot}"
TPOT_ES_REMOTE_PORT="${TPOT_ES_REMOTE_PORT:-64298}"
TUNNEL_LOCAL_BIND="${TUNNEL_LOCAL_BIND:-0.0.0.0:64298}"
AUTOSSH_GATETIME="${AUTOSSH_GATETIME:-0}"
AUTOSSH_POLL="${AUTOSSH_POLL:-60}"

SSH_KEY="${SSH_KEY:-/ssh-keys/id_ed25519}"

# --- Validate required configuration ---------------------------------------
if [ -z "${TPOT_HOST}" ]; then
    echo "tpot-tunnel: FATAL — TPOT_HOST is not set." >&2
    echo "             Set it in tpot2cti/.env (see V1_SPEC §10)." >&2
    exit 2
fi

if [ ! -r "${SSH_KEY}" ]; then
    echo "tpot-tunnel: FATAL — SSH key not readable at ${SSH_KEY}." >&2
    echo "             setup.sh should have generated ./ssh-keys/id_ed25519" >&2
    echo "             and registered the public half on T-Pot." >&2
    exit 2
fi

# --- known_hosts: seed via ssh-keyscan if not already present ---------------
KNOWN_HOSTS="${HOME}/.ssh/known_hosts"
mkdir -p "${HOME}/.ssh"
chmod 700 "${HOME}/.ssh"
touch "${KNOWN_HOSTS}"
chmod 600 "${KNOWN_HOSTS}"

if ! ssh-keygen -F "[${TPOT_HOST}]:${TPOT_SSH_PORT}" -f "${KNOWN_HOSTS}" >/dev/null 2>&1; then
    echo "tpot-tunnel: seeding known_hosts for ${TPOT_HOST}:${TPOT_SSH_PORT} via ssh-keyscan..."
    # `-H` hashes the hostname; `-T 5` caps the timeout so a slow/dead
    # host doesn't make this loop forever.
    if ssh-keyscan -H -T 5 -p "${TPOT_SSH_PORT}" "${TPOT_HOST}" >> "${KNOWN_HOSTS}" 2>/dev/null; then
        echo "tpot-tunnel: known_hosts seeded."
    else
        echo "tpot-tunnel: WARN ssh-keyscan failed; falling back to StrictHostKeyChecking=accept-new" >&2
    fi
fi

echo "tpot-tunnel: starting autossh"
echo "             remote=${TPOT_SSH_USER}@${TPOT_HOST}:${TPOT_SSH_PORT}"
echo "             forward=${TUNNEL_LOCAL_BIND} -> 127.0.0.1:${TPOT_ES_REMOTE_PORT}"
echo "             key=${SSH_KEY}"

export AUTOSSH_GATETIME
export AUTOSSH_POLL

# -M 0          — disable autossh's own monitoring port; we rely on
#                  ServerAliveInterval/CountMax for liveness detection
# -N            — no remote command
# accept-new    — first-run convenience; subsequent runs use known_hosts
exec autossh \
    -M 0 \
    -N \
    -o "ServerAliveInterval=30" \
    -o "ServerAliveCountMax=3" \
    -o "ExitOnForwardFailure=yes" \
    -o "StrictHostKeyChecking=accept-new" \
    -o "UserKnownHostsFile=${KNOWN_HOSTS}" \
    -i "${SSH_KEY}" \
    -L "${TUNNEL_LOCAL_BIND}:127.0.0.1:${TPOT_ES_REMOTE_PORT}" \
    -p "${TPOT_SSH_PORT}" \
    "${TPOT_SSH_USER}@${TPOT_HOST}"
