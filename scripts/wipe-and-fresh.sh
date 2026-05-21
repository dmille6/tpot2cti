#!/usr/bin/env bash
#
# wipe-and-fresh.sh — destructively reset the tpot2cti deployment to
# a clean-slate state, ready for a fresh `./setup.sh` run.
#
# What this does (in order):
#
#   1. Stop any background soak watcher started by Phase 9 work.
#   2. Run ./teardown.sh --purge, which:
#        - docker compose -p tpot2cti down -v
#        - docker compose -p opencti  down -v
#        - rm -rf data/ logs/ ssh-keys/ opencti/
#        - explicitly remove opencti_* / tpot2cti_* named volumes
#        - docker volume prune -f (orphan sweep)
#   3. Remove the generated ./.env so the next setup.sh re-prompts
#      operator/T-Pot config from scratch.
#   4. Clear the local known_hosts entry for the T-Pot the previous
#      install was pointed at, so the next ssh-copy-id doesn't trip
#      over a host-key mismatch warning.
#   5. Print a "ready" summary + the exact next commands to run.
#
# What this does NOT touch:
#
#   - Source code (anything under /opt/tpot2cti/tpot2cti/, etc.)
#   - .env.example, V1_SPEC.md, docs/, setup.sh, teardown.sh, update.sh
#   - Docker images (opencti/* + tpot2cti/* still cached — saves ~5-10 min
#     on next docker compose up; remove them by hand if you really want
#     to pull fresh: `docker image prune -a -f`).
#   - Build cache (1GB+; same reasoning).
#   - The git repo state (no `git reset` here).
#
# Safety:
#
#   - Requires typing the literal word `yes` (lowercase) to proceed.
#   - There is NO -y / --yes shortcut. Destructive ops must be intentional.
#   - --dry-run prints what would happen without doing anything.
#
# Usage:
#
#   scripts/wipe-and-fresh.sh             # interactive purge, requires "yes"
#   scripts/wipe-and-fresh.sh --dry-run   # just prints the plan
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DRY_RUN=0
case "${1:-}" in
    --dry-run|-n) DRY_RUN=1 ;;
    --help|-h)
        sed -n '2,/^#$/p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    "") : ;;
    *)
        echo "[error] unknown arg: $1" >&2
        echo "usage: $0 [--dry-run|--help]" >&2
        exit 2
        ;;
esac

ok()   { echo "[ok]   $*" >&2; }
info() { echo "[info] $*" >&2; }
warn() { echo "[warn] $*" >&2; }
fail() { echo "[fail] $*" >&2; exit 1; }
dry()  { echo "DRY:   $*" >&2; }
step() { echo "" >&2; echo "=== $* ===" >&2; }

# ─── Capture context about what we're about to wipe ─────────────────────
PREV_TPOT_HOST=""
PREV_TPOT_PORT=""
if [[ -f "${REPO_ROOT}/.env" ]]; then
    PREV_TPOT_HOST="$(grep -E '^TPOT_HOST=' "${REPO_ROOT}/.env" | head -1 | cut -d= -f2- | tr -d ' "')"
    PREV_TPOT_PORT="$(grep -E '^TPOT_SSH_PORT=' "${REPO_ROOT}/.env" | head -1 | cut -d= -f2- | tr -d ' "')"
fi
PREV_TPOT_PORT="${PREV_TPOT_PORT:-64295}"

# ─── Confirm ─────────────────────────────────────────────────────────────
cat >&2 <<EOF

═══════════════════════════════════════════════════════════════════════
  wipe-and-fresh — full destructive reset of tpot2cti on this host
═══════════════════════════════════════════════════════════════════════

  Will permanently delete (after confirmation):

    - All tpot2cti containers (tpot2cti-core / tunnel / credentials / vault)
    - All OpenCTI containers (platform / workers / connectors / redis /
      elasticsearch / rabbitmq / minio / xtm-composer / rsa-key-generator)
    - All named volumes: opencti_esdata, opencti_redisdata,
      opencti_amqpdata, opencti_s3data, opencti_rsakeys, and any
      tpot2cti_* / tpot-tunnel_* siblings
    - Host directories: ${REPO_ROOT}/data, ${REPO_ROOT}/logs,
      ${REPO_ROOT}/ssh-keys, ${REPO_ROOT}/opencti
    - The generated ${REPO_ROOT}/.env (so next setup.sh re-prompts)
    - Background soak watcher process (if running)
EOF

if [[ -n "$PREV_TPOT_HOST" ]]; then
    cat >&2 <<EOF
    - SSH known_hosts entry for ${PREV_TPOT_HOST}:${PREV_TPOT_PORT}
EOF
fi

cat >&2 <<EOF

  PRESERVED (NOT removed):
    - source code, docs/, .env.example, V1_SPEC.md
    - setup.sh / teardown.sh / update.sh
    - Docker images (so next \`compose up\` is fast)
    - Docker build cache
    - git repo state

EOF

if (( DRY_RUN )); then
    info "DRY RUN — no changes will be made"
    echo "" >&2
else
    echo -n "Type 'yes' (lowercase, full word) to proceed: " >&2
    read -r answer
    if [[ "$answer" != "yes" ]]; then
        fail "aborted (you typed: ${answer:-<empty>})"
    fi
fi

# ─── 1. Stop soak watcher ────────────────────────────────────────────────
step "Step 1/5: Stopping background soak watcher (if running)"
WATCHER_PID_FILE="/tmp/tpot2cti-soak-watcher.pid"
WATCHER_LOG_FILE="/tmp/tpot2cti-soak-watcher.log"
if [[ -f "$WATCHER_PID_FILE" ]]; then
    pid="$(cat "$WATCHER_PID_FILE")"
    if (( DRY_RUN )); then
        dry "kill $pid (current pid in $WATCHER_PID_FILE)"
    else
        if kill "$pid" 2>/dev/null; then
            ok "soak watcher pid=$pid stopped"
        else
            info "soak watcher pid=$pid already gone"
        fi
        rm -f "$WATCHER_PID_FILE" "$WATCHER_LOG_FILE"
    fi
else
    info "no watcher pid file at $WATCHER_PID_FILE"
fi

# ─── 2. Run teardown --purge ────────────────────────────────────────────
step "Step 2/5: Running ./teardown.sh --purge"
if (( DRY_RUN )); then
    dry "(cd $REPO_ROOT && printf 'y\\nyes\\n' | ./teardown.sh --purge)"
else
    # teardown.sh prompts twice (Continue? [y/N], then 'yes' for purge).
    # We feed both because this wrapper already got its own 'yes' confirmation.
    (cd "$REPO_ROOT" && printf "y\nyes\n" | ./teardown.sh --purge) \
        || warn "teardown.sh returned non-zero (continuing — it may have already been partially wiped)"
fi

# ─── 3. Remove .env ─────────────────────────────────────────────────────
step "Step 3/5: Removing ${REPO_ROOT}/.env to force fresh prompts"
if (( DRY_RUN )); then
    dry "rm -f ${REPO_ROOT}/.env"
else
    if [[ -f "${REPO_ROOT}/.env" ]]; then
        rm -f "${REPO_ROOT}/.env"
        ok "removed ${REPO_ROOT}/.env"
    else
        info "no .env to remove (already gone)"
    fi
fi

# ─── 4. Clear known_hosts entry for T-Pot ───────────────────────────────
step "Step 4/5: Clearing T-Pot host-key entry from local known_hosts"
if [[ -n "$PREV_TPOT_HOST" ]]; then
    HOST_PORT_KEY="[${PREV_TPOT_HOST}]:${PREV_TPOT_PORT}"
    USER_KNOWN_HOSTS="${HOME}/.ssh/known_hosts"
    REPO_KNOWN_HOSTS="${REPO_ROOT}/ssh-keys/known_hosts"
    for kh in "$USER_KNOWN_HOSTS" "$REPO_KNOWN_HOSTS"; do
        if [[ -f "$kh" ]]; then
            if (( DRY_RUN )); then
                dry "ssh-keygen -R '${HOST_PORT_KEY}' -f '$kh'"
            else
                # ssh-keygen -R returns 0 even on no-match — silently safe
                ssh-keygen -R "${HOST_PORT_KEY}" -f "$kh" 2>/dev/null \
                    | grep -E '^(removed|updating)' >&2 \
                    && ok "cleaned host-key entry in $kh" \
                    || info "no matching entry in $kh"
            fi
        fi
    done
else
    info "no previous TPOT_HOST recorded; skipping known_hosts cleanup"
fi

# ─── 5. Final state ─────────────────────────────────────────────────────
step "Step 5/5: Final state verification"
if (( DRY_RUN )); then
    dry "docker ps -a (expect 0 tpot2cti/opencti containers)"
    dry "docker volume ls (expect 0 opencti_* / tpot2cti_*)"
    dry "ls -la ${REPO_ROOT}/.env (expect: not found)"
    dry "ls ${REPO_ROOT}/opencti (expect: not found)"
else
    surviving_containers="$(docker ps -a --format '{{.Names}}' \
        | grep -E '^(tpot2cti|opencti)' || true)"
    if [[ -n "$surviving_containers" ]]; then
        warn "still-present containers: $(echo "$surviving_containers" | tr '\n' ' ')"
    else
        ok "0 tpot2cti/opencti containers remain"
    fi

    surviving_volumes="$(docker volume ls --format '{{.Name}}' \
        | grep -E '^(opencti_|tpot2cti_|tpot-tunnel_)' || true)"
    if [[ -n "$surviving_volumes" ]]; then
        warn "still-present volumes: $(echo "$surviving_volumes" | tr '\n' ' ')"
    else
        ok "0 named volumes remain"
    fi

    [[ ! -f "${REPO_ROOT}/.env" ]] && ok "${REPO_ROOT}/.env is gone" \
        || warn "${REPO_ROOT}/.env still present (?)"
    [[ ! -d "${REPO_ROOT}/opencti" ]] && ok "${REPO_ROOT}/opencti/ is gone" \
        || warn "${REPO_ROOT}/opencti/ still present (?)"
fi

# ─── Next steps ─────────────────────────────────────────────────────────
cat >&2 <<EOF

═══════════════════════════════════════════════════════════════════════
  Clean slate ready. Next:

    1.  cd ${REPO_ROOT}
    2.  ./setup.sh

  setup.sh will prompt for T-Pot host, operator name, TLP, sidecars,
  and pause at step 6 with a new ed25519 public key for you to copy
  to T-Pot's authorized_keys before step 7.

  Tip for step 6 — use ssh-copy-id from another terminal on this host:

    ssh-copy-id -i ${REPO_ROOT}/ssh-keys/id_ed25519.pub \\
        -p 64295 <your-tpot-user>@<your-tpot-host>

  Then return to the setup.sh prompt and press Enter to continue.

═══════════════════════════════════════════════════════════════════════

EOF
