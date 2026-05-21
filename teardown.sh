#!/usr/bin/env bash
# =============================================================================
# tpot2cti — teardown
#
# Implements V1_SPEC.md §9 "Sister scripts: teardown.sh and update.sh".
#
#   ./teardown.sh           # Stops both stacks; data volumes preserved.
#   ./teardown.sh --purge   # Stops + removes data dirs + prunes volumes.
#                             Requires interactive 'yes' confirmation.
#   ./teardown.sh --help    # Print usage.
#
# Hard rule: --purge NEVER skips its confirmation. There is intentionally
# no `-y` / `--yes` to bypass. This is destructive; we make the user type.
# =============================================================================
set -euo pipefail

readonly OPENCTI_PROJECT="opencti"
readonly TPOT2CTI_PROJECT="tpot2cti"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PURGE=0

print_help() {
    cat <<'EOF'
Usage: ./teardown.sh [--purge] [--help]

  (no args)   Stop both stacks. Data volumes and host directories preserved.
  --purge     Also remove data/, logs/, ssh-keys/, opencti/ and prune unused
              Docker volumes. INTERACTIVE confirmation required.
  --help      Show this message and exit.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --purge) PURGE=1 ;;
            -h|--help) print_help; exit 0 ;;
            *) echo "Unknown argument: $1 (try --help)" >&2; exit 1 ;;
        esac
        shift
    done
}

confirm_stop() {
    echo "" >&2
    echo "About to stop both compose stacks:" >&2
    echo "  - tpot2cti (project: $TPOT2CTI_PROJECT)" >&2
    echo "  - opencti  (project: $OPENCTI_PROJECT)" >&2
    if (( PURGE )); then
        echo "  Then PURGE host data dirs and Docker volumes." >&2
    else
        echo "  Data volumes will be preserved." >&2
    fi
    echo "" >&2
    read -r -p "Continue? [y/N] " answer
    case "${answer,,}" in
        y|yes) return 0 ;;
        *) echo "[abort] Cancelled." >&2; exit 1 ;;
    esac
}

stop_stacks() {
    echo "" >&2
    echo "=== Stopping tpot2cti stack ===" >&2
    if [[ -f "${SCRIPT_DIR}/docker-compose.yml" ]]; then
        local envfile=""
        if [[ -f "${SCRIPT_DIR}/tpot2cti/.env" ]]; then
            envfile="--env-file ${SCRIPT_DIR}/tpot2cti/.env"
        fi
        # shellcheck disable=SC2086
        (cd "$SCRIPT_DIR" && docker compose $envfile -p "$TPOT2CTI_PROJECT" down) || true
    else
        echo "[info] no docker-compose.yml at $SCRIPT_DIR; skipping tpot2cti down" >&2
    fi

    echo "" >&2
    echo "=== Stopping OpenCTI stack ===" >&2
    if [[ -d "${SCRIPT_DIR}/opencti" ]]; then
        (cd "${SCRIPT_DIR}/opencti" && docker compose -p "$OPENCTI_PROJECT" down) || true
    else
        echo "[info] no opencti/ directory; skipping opencti down" >&2
    fi

    echo "" >&2
    echo "[ok] Both stacks stopped. Data preserved (unless --purge)." >&2
}

confirm_purge() {
    echo "" >&2
    echo "===========================================================================" >&2
    echo "  PURGE: about to permanently delete the following:" >&2
    echo "===========================================================================" >&2
    echo "  - ${SCRIPT_DIR}/data/" >&2
    echo "  - ${SCRIPT_DIR}/logs/" >&2
    echo "  - ${SCRIPT_DIR}/ssh-keys/" >&2
    echo "  - ${SCRIPT_DIR}/opencti/   (the cloned OpenCTI repo)" >&2
    echo "  - all unused Docker volumes (docker volume prune -f)" >&2
    echo "" >&2
    echo "  Type 'yes' (lowercase, full word) to continue, anything else to abort:" >&2

    local answer
    read -r answer
    if [[ "$answer" != "yes" ]]; then
        echo "[abort] Purge cancelled." >&2
        exit 1
    fi
}

do_purge() {
    confirm_purge

    echo "" >&2
    echo "=== Removing host directories ===" >&2
    for d in data logs ssh-keys opencti; do
        local path="${SCRIPT_DIR}/${d}"
        if [[ -e "$path" ]]; then
            rm -rf "$path"
            echo "[ok] removed $path" >&2
        fi
    done

    # Recreate the empty placeholder dirs we ship with the repo so the next
    # setup.sh has a place to put things.
    mkdir -p "${SCRIPT_DIR}/data" "${SCRIPT_DIR}/logs" "${SCRIPT_DIR}/ssh-keys"

    echo "" >&2
    echo "=== Pruning unused Docker volumes ===" >&2
    docker volume prune -f || true

    echo "" >&2
    echo "[ok] Purge complete." >&2
}

main() {
    parse_args "$@"
    confirm_stop
    stop_stacks
    if (( PURGE )); then
        do_purge
    fi
}

main "$@"
