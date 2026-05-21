#!/usr/bin/env bash
# =============================================================================
# tpot2cti — update
#
# Implements V1_SPEC.md §9 "Sister scripts: teardown.sh and update.sh".
#
#   ./update.sh            # git pull tpot2cti, rebuild & restart our stack.
#   ./update.sh --opencti  # Also bump OpenCTI to the version pinned in setup.sh.
#   ./update.sh --help     # Print usage.
#
# Per V1_SPEC §9: when --opencti is passed, we read the OPENCTI_VERSION value
# (and OPENCTI_GIT_REF) from setup.sh, compare with the currently checked-out
# ref under opencti/, and if they differ, fetch + checkout + recompose.
#
# Both modes WARN about backups before proceeding.
# =============================================================================
set -euo pipefail

readonly OPENCTI_PROJECT="opencti"
readonly TPOT2CTI_PROJECT="tpot2cti"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DO_OPENCTI=0

print_help() {
    cat <<'EOF'
Usage: ./update.sh [--opencti] [--help]

  (no args)   Pull latest tpot2cti from origin/main; rebuild & restart our stack.
  --opencti   Also bump OpenCTI to the version pinned in setup.sh
              (cd opencti && git fetch && git checkout <ref> && compose up -d).
  --help      Show this message and exit.

Notes:
  - Always back up data/ before running with --opencti. Major OpenCTI
    upgrades may include schema migrations.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --opencti) DO_OPENCTI=1 ;;
            -h|--help) print_help; exit 0 ;;
            *) echo "Unknown argument: $1 (try --help)" >&2; exit 1 ;;
        esac
        shift
    done
}

ask_yes_no() {
    local prompt="$1" default="${2:-n}" hint
    if [[ "$default" == "y" ]]; then hint="[Y/n]"; else hint="[y/N]"; fi
    local answer
    read -r -p "$prompt $hint " answer
    answer="${answer:-$default}"
    case "${answer,,}" in y|yes) return 0 ;; *) return 1 ;; esac
}

update_tpot2cti() {
    echo "" >&2
    echo "=== Updating tpot2cti ===" >&2

    if [[ ! -d "${SCRIPT_DIR}/.git" ]]; then
        echo "[warn] $SCRIPT_DIR is not a git checkout; skipping git pull" >&2
    else
        (cd "$SCRIPT_DIR" && git fetch && git pull origin main) >&2 || {
            echo "[warn] git pull failed; continuing with current code" >&2
        }
    fi

    echo "" >&2
    echo "=== Rebuilding + restarting tpot2cti stack ===" >&2
    local envfile=""
    if [[ -f "${SCRIPT_DIR}/tpot2cti/.env" ]]; then
        envfile="--env-file ${SCRIPT_DIR}/tpot2cti/.env"
    fi
    # shellcheck disable=SC2086
    (cd "$SCRIPT_DIR" && docker compose $envfile -p "$TPOT2CTI_PROJECT" build --pull) >&2
    # shellcheck disable=SC2086
    (cd "$SCRIPT_DIR" && docker compose $envfile -p "$TPOT2CTI_PROJECT" up -d) >&2

    echo "[ok] tpot2cti updated." >&2
}

# Read the OPENCTI_GIT_REF + OPENCTI_VERSION values from setup.sh — that's the
# single source of truth for the version pin per V1_SPEC §2.
read_pinned_ref() {
    local setup="${SCRIPT_DIR}/setup.sh"
    [[ -f "$setup" ]] || { echo "[fail] setup.sh missing — can't determine pinned OpenCTI ref" >&2; exit 1; }
    PINNED_REF="$(grep -E '^readonly OPENCTI_GIT_REF=' "$setup" | head -1 | sed -E 's/^[^"]*"([^"]+)".*/\1/')"
    PINNED_VERSION="$(grep -E '^readonly OPENCTI_VERSION=' "$setup" | head -1 | sed -E 's/^[^"]*"([^"]+)".*/\1/')"
    [[ -n "$PINNED_REF" ]] || { echo "[fail] could not parse OPENCTI_GIT_REF from setup.sh" >&2; exit 1; }
}

update_opencti() {
    echo "" >&2
    echo "=== Updating OpenCTI ===" >&2

    if [[ ! -d "${SCRIPT_DIR}/opencti/.git" ]]; then
        echo "[fail] No opencti/ checkout found. Run ./setup.sh first." >&2
        exit 1
    fi

    read_pinned_ref
    echo "[info] Target ref: $PINNED_REF  (image version: $PINNED_VERSION)" >&2

    local current
    current="$(git -C "${SCRIPT_DIR}/opencti" rev-parse --abbrev-ref HEAD 2>/dev/null || git -C "${SCRIPT_DIR}/opencti" describe --tags --exact-match 2>/dev/null || echo unknown)"
    echo "[info] Current ref: $current" >&2

    if [[ "$current" == "$PINNED_REF" ]]; then
        # Even on the same branch, master moves; still do the pull.
        echo "[info] Already on $PINNED_REF; will fetch and fast-forward." >&2
    fi

    echo "" >&2
    echo "WARNING: OpenCTI upgrades may include schema migrations. Back up data/" >&2
    echo "         before proceeding. This script will:" >&2
    echo "  1. cd opencti && git fetch --tags && git checkout $PINNED_REF" >&2
    echo "  2. docker compose -p $OPENCTI_PROJECT pull" >&2
    echo "  3. docker compose -p $OPENCTI_PROJECT up -d" >&2
    echo "" >&2
    ask_yes_no "Proceed with OpenCTI upgrade?" "n" || { echo "[abort] cancelled" >&2; exit 1; }

    (cd "${SCRIPT_DIR}/opencti" && git fetch --tags && git checkout "$PINNED_REF" && git pull --ff-only origin "$PINNED_REF" 2>/dev/null || true) >&2
    (cd "${SCRIPT_DIR}/opencti" && docker compose --env-file .env -p "$OPENCTI_PROJECT" pull) >&2
    (cd "${SCRIPT_DIR}/opencti" && docker compose --env-file .env -p "$OPENCTI_PROJECT" up -d) >&2

    echo "[ok] OpenCTI updated to $PINNED_REF." >&2
}

main() {
    parse_args "$@"

    if (( DO_OPENCTI )); then
        update_opencti
    fi
    update_tpot2cti

    echo "" >&2
    echo "[ok] Update complete." >&2
}

main "$@"
