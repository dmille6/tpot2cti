#!/usr/bin/env bash
# =============================================================================
# tpot2cti — interactive setup orchestrator
#
# Implements V1_SPEC.md §9 (Setup experience). Walks the operator through:
#
#   1. Prerequisite checks      (docker, RAM, disk)
#   2. Interactive prompts      (T-Pot connection, identity, optional features)
#   3. Clone OpenCTI upstream   (pinned ref, see OPENCTI_VERSION below)
#   4. Generate all secrets     (passwords, tokens, connector UUIDs)
#   5. Populate both .env files (opencti/.env + tpot2cti/.env, kept in sync)
#   6. Generate SSH key         (ed25519, for T-Pot tunnel)
#   7. Test the SSH tunnel      (one-shot ssh -L + curl logstash-* check)
#   8. Start the OpenCTI stack  (~3-5 minutes, polling for healthy)
#   9. Start the tpot2cti stack (with COMPOSE_PROFILES for optional sidecars)
#  10. Final verification       (curl OpenCTI splash, print success banner)
#
# Idempotent where possible: re-runs skip already-completed steps unless
# --force-regen is passed. --dry-run prints what each step WOULD do.
#
# Hard rule: NEVER destroys data without explicit confirmation. The only
# destructive operations live in teardown.sh --purge.
#
# Style notes:
#   - Diagnostics go to stderr; banner output goes to stdout.
#   - No emoji (project-wide style); `===` and `[ok]` / `[fail]` substitutes.
#   - Cite V1_SPEC sections in function-level comments.
# =============================================================================
set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration constants
# -----------------------------------------------------------------------------

# OpenCTI version pin.
#
# Per V1_SPEC §2 "OpenCTI version pinning": this script checks out a specific
# tested OpenCTI version when cloning their docker repo.
#
# AT SCRIPT-WRITE TIME (2026-05-21) we queried:
#   - `gh api repos/OpenCTI-Platform/docker/tags` — returned empty: the docker
#     repo does NOT publish git tags; it pins versions via image tags only and
#     ships from `master`.
#   - `gh api repos/OpenCTI-Platform/opencti/releases` — returned tag list
#     starting with 7.260521.0 (latest stable 7.x at this date).
#
# Decision: pin OPENCTI_GIT_REF to `master` (the only release channel the
# docker repo offers), and document the platform image version (7.260521.0)
# as OPENCTI_VERSION. The image version is informational — upstream's
# docker-compose.yml uses `:latest`, so users get whatever Docker Hub serves
# at pull time. Users wanting a frozen install can manually swap image tags
# in opencti/docker-compose.yml after setup.
readonly OPENCTI_VERSION="7.260521.0"
readonly OPENCTI_GIT_REF="master"
readonly OPENCTI_REPO_URL="https://github.com/OpenCTI-Platform/docker.git"

# Compose project names — used by every `docker compose -p` invocation.
readonly OPENCTI_PROJECT="opencti"
readonly TPOT2CTI_PROJECT="tpot2cti"

# Where setup.sh runs from; resolved at top of main().
SCRIPT_DIR=""

# Flags (parsed by parse_args)
DRY_RUN=0
FORCE_REGEN=0

# Interactive responses (populated by interactive_prompts())
TPOT_HOST=""
TPOT_SSH_USER="tpot"
TPOT_SSH_PORT="64295"
OPERATOR_ORG_NAME=""
TPOT2CTI_DEFAULT_TLP="AMBER"
ENABLE_CREDENTIALS=0
ENABLE_VAULT=0

# -----------------------------------------------------------------------------
# Output helpers
# -----------------------------------------------------------------------------

step() { echo "" >&2; echo "=== $* ===" >&2; }
ok()   { echo "[ok]   $*" >&2; }
warn() { echo "[warn] $*" >&2; }
fail() { echo "[fail] $*" >&2; exit 1; }
info() { echo "[info] $*" >&2; }
dry()  { echo "DRY:   $*" >&2; }

# Prompt for yes/no with a default. Returns 0 for yes, 1 for no.
ask_yes_no() {
    local prompt="$1"
    local default="${2:-n}"
    local hint
    if [[ "$default" == "y" ]]; then hint="[Y/n]"; else hint="[y/N]"; fi
    local answer
    read -r -p "$prompt $hint " answer
    answer="${answer:-$default}"
    case "${answer,,}" in
        y|yes) return 0 ;;
        *) return 1 ;;
    esac
}

# Prompt with a default value; echoes the chosen value to stdout.
ask_with_default() {
    local prompt="$1"
    local default="$2"
    local var
    if [[ -n "$default" ]]; then
        read -r -p "$prompt [$default] " var
        echo "${var:-$default}"
    else
        read -r -p "$prompt " var
        echo "$var"
    fi
}

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------

print_help() {
    cat <<'EOF'
Usage: ./setup.sh [OPTIONS]

Interactive orchestrator for installing tpot2cti + OpenCTI.
See V1_SPEC.md §9 for the full step sequence.

Options:
  --dry-run        Print what each step would do, but execute nothing.
  --force-regen    Regenerate secrets and re-clone OpenCTI even if present.
  -h, --help       Show this help and exit.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=1 ;;
            --force-regen) FORCE_REGEN=1 ;;
            -h|--help) print_help; exit 0 ;;
            *) fail "Unknown argument: $1 (try --help)" ;;
        esac
        shift
    done
}

# -----------------------------------------------------------------------------
# Step 1: Prerequisites
# Per V1_SPEC §9 step 1: docker 24+, compose plugin, git, RAM >=16GB, disk >=100GB.
# -----------------------------------------------------------------------------

check_prereqs() {
    step "Step 1/10: Checking prerequisites"

    if (( DRY_RUN )); then
        dry "docker info / docker compose version / git --version / free -g / df -BG ."
        return 0
    fi

    # Docker engine
    if ! command -v docker >/dev/null 2>&1; then
        fail "docker not found in PATH. Install Docker Engine 24+ per https://docs.docker.com/engine/install/"
    fi
    local docker_ver
    docker_ver="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
    if [[ -z "$docker_ver" ]]; then
        fail "docker installed but not reachable. Is the daemon running? Try: sudo systemctl start docker"
    fi
    local docker_major="${docker_ver%%.*}"
    if (( docker_major < 24 )); then
        warn "Docker $docker_ver detected; v1.0 tested against Engine 24+. Continuing."
    else
        ok "Docker Engine $docker_ver"
    fi

    # Compose plugin
    if ! docker compose version >/dev/null 2>&1; then
        fail "docker compose plugin missing. Install via 'docker-compose-plugin' package."
    fi
    ok "docker compose plugin: $(docker compose version --short 2>/dev/null || echo unknown)"

    # git
    if ! command -v git >/dev/null 2>&1; then
        fail "git not found in PATH."
    fi
    ok "git: $(git --version | awk '{print $3}')"

    # RAM
    local ram_gb
    ram_gb="$(free -g | awk '/^Mem:/ {print $2}')"
    if (( ram_gb < 16 )); then
        warn "Detected ${ram_gb}G RAM; V1_SPEC §11 calls for >=16GB."
        ask_yes_no "Continue anyway?" "n" || fail "Aborted by user (insufficient RAM)."
    elif (( ram_gb < 32 )); then
        warn "Detected ${ram_gb}G RAM; OpenCTI runs better with 32GB."
        ok "RAM check: ${ram_gb}GB (minimum met)"
    else
        ok "RAM: ${ram_gb}GB (recommended)"
    fi

    # Free disk on the current filesystem
    local disk_free_gb
    disk_free_gb="$(df -BG . | awk 'NR==2 {sub("G","",$4); print $4}')"
    if (( disk_free_gb < 100 )); then
        warn "Only ${disk_free_gb}G free here; V1_SPEC §11 calls for >=100GB."
        ask_yes_no "Continue anyway?" "n" || fail "Aborted by user (insufficient disk)."
    else
        ok "Free disk: ${disk_free_gb}GB"
    fi

    # openssl + uuidgen — used in step 4
    if ! command -v openssl >/dev/null 2>&1; then
        fail "openssl not found in PATH (needed for secret generation)."
    fi
    if ! command -v uuidgen >/dev/null 2>&1; then
        fail "uuidgen not found in PATH (install uuid-runtime on Debian/Ubuntu)."
    fi
    # ssh-keygen, ssh, curl
    for cmd in ssh-keygen ssh curl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            fail "$cmd not found in PATH."
        fi
    done
    ok "Required tools present: openssl, uuidgen, ssh-keygen, ssh, curl"
}

# -----------------------------------------------------------------------------
# Step 2: Interactive prompts
# Per V1_SPEC §9 step 2.
# -----------------------------------------------------------------------------

interactive_prompts() {
    step "Step 2/10: Interactive configuration"

    if (( DRY_RUN )); then
        dry "Would prompt for TPOT_HOST, TPOT_SSH_USER, TPOT_SSH_PORT,"
        dry "OPERATOR_ORG_NAME, TPOT2CTI_DEFAULT_TLP, enable credentials?, enable vault?"
        # Set placeholders so downstream dry-run steps have something to show.
        TPOT_HOST="tpot.example.invalid"
        OPERATOR_ORG_NAME="DRY-RUN Operator"
        return 0
    fi

    # If tpot2cti/.env already populated with non-empty TPOT_HOST and no --force-regen,
    # offer to skip prompting.
    if [[ -f "${SCRIPT_DIR}/.env" ]] && ! (( FORCE_REGEN )); then
        if grep -qE '^TPOT_HOST=.+' "${SCRIPT_DIR}/.env"; then
            info "Existing tpot2cti/.env detected. Re-using its values (pass --force-regen to override)."
            # shellcheck disable=SC1091
            set -a; source "${SCRIPT_DIR}/.env"; set +a
            ENABLE_CREDENTIALS=0
            ENABLE_VAULT=0
            [[ "${COMPOSE_PROFILES:-}" == *credentials* ]] && ENABLE_CREDENTIALS=1
            [[ "${COMPOSE_PROFILES:-}" == *vault* ]] && ENABLE_VAULT=1
            return 0
        fi
    fi

    TPOT_HOST="$(ask_with_default 'T-Pot hostname or IP:' '')"
    [[ -n "$TPOT_HOST" ]] || fail "TPOT_HOST is required."
    TPOT_SSH_USER="$(ask_with_default 'T-Pot SSH user:' 'tpot')"
    TPOT_SSH_PORT="$(ask_with_default 'T-Pot SSH port:' '64295')"

    OPERATOR_ORG_NAME="$(ask_with_default 'Operator organization name (appears in STIX):' 'T-Pot Operator')"

    echo "  Valid TLP choices: WHITE, GREEN, AMBER, AMBER+STRICT, RED" >&2
    TPOT2CTI_DEFAULT_TLP="$(ask_with_default 'Default TLP marking:' 'AMBER')"

    if ask_yes_no "Enable optional 'credentials' sidecar (DuckDB credential analytics)?" "n"; then
        ENABLE_CREDENTIALS=1
    fi
    if ask_yes_no "Enable optional 'vault' sidecar (SFTP malware-sample fetcher)?" "n"; then
        ENABLE_VAULT=1
    fi

    ok "Interactive configuration captured"
}

# -----------------------------------------------------------------------------
# Step 3: Clone OpenCTI
# Per V1_SPEC §9 step 3.
# -----------------------------------------------------------------------------

clone_opencti() {
    step "Step 3/10: Cloning OpenCTI upstream (ref=$OPENCTI_GIT_REF image=$OPENCTI_VERSION)"

    local target="${SCRIPT_DIR}/opencti"

    if (( DRY_RUN )); then
        dry "git clone $OPENCTI_REPO_URL $target"
        dry "git -C $target checkout $OPENCTI_GIT_REF"
        return 0
    fi

    if [[ -d "$target/.git" ]] && ! (( FORCE_REGEN )); then
        info "OpenCTI already cloned at $target — skipping (use --force-regen to re-clone)."
        [[ -f "$target/.env.sample" ]] || fail "$target/.env.sample missing; corrupted clone? Re-run with --force-regen."
        [[ -f "$target/docker-compose.yml" ]] || fail "$target/docker-compose.yml missing; corrupted clone? Re-run with --force-regen."
        ok "OpenCTI repo verified"
        return 0
    fi

    if (( FORCE_REGEN )) && [[ -d "$target" ]]; then
        warn "Removing existing $target (--force-regen)"
        rm -rf "$target"
    fi

    git clone "$OPENCTI_REPO_URL" "$target" >&2
    git -C "$target" checkout "$OPENCTI_GIT_REF" >&2

    [[ -f "$target/.env.sample" ]] || fail "Clone succeeded but .env.sample missing — upstream layout changed?"
    [[ -f "$target/docker-compose.yml" ]] || fail "Clone succeeded but docker-compose.yml missing — upstream layout changed?"
    ok "OpenCTI cloned to $target"
}

# -----------------------------------------------------------------------------
# Step 4: Generate secrets
# Per V1_SPEC §9 step 4. Populates the GEN_* env vars used in step 5.
# -----------------------------------------------------------------------------

generate_secrets() {
    step "Step 4/10: Generating secrets"

    if (( DRY_RUN )); then
        dry "Generate OPENCTI_ADMIN_PASSWORD (24-char), OPENCTI_ADMIN_TOKEN (UUIDv4),"
        dry "RABBITMQ_DEFAULT_PASS, MINIO_ROOT_PASSWORD, OPENSEARCH_ADMIN_PASSWORD,"
        dry "OPENCTI_HEALTHCHECK_ACCESS_KEY, OPENCTI_ENCRYPTION_KEY (base64-32),"
        dry "UUIDs for every CONNECTOR_*_ID placeholder in opencti/.env.sample,"
        dry "and UUIDs for TPOT2CTI_{,CREDENTIALS_,VAULT_}CONNECTOR_ID."
        dry "Auto-set ELASTIC_MEMORY_SIZE based on detected RAM."
        return 0
    fi

    GEN_OPENCTI_ADMIN_PASSWORD="$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)"
    GEN_OPENCTI_ADMIN_TOKEN="$(uuidgen)"
    GEN_RABBITMQ_DEFAULT_PASS="$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)"
    GEN_MINIO_ROOT_PASSWORD="$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)"
    GEN_OPENSEARCH_ADMIN_PASSWORD="$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)"
    GEN_OPENCTI_HEALTHCHECK_ACCESS_KEY="$(uuidgen)"
    # OPENCTI_ENCRYPTION_KEY: 32-byte base64
    GEN_OPENCTI_ENCRYPTION_KEY="$(openssl rand -base64 32)"

    # tpot2cti connector UUIDs
    GEN_TPOT2CTI_CONNECTOR_ID="$(uuidgen)"
    GEN_TPOT2CTI_CREDENTIALS_CONNECTOR_ID="$(uuidgen)"
    GEN_TPOT2CTI_VAULT_CONNECTOR_ID="$(uuidgen)"

    # Per V1_SPEC §11: ELASTIC_MEMORY_SIZE auto-set
    local ram_gb
    ram_gb="$(free -g | awk '/^Mem:/ {print $2}')"
    if (( ram_gb >= 32 )); then
        GEN_ELASTIC_MEMORY_SIZE="4G"
    else
        GEN_ELASTIC_MEMORY_SIZE="2G"
    fi
    info "ELASTIC_MEMORY_SIZE auto-set to $GEN_ELASTIC_MEMORY_SIZE (detected ${ram_gb}G host RAM)"

    # Discover every CONNECTOR_*_ID in opencti/.env.sample and generate a fresh UUID
    # for each. Per LESSONS §8.2: empty connector IDs cause BAD_USER_INPUT.
    GEN_CONNECTOR_UUID_MAP=()
    while IFS='=' read -r key _value; do
        if [[ "$key" == CONNECTOR_*_ID ]] || [[ "$key" == XTM_COMPOSER_ID ]]; then
            GEN_CONNECTOR_UUID_MAP+=("$key=$(uuidgen)")
        fi
    done < <(grep -E '^[A-Z_]+=' "${SCRIPT_DIR}/opencti/.env.sample" || true)

    ok "Generated ${#GEN_CONNECTOR_UUID_MAP[@]} OpenCTI connector UUIDs + 3 tpot2cti UUIDs"
}

# -----------------------------------------------------------------------------
# Step 5: Populate both .env files
# Per V1_SPEC §9 step 5.
# -----------------------------------------------------------------------------

populate_env_files() {
    step "Step 5/10: Writing opencti/.env and tpot2cti/.env"

    if (( DRY_RUN )); then
        dry "Write opencti/.env from opencti/.env.sample with substitutions"
        dry "Write tpot2cti/.env from .env.example with substitutions"
        return 0
    fi

    local opencti_env="${SCRIPT_DIR}/opencti/.env"
    local tpot2cti_env="${SCRIPT_DIR}/.env"

    if [[ -f "$opencti_env" ]] && [[ -f "$tpot2cti_env" ]] && ! (( FORCE_REGEN )); then
        info "Both .env files already exist — skipping (use --force-regen to overwrite)"
        return 0
    fi

    # --- opencti/.env -------------------------------------------------------
    cp "${SCRIPT_DIR}/opencti/.env.sample" "$opencti_env"

    _sed_kv() {
        # _sed_kv <file> <key> <value>
        local file="$1" key="$2" value="$3"
        local esc_value
        esc_value="$(printf '%s' "$value" | sed -e 's/[\/&]/\\&/g')"
        sed -i -E "s/^${key}=.*/${key}=${esc_value}/" "$file"
    }

    _sed_kv "$opencti_env" "OPENCTI_ADMIN_PASSWORD" "$GEN_OPENCTI_ADMIN_PASSWORD"
    _sed_kv "$opencti_env" "OPENCTI_ADMIN_TOKEN" "$GEN_OPENCTI_ADMIN_TOKEN"
    _sed_kv "$opencti_env" "OPENCTI_HEALTHCHECK_ACCESS_KEY" "$GEN_OPENCTI_HEALTHCHECK_ACCESS_KEY"
    _sed_kv "$opencti_env" "OPENCTI_ENCRYPTION_KEY" "$GEN_OPENCTI_ENCRYPTION_KEY"
    _sed_kv "$opencti_env" "RABBITMQ_DEFAULT_PASS" "$GEN_RABBITMQ_DEFAULT_PASS"
    _sed_kv "$opencti_env" "MINIO_ROOT_PASSWORD" "$GEN_MINIO_ROOT_PASSWORD"
    _sed_kv "$opencti_env" "OPENSEARCH_ADMIN_PASSWORD" "$GEN_OPENSEARCH_ADMIN_PASSWORD"
    _sed_kv "$opencti_env" "ELASTIC_MEMORY_SIZE" "$GEN_ELASTIC_MEMORY_SIZE"

    for kv in "${GEN_CONNECTOR_UUID_MAP[@]}"; do
        local k="${kv%%=*}" v="${kv#*=}"
        _sed_kv "$opencti_env" "$k" "$v"
    done

    chmod 600 "$opencti_env"
    ok "Wrote $opencti_env (mode 600)"

    # --- tpot2cti/.env ------------------------------------------------------
    local profiles=""
    if (( ENABLE_CREDENTIALS )) && (( ENABLE_VAULT )); then
        profiles="credentials,vault"
    elif (( ENABLE_CREDENTIALS )); then
        profiles="credentials"
    elif (( ENABLE_VAULT )); then
        profiles="vault"
    fi

    cat > "$tpot2cti_env" <<EOF
# tpot2cti — generated by setup.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Edit with care; setup.sh --force-regen will overwrite.

# === T-Pot connection ===
TPOT_HOST=${TPOT_HOST}
TPOT_SSH_USER=${TPOT_SSH_USER}
TPOT_SSH_PORT=${TPOT_SSH_PORT}

# Self-filter: src_ip values to drop before parsing. Auto-seeded with
# the T-Pot host (so Suricata events from our own deceptive HTTP
# responses don't get attributed as attacker activity). Add hive +
# bastion IPs here too — see .env.example for full guidance.
TPOT_HONEYPOT_IPS=${TPOT_HOST}

# === Operator identity ===
OPERATOR_ORG_NAME=${OPERATOR_ORG_NAME}
TPOT2CTI_DEFAULT_TLP=${TPOT2CTI_DEFAULT_TLP}
TPOT2CTI_DEFAULT_CONFIDENCE=75

# === Cycle behavior ===
TPOT2CTI_INTERVAL=PT15M
TPOT2CTI_INITIAL_LOOKBACK_HOURS=0
# P0f default-ignored per the V0 "two-question rule" (slowly-evolving enrichment data belongs in a separate cadence, not the bulk-import loop) (the "two-question rule"):
# P0f is enrichment-shaped passive fingerprint data, not actionable
# attack-event data. ~2.3M events/day fleet-wide if ingested.
TPOT2CTI_IGNORE_TYPES=P0f
# Per PoC HP_CONNECTOR_HANDOFF §4: indexing delay between the three
# publisher passes. 60s is safe for single-sensor; hive operators
# should raise to 120-300s. Watch the cycle log for "cycle overrun"
# warnings — that's the signal to increase this.
TPOT2CTI_INDEXING_DELAY_SECONDS=60
# FATT events are slowly-evolving passive fingerprints; running them
# every cycle is wasteful. Multiplier=4 with PT15M base interval =
# FATT processed every ~60 min. Set 1 to process every cycle.
TPOT2CTI_FATT_CYCLE_MULTIPLIER=4

# === OpenCTI connection (mirrors opencti/.env) ===
OPENCTI_URL=http://opencti:8080
OPENCTI_ADMIN_TOKEN=${GEN_OPENCTI_ADMIN_TOKEN}

# === Connector UUIDs ===
TPOT2CTI_CONNECTOR_ID=${GEN_TPOT2CTI_CONNECTOR_ID}
TPOT2CTI_CREDENTIALS_CONNECTOR_ID=${GEN_TPOT2CTI_CREDENTIALS_CONNECTOR_ID}
TPOT2CTI_VAULT_CONNECTOR_ID=${GEN_TPOT2CTI_VAULT_CONNECTOR_ID}

# === Compose profiles (optional sidecars) ===
COMPOSE_PROFILES=${profiles}

# === Network attachment ===
OPENCTI_NETWORK_NAME=opencti_default

# === Logging ===
LOG_LEVEL=INFO

# === Sidecar cycle intervals (optional, defaults shown) ===
TPOT2CTI_CREDENTIALS_INTERVAL=PT60M
TPOT2CTI_VAULT_INTERVAL=PT15M
EOF
    chmod 600 "$tpot2cti_env"
    ok "Wrote $tpot2cti_env (mode 600)"
}

# -----------------------------------------------------------------------------
# Step 6: Generate SSH key for T-Pot tunnel
# Per V1_SPEC §9 step 6.
# -----------------------------------------------------------------------------

setup_ssh_key() {
    step "Step 6/10: SSH key for T-Pot tunnel"

    local key_dir="${SCRIPT_DIR}/ssh-keys"
    local key_path="${key_dir}/id_ed25519"

    if (( DRY_RUN )); then
        dry "mkdir -p $key_dir && chmod 700 $key_dir"
        dry "ssh-keygen -t ed25519 -f $key_path -N '' -C 'tpot2cti@$(hostname)'"
        dry "Test pubkey auth to ${TPOT_SSH_USER}@${TPOT_HOST}:${TPOT_SSH_PORT}"
        dry "If pubkey auth fails: prompt 'install via ssh-copy-id now? [Y/n]'"
        dry "If user says yes: ssh-copy-id -i ${key_path}.pub -p ${TPOT_SSH_PORT} ${TPOT_SSH_USER}@${TPOT_HOST}"
        dry "Otherwise fall back to manual paste + Enter prompt"
        return 0
    fi

    mkdir -p "$key_dir"
    chmod 700 "$key_dir"

    if [[ -f "$key_path" ]] && ! (( FORCE_REGEN )); then
        info "SSH key already exists at $key_path — skipping generation"
    else
        if (( FORCE_REGEN )) && [[ -f "$key_path" ]]; then
            warn "Removing existing SSH key (--force-regen): $key_path"
            rm -f "$key_path" "${key_path}.pub"
        fi
        ssh-keygen -t ed25519 -f "$key_path" -N "" -C "tpot2cti@$(hostname)" >&2
        chmod 600 "$key_path"
        ok "Generated ed25519 key at $key_path"
    fi

    local known_hosts="${key_dir}/known_hosts"

    # ── Auto-install path ─────────────────────────────────────────────
    # First check if the key is ALREADY authorized on T-Pot (idempotent
    # re-run of setup.sh). If so, nothing to do.
    info "Checking whether pubkey auth already works against T-Pot…"
    if ssh -o BatchMode=yes \
           -o PreferredAuthentications=publickey \
           -o StrictHostKeyChecking=accept-new \
           -o UserKnownHostsFile="${known_hosts}" \
           -o ConnectTimeout=5 \
           -i "$key_path" \
           -p "$TPOT_SSH_PORT" \
           "${TPOT_SSH_USER}@${TPOT_HOST}" \
           'true' >/dev/null 2>&1; then
        ok "Pubkey is already installed on T-Pot — skipping ssh-copy-id"
        return 0
    fi

    # Show the key + offer to install it automatically.
    echo "" >&2
    echo "--------------------------------------------------------------------" >&2
    echo "  PUBLIC KEY (must end up in T-Pot's authorized_keys):" >&2
    echo "--------------------------------------------------------------------" >&2
    cat "${key_path}.pub" >&2
    echo "--------------------------------------------------------------------" >&2
    echo "" >&2

    local default_choice="Y"
    if ! command -v ssh-copy-id >/dev/null 2>&1; then
        warn "ssh-copy-id not found on this host; manual install required."
        default_choice=""
    fi

    if [[ "$default_choice" == "Y" ]]; then
        local answer
        read -r -p \
"Would you like me to install the key on T-Pot now via ssh-copy-id?
This will prompt you for your T-Pot password ONCE. [Y/n] " answer
        # Default to Y on empty input.
        if [[ -z "$answer" ]] || [[ "$answer" =~ ^[Yy] ]]; then
            echo "" >&2
            info "Running: ssh-copy-id -i ${key_path}.pub -p ${TPOT_SSH_PORT} ${TPOT_SSH_USER}@${TPOT_HOST}"
            info "(if you've never logged into this T-Pot from here, you'll see"
            info " a host-key fingerprint prompt — answer 'yes' to accept.)"
            echo "" >&2

            # `accept-new` auto-trusts the T-Pot host key on first use
            # (we don't have a baked-in fingerprint to verify against).
            # ssh-copy-id passes -o options through via -o … on the cmd line.
            if ssh-copy-id \
                -i "${key_path}.pub" \
                -p "$TPOT_SSH_PORT" \
                -o "StrictHostKeyChecking=accept-new" \
                -o "UserKnownHostsFile=${known_hosts}" \
                "${TPOT_SSH_USER}@${TPOT_HOST}" >&2; then

                # Verify pubkey auth actually works now.
                if ssh -o BatchMode=yes \
                       -o PreferredAuthentications=publickey \
                       -o StrictHostKeyChecking=accept-new \
                       -o UserKnownHostsFile="${known_hosts}" \
                       -o ConnectTimeout=5 \
                       -i "$key_path" \
                       -p "$TPOT_SSH_PORT" \
                       "${TPOT_SSH_USER}@${TPOT_HOST}" \
                       'true' >/dev/null 2>&1; then
                    ok "Key installed and pubkey auth verified."
                    return 0
                else
                    warn "ssh-copy-id reported success but pubkey auth still fails."
                    warn "Falling back to manual-install path…"
                fi
            else
                warn "ssh-copy-id failed (wrong password, network, or T-Pot's"
                warn "sshd config). Falling back to manual-install path…"
            fi
        else
            info "Skipping automated install (per your choice)."
        fi
    fi

    # ── Manual fallback ──────────────────────────────────────────────
    echo "" >&2
    echo "To install the key manually:" >&2
    echo "" >&2
    echo "  1. Open a NEW terminal on this host and run either:" >&2
    echo "       ssh-copy-id -i ${key_path}.pub -p ${TPOT_SSH_PORT} ${TPOT_SSH_USER}@${TPOT_HOST}" >&2
    echo "     (or, if ssh-copy-id is unavailable, log into T-Pot and append the" >&2
    echo "      key above to ~/.ssh/authorized_keys yourself)" >&2
    echo "" >&2
    echo "  2. Come back here when done." >&2
    echo "" >&2
    read -r -p "Press Enter once the key is installed on T-Pot…" _
}

# -----------------------------------------------------------------------------
# Step 7: Test the SSH tunnel
# Per V1_SPEC §9 step 7. Open a one-shot tunnel, hit ES via curl, tear down.
# -----------------------------------------------------------------------------

test_ssh_tunnel() {
    step "Step 7/10: Testing SSH tunnel to T-Pot ES"

    if (( DRY_RUN )); then
        dry "ssh -L 19298:127.0.0.1:64298 ${TPOT_SSH_USER}@${TPOT_HOST}:${TPOT_SSH_PORT} -N &"
        dry "curl -sf http://localhost:19298/_cat/indices?h=index | grep logstash-"
        return 0
    fi

    local key_path="${SCRIPT_DIR}/ssh-keys/id_ed25519"
    local tunnel_pid=""

    cleanup_tunnel() {
        if [[ -n "${tunnel_pid:-}" ]]; then
            kill "$tunnel_pid" 2>/dev/null || true
            wait "$tunnel_pid" 2>/dev/null || true
        fi
    }
    trap cleanup_tunnel RETURN

    info "Opening one-shot tunnel: localhost:19298 -> ${TPOT_HOST}:64298 (via :${TPOT_SSH_PORT})"
    # BatchMode + PreferredAuthentications=publickey makes the test FAIL LOUDLY
    # if the user hasn't actually installed the pubkey on T-Pot — the tunnel
    # container has no way to type a password fallback at runtime, so a
    # password-only success here would hide a problem that surfaces at step 9.
    ssh -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="${SCRIPT_DIR}/ssh-keys/known_hosts" \
        -o ExitOnForwardFailure=yes \
        -o ConnectTimeout=10 \
        -o BatchMode=yes \
        -o PreferredAuthentications=publickey \
        -i "$key_path" \
        -p "$TPOT_SSH_PORT" \
        -L "19298:127.0.0.1:64298" \
        -N \
        "${TPOT_SSH_USER}@${TPOT_HOST}" &
    tunnel_pid=$!

    # Wait for the local port to become connectable (up to ~15s).
    local i=0
    while (( i < 15 )); do
        if (echo >/dev/tcp/127.0.0.1/19298) 2>/dev/null; then
            break
        fi
        sleep 1
        i=$((i+1))
    done
    if (( i >= 15 )); then
        if ! kill -0 "$tunnel_pid" 2>/dev/null; then
            fail "SSH tunnel exited before the port came up. Common causes: key not yet added to T-Pot authorized_keys; wrong TPOT_HOST or TPOT_SSH_PORT; T-Pot SSH not listening."
        fi
        fail "SSH tunnel running but localhost:19298 not connectable after 15s"
    fi

    local indices
    indices="$(curl -sf "http://localhost:19298/_cat/indices?h=index" --max-time 10 || true)"
    if [[ -z "$indices" ]]; then
        fail "curl to local ES tunnel returned empty/failed. Is T-Pot ES (:64298) listening on the T-Pot box?"
    fi
    if ! echo "$indices" | grep -q '^logstash-'; then
        warn "No logstash-* index found yet. T-Pot may not have ingested any events."
        echo "$indices" | head -5 >&2
        ask_yes_no "Continue anyway?" "n" || fail "Aborted by user."
    else
        local n
        n="$(echo "$indices" | grep -c '^logstash-')"
        ok "ES tunnel verified ($n logstash-* indices visible)"
    fi
}

# -----------------------------------------------------------------------------
# Step 8: Start the OpenCTI stack
# Per V1_SPEC §9 step 8.
# -----------------------------------------------------------------------------

start_opencti() {
    step "Step 8/10: Starting OpenCTI stack (this takes 3-5 minutes)"

    if (( DRY_RUN )); then
        dry "(cd ${SCRIPT_DIR}/opencti && docker compose -p $OPENCTI_PROJECT up -d)"
        dry "Poll docker compose ps until all containers report healthy (timeout 600s)"
        dry "Verify docker network inspect opencti_default succeeds"
        return 0
    fi

    (
        cd "${SCRIPT_DIR}/opencti"
        docker compose --env-file .env -p "$OPENCTI_PROJECT" up -d >&2
    )

    info "Polling for OpenCTI containers to become healthy (max 600s)"
    local waited=0
    local max=600
    while (( waited < max )); do
        local ps_out
        ps_out="$(docker compose -p "$OPENCTI_PROJECT" ps --format json 2>/dev/null || true)"
        if [[ -n "$ps_out" ]]; then
            if echo "$ps_out" | grep -qiE '"Health":"unhealthy"|"State":"restarting"'; then
                : # still bad
            elif echo "$ps_out" | grep -qE '"State":"running"'; then
                local code
                code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://localhost:8080" || echo 000)"
                if [[ "$code" == "200" ]] || [[ "$code" == "401" ]] || [[ "$code" == "302" ]]; then
                    ok "OpenCTI responding at http://localhost:8080 (HTTP $code)"
                    break
                fi
            fi
        fi
        sleep 10
        waited=$((waited+10))
        if (( waited % 60 == 0 )); then
            info "  ... still waiting ($waited / $max s)"
        fi
    done
    if (( waited >= max )); then
        warn "OpenCTI didn't reach healthy in ${max}s. Containers left running for you to debug:"
        warn "  docker compose -p $OPENCTI_PROJECT ps"
        warn "  docker compose -p $OPENCTI_PROJECT logs --tail=200"
        fail "OpenCTI startup timeout"
    fi

    if ! docker network inspect opencti_default >/dev/null 2>&1; then
        # OpenCTI's compose may name the network based on COMPOSE_PROJECT_NAME (xtm by default).
        if docker network inspect "${OPENCTI_PROJECT}_default" >/dev/null 2>&1; then
            warn "Network found under '${OPENCTI_PROJECT}_default' (not 'opencti_default'). Our compose expects 'opencti_default'; you may need to set OPENCTI_NETWORK_NAME in tpot2cti/.env."
        else
            fail "OpenCTI 'opencti_default' network not found"
        fi
    else
        ok "Network opencti_default exists"
    fi
}

# -----------------------------------------------------------------------------
# Step 9: Start the tpot2cti stack
# Per V1_SPEC §9 step 9.
# -----------------------------------------------------------------------------

start_tpot2cti() {
    step "Step 9/10: Starting tpot2cti stack"

    if (( DRY_RUN )); then
        dry "Pre-create ${SCRIPT_DIR}/data/{tpot2cti,credentials,malware-vault} and logs/ as the invoking user"
        dry "(cd $SCRIPT_DIR && docker compose --env-file ./.env -p $TPOT2CTI_PROJECT up -d --build)"
        dry "Poll tpot2cti-core healthy"
        return 0
    fi

    # Pre-create the bind-mount target dirs as the invoking user, BEFORE
    # docker compose up. If we don't, the docker daemon (running as root)
    # auto-creates the missing dirs as root, and our containers (which
    # run as uid 1000 — tpot2cti, tunnel, credentials, vault) can't
    # write into them. Symptom: sidecars enter a restart loop with
    # "Permission denied" on /data/credentials.duckdb and /data/samples/.
    # This bit us twice during 2026-05-21 installs before we baked the
    # fix in here.
    for d in data/tpot2cti data/credentials data/malware-vault logs; do
        mkdir -p "${SCRIPT_DIR}/${d}"
    done
    ok "Pre-created bind-mount dirs as $(id -un) (uid $(id -u))"

    # Build-time git SHA — baked into the image via Dockerfile ARG so
    # the startup banner can identify which build is running. Best-
    # effort: if not in a git checkout, fall through to "unknown".
    local _git_sha
    _git_sha="$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
    ok "Building tpot2cti image with TPOT2CTI_GIT_SHA=${_git_sha:0:12}"

    (
        cd "$SCRIPT_DIR"
        TPOT2CTI_GIT_SHA="$_git_sha" \
            docker compose --env-file ./.env -p "$TPOT2CTI_PROJECT" up -d --build >&2
    )

    info "Polling for tpot2cti containers to come up (max 120s)"
    local waited=0
    while (( waited < 120 )); do
        if docker compose -p "$TPOT2CTI_PROJECT" ps --format json 2>/dev/null | grep -qE '"State":"running"'; then
            ok "tpot2cti stack running"
            return 0
        fi
        sleep 5
        waited=$((waited+5))
    done
    warn "tpot2cti containers not yet running after 120s. Check: docker compose -p $TPOT2CTI_PROJECT logs"
}

# -----------------------------------------------------------------------------
# Step 10: Final verification + success banner
# Per V1_SPEC §9 step 10.
# -----------------------------------------------------------------------------

final_verification() {
    step "Step 10/10: Final verification"

    if (( DRY_RUN )); then
        dry "curl -sf http://localhost:8080  (verify OpenCTI splash reachable)"
        dry "Print success banner"
        return 0
    fi

    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://localhost:8080" || echo 000)"
    if [[ "$code" != "200" ]] && [[ "$code" != "302" ]] && [[ "$code" != "401" ]]; then
        warn "OpenCTI splash returned HTTP $code (expected 200/302/401). Continuing — it may still be initializing."
    else
        ok "OpenCTI splash reachable (HTTP $code)"
    fi

    # End-to-end smoke: emit a tiny foundation bundle via pycti and verify
    # it lands cleanly. Catches pycti-version-vs-OpenCTI-version mismatches
    # at install time rather than at the first scheduled cycle.
    # The emission is idempotent (UUID5) so re-running setup.sh is a no-op.
    info "Running install self-test (pycti emission to OpenCTI)..."
    if docker exec tpot2cti-core python3 -m tpot2cti.selftest >&2; then
        ok "Self-test passed — first ingestion cycle should succeed."
    else
        warn "Self-test FAILED. The pipeline may still recover on its first scheduled cycle,"
        warn "but inspect the output above for the cause (likely pycti version drift,"
        warn "OpenCTI not fully initialized, or a connector_id misconfiguration)."
        warn "To re-run after fixing: docker exec tpot2cti-core python3 -m tpot2cti.selftest"
    fi

    # Read the OpenCTI admin credentials back out of opencti/.env so the
    # operator can copy/paste straight from the install output rather
    # than `grep ^OPENCTI_ADMIN_PASSWORD opencti/.env`. Defensive: if any
    # field is missing (incomplete install) we fall back to a pointer at
    # the file path so the operator still has a path to recovery.
    local opencti_env="${SCRIPT_DIR}/opencti/.env"
    local oc_email="" oc_password="" oc_token=""
    if [[ -r "$opencti_env" ]]; then
        oc_email="$(grep -E '^OPENCTI_ADMIN_EMAIL=' "$opencti_env" | cut -d= -f2- | head -n1)"
        oc_password="$(grep -E '^OPENCTI_ADMIN_PASSWORD=' "$opencti_env" | cut -d= -f2- | head -n1)"
        oc_token="$(grep -E '^OPENCTI_ADMIN_TOKEN=' "$opencti_env" | cut -d= -f2- | head -n1)"
        # Heads-up if opencti/.env is world- or group-readable. setup.sh
        # writes it 600 in generate_secrets(), but a paranoid umask check
        # never hurt anyone.
        local mode
        mode="$(stat -c '%a' "$opencti_env" 2>/dev/null || echo "?")"
        if [[ "$mode" != "600" ]] && [[ "$mode" != "?" ]]; then
            warn "opencti/.env is mode $mode (expected 600). Consider:  chmod 600 $opencti_env"
        fi
    fi
    : "${oc_email:=admin@opencti.io}"
    : "${oc_password:=<missing — see opencti/.env>}"
    : "${oc_token:=<missing — see opencti/.env>}"

    cat <<EOF

===========================================================================
  Setup complete.

  OpenCTI:    http://localhost:8080
  Username:   ${oc_email}
  Password:   ${oc_password}
  API token:  ${oc_token}

  Credentials are also stored in:  ${opencti_env}
  Treat them like SSH keys — do not commit, do not share over chat.

  First T-Pot ingestion cycle starts within 15 minutes.

  Stop:       ./teardown.sh
  Update:     ./update.sh
  Logs:       docker compose -p $TPOT2CTI_PROJECT logs -f
  OpenCTI:    docker compose -p $OPENCTI_PROJECT logs -f
===========================================================================
EOF
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
    parse_args "$@"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"

    if (( DRY_RUN )); then
        info "*** DRY RUN — no changes will be made ***"
    fi

    check_prereqs
    interactive_prompts
    clone_opencti
    generate_secrets
    populate_env_files
    setup_ssh_key
    test_ssh_tunnel
    start_opencti
    start_tpot2cti
    final_verification
}

main "$@"
