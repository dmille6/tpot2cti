#!/usr/bin/env bash
# enroll-sensor.sh — register a T-Pot sensor with the tpot2cti malware vault.
#
# Bootstrap-to-key model: you enter the sensor's SSH password ONCE; this script
# installs the vault's ed25519 public key, verifies passwordless key auth and
# passwordless sudo-read of the honeypot capture dirs, records the host key, and
# appends the sensor to data/malware-vault/sensors.json. The password is never
# stored — after enrollment the vault pulls samples using key auth only.
#
# Safe to re-run: enrolling an existing sensor name updates that entry in place.
#
#   ./scripts/enroll-sensor.sh                 # interactive
#   ./scripts/enroll-sensor.sh --list          # show enrolled sensors
#   ./scripts/enroll-sensor.sh --remove NAME   # drop a sensor
set -euo pipefail

# --- locate repo + shared paths ----------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
REPO_DIR="$(cd -- "${SCRIPT_DIR}/.." >/dev/null && pwd)"
KEY_DIR="${REPO_DIR}/ssh-keys"
KEY_PATH="${KEY_DIR}/id_ed25519"
KNOWN_HOSTS="${KEY_DIR}/known_hosts"
SENSORS="${REPO_DIR}/data/malware-vault/sensors.json"

# --- pretty output -----------------------------------------------------------
c_step=$'\033[1;36m'; c_ok=$'\033[1;32m'; c_warn=$'\033[1;33m'
c_err=$'\033[1;31m'; c_off=$'\033[0m'
step(){ echo "${c_step}==>${c_off} $*" >&2; }
ok(){   echo "${c_ok}  ok${c_off} $*" >&2; }
warn(){ echo "${c_warn}  !!${c_off} $*" >&2; }
die(){  echo "${c_err} ERR${c_off} $*" >&2; exit 1; }

# --- sensors.json helpers (python3, no jq dependency) ------------------------
have_python(){ command -v python3 >/dev/null 2>&1 || die "python3 is required"; }

sensors_list(){
    have_python
    python3 - "$SENSORS" <<'PY'
import json, os, sys
p = sys.argv[1]
data = json.load(open(p)) if os.path.exists(p) else []
if not data:
    print("  (no sensors enrolled yet)"); sys.exit(0)
w = max(len(s.get("name","")) for s in data)
for s in data:
    print("  %-*s  %s@%s:%s  sudo=%s  data=%s" % (
        w, s.get("name",""), s.get("user",""), s.get("host",""),
        s.get("port",64295), s.get("sudo",True), s.get("data_dir","")))
PY
}

sensors_remove(){
    have_python
    local name="$1"
    python3 - "$SENSORS" "$name" <<'PY'
import json, os, sys
p, name = sys.argv[1], sys.argv[2]
data = json.load(open(p)) if os.path.exists(p) else []
new = [s for s in data if s.get("name") != name]
if len(new) == len(data):
    print("not-found"); sys.exit(0)
json.dump(new, open(p, "w"), indent=2); open(p,"a").write("\n")
print("removed")
PY
}

# Upsert one sensor (replace by name); writes sensors.json mode 0600.
sensors_upsert(){
    have_python
    python3 - "$SENSORS" "$1" "$2" "$3" "$4" "$5" "$6" <<'PY'
import json, os, sys
p, name, host, port, user, sudo, data_dir = sys.argv[1:8]
data = json.load(open(p)) if os.path.exists(p) else []
entry = {"name": name, "host": host, "port": int(port), "user": user,
         "sudo": sudo == "1", "data_dir": data_dir}
data = [s for s in data if s.get("name") != name] + [entry]
os.makedirs(os.path.dirname(p), exist_ok=True)
json.dump(data, open(p, "w"), indent=2); open(p,"a").write("\n")
try: os.chmod(p, 0o600)
except OSError: pass
PY
}

# --- subcommands -------------------------------------------------------------
case "${1:-}" in
    --list|-l) step "Enrolled sensors (${SENSORS}):"; sensors_list; exit 0 ;;
    --remove|-r)
        [[ -n "${2:-}" ]] || die "usage: $0 --remove NAME"
        if [[ "$(sensors_remove "$2")" == "removed" ]]; then
            ok "Removed sensor '$2' (restart the vault to apply)."
        else warn "No sensor named '$2'."; fi
        exit 0 ;;
    -h|--help)
        sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac

# --- preconditions -----------------------------------------------------------
command -v ssh >/dev/null 2>&1 || die "ssh client not found"
command -v ssh-copy-id >/dev/null 2>&1 || die "ssh-copy-id not found (install openssh-client)"
mkdir -p "$KEY_DIR"; chmod 700 "$KEY_DIR"

if [[ ! -f "$KEY_PATH" ]]; then
    step "No vault key yet — generating ${KEY_PATH}"
    ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "tpot2cti-vault@$(hostname)" >&2
    chmod 600 "$KEY_PATH"
    ok "Generated ed25519 key."
fi

# --- prompt for sensor details ----------------------------------------------
ask(){ local p="$1" d="${2:-}" a; if [[ -n "$d" ]]; then
    read -r -p "$p [$d]: " a; echo "${a:-$d}"; else
    read -r -p "$p: " a; echo "$a"; fi; }

step "Enroll a new T-Pot sensor with the malware vault"
NAME="$(ask 'Sensor name (short, e.g. studb, azure-fin)')"
[[ -n "$NAME" ]] || die "sensor name is required"
HOST="$(ask 'Sensor host/IP')"
[[ -n "$HOST" ]] || die "host is required"
PORT="$(ask 'SSH port' '64295')"
USER_="$(ask 'SSH username' 'tpot')"
DATA_DIR="$(ask 'T-Pot data dir on the sensor' '/opt/tpotce/data')"

SSH_BASE=(-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="${KNOWN_HOSTS}" -p "$PORT")
TARGET="${USER_}@${HOST}"

# --- 1) install pubkey (password ONCE) --------------------------------------
step "Checking whether key auth already works to ${TARGET}:${PORT}…"
if ssh -n -o BatchMode=yes -o PreferredAuthentications=publickey -o ConnectTimeout=6 \
       "${SSH_BASE[@]}" -i "$KEY_PATH" "$TARGET" true 2>/dev/null; then
    ok "Key auth already works — skipping ssh-copy-id."
else
    step "Installing vault pubkey (you'll be prompted for the sensor password ONCE)…"
    ssh-copy-id -i "${KEY_PATH}.pub" "${SSH_BASE[@]}" "$TARGET" >&2 \
        || die "ssh-copy-id failed (wrong password, network, or sshd config)."
    ssh -n -o BatchMode=yes -o PreferredAuthentications=publickey -o ConnectTimeout=6 \
        "${SSH_BASE[@]}" -i "$KEY_PATH" "$TARGET" true 2>/dev/null \
        || die "Key installed but pubkey auth still fails — check the sensor's sshd."
    ok "Pubkey installed and key auth verified."
fi

# --- 2) verify passwordless sudo-read of the capture dirs --------------------
# T-Pot captures are owned by uid 2000 mode 0600, so the vault reads them via
# `sudo -n find/cat`. The enrolled account needs passwordless sudo for that.
PROBE_DIR="${DATA_DIR%/}/dionaea/binaries"
SUDO=1
step "Verifying passwordless sudo-read (${PROBE_DIR})…"
if ssh -n -o BatchMode=yes "${SSH_BASE[@]}" -i "$KEY_PATH" "$TARGET" \
       "sudo -n find ${PROBE_DIR} -maxdepth 0" >/dev/null 2>&1; then
    ok "Passwordless sudo works."
else
    warn "Passwordless sudo is NOT configured for '${USER_}' on ${HOST}."
    SUDOERS_LINE="${USER_} ALL=(root) NOPASSWD: /usr/bin/find, /usr/bin/cat, /bin/find, /bin/cat"
    echo "" >&2
    echo "  The vault needs this so it can read the 0600 honeypot captures." >&2
    echo "  Required sudoers entry on ${HOST}:" >&2
    echo "    ${SUDOERS_LINE}" >&2
    echo "" >&2
    read -r -p "Install this sudoers rule now via sudo (prompts the sensor password ONCE)? [Y/n] " a
    if [[ -z "$a" || "$a" =~ ^[Yy] ]]; then
        # Write a dedicated drop-in, validated with visudo -c before activation.
        if ssh -t "${SSH_BASE[@]}" "$TARGET" \
              "echo '${SUDOERS_LINE}' | sudo tee /etc/sudoers.d/tpot2cti-vault >/dev/null \
               && sudo chmod 440 /etc/sudoers.d/tpot2cti-vault \
               && sudo visudo -cf /etc/sudoers.d/tpot2cti-vault" >&2; then
            if ssh -n -o BatchMode=yes "${SSH_BASE[@]}" -i "$KEY_PATH" "$TARGET" \
                   "sudo -n find ${PROBE_DIR} -maxdepth 0" >/dev/null 2>&1; then
                ok "Passwordless sudo installed and verified."
            else
                warn "Installed the rule but sudo-read still fails; enrolling with sudo=false."
                SUDO=0
            fi
        else
            warn "Could not install the sudoers rule; enrolling with sudo=false."
            warn "Without sudo the vault only sees world-readable files (often none)."
            SUDO=0
        fi
    else
        warn "Skipping sudo setup; enrolling with sudo=false."
        SUDO=0
    fi
fi

# --- 3) record host key + write sensors.json ---------------------------------
# accept-new above already wrote the host key into known_hosts.
ok "Host key recorded in ${KNOWN_HOSTS}."

sensors_upsert "$NAME" "$HOST" "$PORT" "$USER_" "$SUDO" "${DATA_DIR%/}"
ok "Wrote ${SENSORS} (entry: ${NAME})."

echo "" >&2
step "Sensor '${NAME}' enrolled. Current inventory:"
sensors_list
echo "" >&2

# Apply immediately by recreating the vault. The vault reads sensors.json once
# at startup, so a new sensor only goes live after a restart — offer to do it
# here so adding a sensor post-install is a single, self-contained step.
RESTART_CMD="docker compose --profile vault up -d --force-recreate tpot2cti-vault"
if command -v docker >/dev/null 2>&1 && [[ -f "${REPO_DIR}/docker-compose.yml" ]]; then
    read -r -p "Restart the vault now so it starts pulling from '${NAME}'? [Y/n] " apply || apply=""
    if [[ -z "$apply" || "$apply" =~ ^[Yy] ]]; then
        if ( cd "$REPO_DIR" && eval "$RESTART_CMD" >&2 ); then
            ok "Vault restarted — it will pull from '${NAME}' on the next cycle."
        else
            warn "Restart failed; apply manually from ${REPO_DIR}:"
            warn "  ${RESTART_CMD}"
        fi
    else
        ok "Apply later from ${REPO_DIR}:  ${RESTART_CMD}"
    fi
else
    ok "Apply from ${REPO_DIR}:  ${RESTART_CMD}"
fi
