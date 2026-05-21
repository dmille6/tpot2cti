"""tpot2cti-vault — runtime configuration.

Implements V1_SPEC §8.2 (SFTP malware-sample fetcher sidecar).

Per V1_SPEC §8.2 the vault sidecar makes a DIRECT paramiko SSH connection
to TPOT_HOST:TPOT_SSH_PORT using /ssh-keys/id_ed25519. It does NOT
go through the autossh tunnel container — autossh forwards Elasticsearch
(port 64298), not arbitrary SSH/SFTP. T-Pot's sshd has no trouble with
multiple concurrent sessions, so the duplicate connection is fine.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

_ISO_DURATION_RE = re.compile(
    r"^PT"
    r"(?:(?P<h>\d+(?:\.\d+)?)H)?"
    r"(?:(?P<m>\d+(?:\.\d+)?)M)?"
    r"(?:(?P<s>\d+(?:\.\d+)?)S)?"
    r"$"
)


def _parse_iso_duration_seconds(iso: str, default_seconds: float) -> float:
    if not iso:
        return default_seconds
    m = _ISO_DURATION_RE.match(iso.strip())
    if not m:
        return default_seconds
    h = float(m.group("h") or 0.0)
    mn = float(m.group("m") or 0.0)
    s = float(m.group("s") or 0.0)
    total = h * 3600.0 + mn * 60.0 + s
    return total if total > 0 else default_seconds


# Drop directories on T-Pot per V1_SPEC §8.2.
#
# Each tuple: (honeypot_name, remote_dir_path).
DEFAULT_DROPS: tuple[tuple[str, str], ...] = (
    ("cowrie",    "/data/cowrie/downloads/"),
    ("dionaea",   "/data/dionaea/binaries/"),
    ("honeytrap", "/data/honeytrap/downloads-all/"),
    ("adbhoney",  "/data/adbhoney/downloads/"),
)


@dataclass(frozen=True)
class VaultConfig:
    # T-Pot SSH/SFTP connection (direct from the sidecar — not via tunnel container)
    tpot_host: str
    tpot_ssh_user: str
    tpot_ssh_port: int
    ssh_key_path: str
    known_hosts_path: str
    auto_add_host_key: bool          # True only on first run; track via known_hosts

    # Local storage
    data_dir: str                    # /data (compose binds host ./data/malware-vault/)
    samples_dir: str                 # /data/samples
    state_db_path: str               # /data/vault_state.db

    # Drop directories on T-Pot
    drop_dirs: tuple[tuple[str, str], ...]

    # Cycle behavior
    interval_seconds: float
    sensor_name: str                 # logical sensor id; one sidecar = one T-Pot

    # Healthcheck touch file
    healthcheck_path: str

    # Logging
    log_level: str

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "VaultConfig":
        e = env if env is not None else os.environ
        data_dir = e.get("TPOT2CTI_VAULT_DATA_DIR", "/data")
        return cls(
            tpot_host=e.get("TPOT_HOST", ""),
            tpot_ssh_user=e.get("TPOT_SSH_USER", "tpot"),
            tpot_ssh_port=int(e.get("TPOT_SSH_PORT", "64295")),
            ssh_key_path=e.get("TPOT2CTI_VAULT_KEY", "/ssh-keys/id_ed25519"),
            known_hosts_path=e.get("TPOT2CTI_VAULT_KNOWN_HOSTS", "/ssh-keys/known_hosts"),
            auto_add_host_key=e.get("TPOT2CTI_VAULT_AUTO_ADD_HOST_KEY", "1") == "1",
            data_dir=data_dir,
            samples_dir=os.path.join(data_dir, "samples"),
            state_db_path=os.path.join(data_dir, "vault_state.db"),
            drop_dirs=DEFAULT_DROPS,
            interval_seconds=_parse_iso_duration_seconds(
                e.get("TPOT2CTI_VAULT_INTERVAL", "PT15M"),
                default_seconds=900.0,
            ),
            sensor_name=e.get("OPERATOR_ORG_NAME", "tpot") or "tpot",
            healthcheck_path=e.get("TPOT2CTI_HEALTH_TOUCH", "/tmp/last_cycle_ok"),
            log_level=e.get("LOG_LEVEL", "INFO").upper(),
        )
