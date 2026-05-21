"""tpot2cti-vault — entrypoint.

Implements V1_SPEC §8.2 cycle:

    1. Open paramiko SSH/SFTP to T-Pot.
    2. For each honeypot drop dir (cowrie, dionaea, honeytrap, adbhoney):
         a. listdir
         b. For each file not already in seen_files for this (sensor, honeypot):
              - stream-download to tmp
              - sha256 + size
              - if not in samples: rename tmp -> /data/samples/<sha256>; INSERT samples
              - else: bump capture_count on the existing sample
              - INSERT seen_files
         c. Skip files already in seen_files (idempotency).
    3. Log cycle counts; touch /tmp/last_cycle_ok.
    4. Sleep `interval_seconds`.

Errors per-file: log DEBUG, skip, continue. Errors per-cycle: log WARN,
sleep, retry next cycle.
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
import time
from dataclasses import dataclass
from typing import Iterable

from config import VaultConfig
from log import setup_logging
from sftp_client import RemoteFile, TpotSFTP
from store import VaultStore

logger = logging.getLogger("tpot2cti.vault")


@dataclass
class CycleCounts:
    dirs_scanned: int = 0
    files_listed: int = 0
    files_skipped: int = 0
    files_downloaded: int = 0
    new_samples: int = 0
    bumped_samples: int = 0
    errors: int = 0


def _ensure_dirs(cfg: VaultConfig) -> None:
    os.makedirs(cfg.samples_dir, exist_ok=True)


def _process_file(
    sftp,                  # TpotSFTP or stub
    store: VaultStore,
    cfg: VaultConfig,
    honeypot: str,
    remote_dir: str,
    f: RemoteFile,
    counts: CycleCounts,
) -> None:
    """Download a single remote file and update the store.

    Per V1_SPEC §8.2: skip if (sensor, honeypot, filename) already in
    seen_files. Otherwise stream-download, hash, store at /data/samples/
    by sha256 (idempotent on rename), and record both tables.
    """
    if store.have_seen(cfg.sensor_name, honeypot, f.filename):
        counts.files_skipped += 1
        return

    remote_path = remote_dir.rstrip("/") + "/" + f.filename
    try:
        with sftp.stream_download(remote_path) as (tmp_path, sha256, size):
            target = os.path.join(cfg.samples_dir, sha256)
            if not store.have_sample(sha256):
                # Move tmp -> /data/samples/<sha256>. shutil.move() is
                # atomic on the same filesystem (samples_dir is a child
                # of /data which is the same mount as our tempdir).
                #
                # If another race put the file there between our check
                # and move, shutil.move() will overwrite — same bytes,
                # since the path is content-addressable.
                if not os.path.exists(target):
                    shutil.move(tmp_path, target)
                else:
                    # Content already present from a parallel run; drop tmp.
                    os.unlink(tmp_path)
                store.insert_sample(sha256, cfg.sensor_name, honeypot, size)
                counts.new_samples += 1
                logger.info(
                    "vault: new sample sha256=%s honeypot=%s size=%d", sha256, honeypot, size,
                )
            else:
                # Bytes already in vault; just bump counters.
                # The tmp file is auto-deleted by stream_download's exit.
                store.bump_sample(sha256)
                counts.bumped_samples += 1

            store.mark_seen(cfg.sensor_name, honeypot, f.filename, sha256)
            counts.files_downloaded += 1
    except Exception as exc:
        counts.errors += 1
        logger.debug(
            "Per-file error (honeypot=%s file=%s): %s — skipping",
            honeypot, f.filename, exc,
        )


def run_cycle(sftp, store: VaultStore, cfg: VaultConfig) -> CycleCounts:
    counts = CycleCounts()
    with store.transaction():
        for honeypot, remote_dir in cfg.drop_dirs:
            counts.dirs_scanned += 1
            files = sftp.list_dir(remote_dir)
            counts.files_listed += len(files)
            for f in files:
                _process_file(sftp, store, cfg, honeypot, remote_dir, f, counts)
    logger.info(
        "vault cycle: dirs=%d listed=%d downloaded=%d new=%d bumped=%d skipped=%d errors=%d",
        counts.dirs_scanned, counts.files_listed, counts.files_downloaded,
        counts.new_samples, counts.bumped_samples, counts.files_skipped, counts.errors,
    )
    return counts


def touch_healthcheck(cfg: VaultConfig) -> None:
    try:
        with open(cfg.healthcheck_path, "w") as fh:
            from datetime import datetime, timezone
            fh.write(datetime.now(timezone.utc).isoformat() + "\n")
    except OSError as exc:
        logger.warning("Could not touch healthcheck file %s: %s", cfg.healthcheck_path, exc)


def run_forever(cfg: VaultConfig) -> int:
    setup_logging(cfg.log_level)
    _ensure_dirs(cfg)
    if not cfg.tpot_host:
        logger.error("TPOT_HOST not set — refusing to run")
        return 2
    store = VaultStore(cfg.state_db_path)
    logger.info(
        "tpot2cti-vault starting: tpot=%s:%d interval=%.0fs samples_dir=%s",
        cfg.tpot_host, cfg.tpot_ssh_port, cfg.interval_seconds, cfg.samples_dir,
    )
    try:
        while True:
            try:
                with TpotSFTP(
                    host=cfg.tpot_host,
                    port=cfg.tpot_ssh_port,
                    user=cfg.tpot_ssh_user,
                    key_path=cfg.ssh_key_path,
                    known_hosts_path=cfg.known_hosts_path,
                    auto_add_host_key=cfg.auto_add_host_key,
                ) as sftp:
                    run_cycle(sftp, store, cfg)
                touch_healthcheck(cfg)
            except Exception as exc:
                logger.warning("Vault cycle failed: %s", exc, exc_info=True)
            time.sleep(cfg.interval_seconds)
    finally:
        store.close()
    return 0


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

def _smoke_test() -> None:
    """Stub paramiko SFTPClient; verify samples land at /data/samples/<sha256>.

    Does NOT touch the network. Uses a tempdir for /data.
    """
    import hashlib
    import tempfile
    from contextlib import contextmanager

    setup_logging("INFO", connector_name="tpot2cti-vault-smoke")

    tmpdir = tempfile.mkdtemp(prefix="vault-smoke-")
    data_dir = os.path.join(tmpdir, "data")
    os.makedirs(os.path.join(data_dir, "samples"), exist_ok=True)

    cfg = VaultConfig.from_env({
        "TPOT_HOST": "fake.invalid",
        "TPOT2CTI_VAULT_DATA_DIR": data_dir,
        "TPOT2CTI_VAULT_INTERVAL": "PT15M",
        "TPOT2CTI_HEALTH_TOUCH": os.path.join(tmpdir, "last_cycle_ok"),
        "OPERATOR_ORG_NAME": "smoke-sensor",
        "LOG_LEVEL": "INFO",
    })

    # ----- Fake remote filesystem -----
    payload_a = b"malware sample alpha\n" * 16
    payload_b = b"malware sample beta\n" * 12
    sha_a = hashlib.sha256(payload_a).hexdigest()
    sha_b = hashlib.sha256(payload_b).hexdigest()

    fake_fs = {
        "/data/cowrie/downloads/": {"file-a.bin": payload_a},
        "/data/dionaea/binaries/": {"file-b.bin": payload_b, "file-a-dup.bin": payload_a},
        "/data/honeytrap/downloads-all/": {},   # empty dir
        "/data/adbhoney/downloads/": {},        # missing dir scenario simulated via empty
    }

    class StubSFTP:
        """Behaves like TpotSFTP for the smoke test."""

        def list_dir(self, remote_path: str):
            entries = fake_fs.get(remote_path, {})
            return [RemoteFile(filename=name, size_bytes=len(data)) for name, data in entries.items()]

        @contextmanager
        def stream_download(self, remote_path: str):
            d = os.path.dirname(remote_path) + "/"
            name = os.path.basename(remote_path)
            data = fake_fs[d][name]
            fd, tmp = tempfile.mkstemp(prefix="vault-smoke-")
            os.close(fd)
            with open(tmp, "wb") as fh:
                fh.write(data)
            try:
                yield tmp, hashlib.sha256(data).hexdigest(), len(data)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)

    store = VaultStore(cfg.state_db_path)
    counts = run_cycle(StubSFTP(), store, cfg)

    # Assertions
    assert counts.dirs_scanned == 4, f"dirs_scanned={counts.dirs_scanned} != 4"
    assert counts.files_listed == 3, f"files_listed={counts.files_listed} != 3"
    assert counts.files_downloaded == 3, f"files_downloaded={counts.files_downloaded} != 3"
    assert counts.new_samples == 2, f"new_samples={counts.new_samples} != 2"
    assert counts.bumped_samples == 1, f"bumped_samples={counts.bumped_samples} != 1"

    # On-disk content-addressable store
    assert os.path.exists(os.path.join(data_dir, "samples", sha_a)), "sample alpha missing"
    assert os.path.exists(os.path.join(data_dir, "samples", sha_b)), "sample beta missing"
    with open(os.path.join(data_dir, "samples", sha_a), "rb") as fh:
        assert fh.read() == payload_a
    with open(os.path.join(data_dir, "samples", sha_b), "rb") as fh:
        assert fh.read() == payload_b

    # samples table
    samples_rows = list(store._conn.execute("SELECT sha256, capture_count, first_honeypot FROM samples"))
    samples_by_sha = {r["sha256"]: r for r in samples_rows}
    assert sha_a in samples_by_sha
    assert sha_b in samples_by_sha
    assert samples_by_sha[sha_a]["capture_count"] == 2  # alpha captured twice
    assert samples_by_sha[sha_b]["capture_count"] == 1

    # seen_files table
    seen_rows = list(store._conn.execute(
        "SELECT honeypot, filename, sha256 FROM seen_files ORDER BY honeypot, filename"
    ))
    assert len(seen_rows) == 3, f"seen_files rows={len(seen_rows)} != 3"

    # Idempotency: second cycle should skip everything.
    counts2 = run_cycle(StubSFTP(), store, cfg)
    assert counts2.files_skipped == 3, f"2nd cycle files_skipped={counts2.files_skipped} != 3"
    assert counts2.files_downloaded == 0
    assert counts2.new_samples == 0

    store.close()
    print("OK")


if __name__ == "__main__":
    if "--serve" in sys.argv or os.environ.get("TPOT2CTI_VAULT_SERVE") == "1":
        cfg = VaultConfig.from_env()
        sys.exit(run_forever(cfg))
    _smoke_test()
