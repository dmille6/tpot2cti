"""Paramiko-based SFTP client for the vault sidecar.

Per V1_SPEC §8.2: the vault sidecar makes a DIRECT SSH connection
(not via the autossh tunnel container) to T-Pot's `:64295` SSH port,
authenticated by the same ed25519 key the tunnel container uses. T-Pot's
sshd handles multiple concurrent sessions trivially.

Why direct rather than tunnel? The tunnel container forwards Elasticsearch
(64298), not arbitrary ports — it doesn't act as a ProxyJump host. Adding
that would mean a second autossh forward or a ProxyCommand chain. Direct
is the simplest correct answer; outbound network egress is already
required for the core importer.
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, List

import paramiko

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RemoteFile:
    """One entry in a remote drop directory."""
    filename: str
    size_bytes: int


class TpotSFTP:
    """Thin paramiko wrapper for the SFTP-listing/SFTP-fetching workflow.

    The class owns the SSHClient + SFTPClient pair; the constructor opens
    them, ``close()`` (or context-manager exit) tears them down.
    """

    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        key_path: str,
        known_hosts_path: str | None,
        auto_add_host_key: bool,
        timeout: float = 30.0,
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.timeout = timeout
        self._client: paramiko.SSHClient | None = None
        self._sftp: paramiko.SFTPClient | None = None

        client = paramiko.SSHClient()
        # Load known_hosts if present so we pin on the first-seen host key.
        if known_hosts_path and os.path.exists(known_hosts_path):
            try:
                client.load_host_keys(known_hosts_path)
            except OSError as exc:
                logger.warning("Could not load known_hosts %s: %s", known_hosts_path, exc)

        if auto_add_host_key:
            # First-run: accept and persist the host key. Subsequent runs
            # pin against the saved entry via load_host_keys above. We
            # intentionally don't use RejectPolicy() because tpot2cti has
            # to bootstrap from zero state on first cycle.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        pkey = paramiko.Ed25519Key.from_private_key_file(key_path)

        client.connect(
            hostname=host,
            port=port,
            username=user,
            pkey=pkey,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        # Persist any newly-added host key so we don't blindly AutoAdd next run.
        if auto_add_host_key and known_hosts_path:
            try:
                os.makedirs(os.path.dirname(known_hosts_path) or ".", exist_ok=True)
                client.get_host_keys().save(known_hosts_path)
            except OSError as exc:
                logger.warning("Could not save known_hosts %s: %s", known_hosts_path, exc)

        self._client = client
        self._sftp = client.open_sftp()
        logger.info("SFTP connected: %s@%s:%d", user, host, port)

    def close(self) -> None:
        try:
            if self._sftp is not None:
                self._sftp.close()
        except Exception:  # pragma: no cover - defensive
            pass
        try:
            if self._client is not None:
                self._client.close()
        except Exception:  # pragma: no cover - defensive
            pass

    def __enter__(self) -> "TpotSFTP":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    # ops
    # ------------------------------------------------------------------ #

    def list_dir(self, remote_path: str) -> List[RemoteFile]:
        """Return the list of regular files in ``remote_path``.

        Returns an empty list if the directory doesn't exist or is empty
        — both are normal operating states (e.g. brand-new T-Pot install
        with no malware captured yet).
        """
        assert self._sftp is not None
        try:
            entries = self._sftp.listdir_attr(remote_path)
        except FileNotFoundError:
            logger.debug("Remote dir not found (ok if honeypot has no captures yet): %s", remote_path)
            return []
        except Exception as exc:
            logger.warning("Could not listdir %s: %s", remote_path, exc)
            return []

        files: List[RemoteFile] = []
        for entry in entries:
            # Skip directories — drop dirs are flat per V1_SPEC §8.2.
            from stat import S_ISDIR
            if entry.st_mode is not None and S_ISDIR(entry.st_mode):
                continue
            if entry.filename in (".", ".."):
                continue
            files.append(RemoteFile(filename=entry.filename, size_bytes=entry.st_size or 0))
        return files

    @contextmanager
    def stream_download(self, remote_path: str) -> Iterator[tuple[str, str, int]]:
        """Download ``remote_path`` to a temp file, yield (tmp_path, sha256, size).

        The temp file is deleted on context-manager exit unless the
        caller renames it elsewhere first.
        """
        assert self._sftp is not None
        fd, tmp_path = tempfile.mkstemp(prefix="vault-")
        os.close(fd)

        h = hashlib.sha256()
        size = 0
        try:
            # paramiko's SFTPClient supports getfo() — open remote read,
            # stream-copy into the temp file while hashing.
            with self._sftp.open(remote_path, "rb") as remote_fh, open(tmp_path, "wb") as local_fh:
                remote_fh.prefetch()
                while True:
                    chunk = remote_fh.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
                    local_fh.write(chunk)
                    size += len(chunk)
            yield tmp_path, h.hexdigest(), size
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:  # pragma: no cover - defensive
                pass
