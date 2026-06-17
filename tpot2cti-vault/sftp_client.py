"""Paramiko-based SSH/SFTP client for the vault sidecar.

Per V1_SPEC §8.2: the vault makes a DIRECT SSH connection (not via the
autossh tunnel) to a sensor's `:64295` SSH port, authenticated by the
vault's ed25519 key (installed during enrollment).

Two read modes:

* **SFTP** (default) — when the SSH user can read the drop dirs directly.
* **sudo** (``use_sudo=True``) — list + read via ``sudo -n find``/``sudo -n
  cat`` over an exec channel. T-Pot honeypot captures are owned by uid 2000
  mode 0600, unreadable by the (non-root) SSH login user, so on a standard
  T-Pot the sudo mode is required. The enrolled account needs passwordless
  sudo (NOPASSWD) for the read — verified at enrollment.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shlex
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from stat import S_ISDIR
from typing import Iterator, List

import paramiko

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RemoteFile:
    """One entry in a remote drop directory."""
    filename: str
    size_bytes: int


class TpotSFTP:
    """paramiko wrapper for listing/fetching a sensor's malware drops.

    Owns the SSHClient (+ an SFTPClient when not using sudo). The
    constructor opens them; ``close()`` / context-exit tears them down.
    """

    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        key_path: str,
        known_hosts_path: str | None,
        auto_add_host_key: bool,
        use_sudo: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.use_sudo = use_sudo
        self.timeout = timeout
        self._client: paramiko.SSHClient | None = None
        self._sftp: paramiko.SFTPClient | None = None

        client = paramiko.SSHClient()
        if known_hosts_path and os.path.exists(known_hosts_path):
            try:
                client.load_host_keys(known_hosts_path)
            except OSError as exc:
                logger.warning("Could not load known_hosts %s: %s", known_hosts_path, exc)

        if auto_add_host_key:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        pkey = paramiko.Ed25519Key.from_private_key_file(key_path)
        client.connect(
            hostname=host, port=port, username=user, pkey=pkey,
            timeout=timeout, allow_agent=False, look_for_keys=False,
        )
        if auto_add_host_key and known_hosts_path:
            try:
                os.makedirs(os.path.dirname(known_hosts_path) or ".", exist_ok=True)
                client.get_host_keys().save(known_hosts_path)
            except OSError as exc:
                logger.warning("Could not save known_hosts %s: %s", known_hosts_path, exc)

        self._client = client
        if not use_sudo:
            self._sftp = client.open_sftp()
        logger.info("SSH connected: %s@%s:%d (sudo=%s)", user, host, port, use_sudo)

    def close(self) -> None:
        for obj in (self._sftp, self._client):
            try:
                if obj is not None:
                    obj.close()
            except Exception:  # pragma: no cover - defensive
                pass

    def __enter__(self) -> "TpotSFTP":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    # exec helper (sudo mode)
    # ------------------------------------------------------------------ #
    def _exec(self, cmd: str):
        assert self._client is not None
        return self._client.exec_command(cmd, timeout=self.timeout)

    # ------------------------------------------------------------------ #
    # ops
    # ------------------------------------------------------------------ #
    def list_dir(self, remote_path: str) -> List[RemoteFile]:
        """Regular files in ``remote_path`` (empty list if missing/empty —
        a normal state for a honeypot with no captures yet)."""
        if self.use_sudo:
            return self._list_dir_sudo(remote_path)
        assert self._sftp is not None
        try:
            entries = self._sftp.listdir_attr(remote_path)
        except FileNotFoundError:
            return []
        except Exception as exc:
            logger.warning("Could not listdir %s: %s", remote_path, exc)
            return []
        files: List[RemoteFile] = []
        for entry in entries:
            if entry.st_mode is not None and S_ISDIR(entry.st_mode):
                continue
            if entry.filename in (".", ".."):
                continue
            files.append(RemoteFile(entry.filename, entry.st_size or 0))
        return files

    def _list_dir_sudo(self, remote_path: str) -> List[RemoteFile]:
        # `find -printf '%f\t%s\n'` = basename<TAB>size for each regular file.
        cmd = ("sudo -n find " + shlex.quote(remote_path)
               + r" -maxdepth 1 -type f -printf '%f\t%s\n' 2>/dev/null")
        _in, out, err = self._exec(cmd)
        data = out.read().decode("utf-8", "replace")
        rc = out.channel.recv_exit_status()
        if rc != 0 and not data:
            msg = err.read().decode("utf-8", "replace").strip()
            if msg:
                logger.warning("sudo find %s failed (rc=%d): %s", remote_path, rc, msg[:160])
            return []
        files: List[RemoteFile] = []
        for line in data.splitlines():
            name, _tab, size = line.partition("\t")
            if name:
                files.append(RemoteFile(name, int(size) if size.isdigit() else 0))
        return files

    @contextmanager
    def stream_download(self, remote_path: str) -> Iterator[tuple[str, str, int]]:
        """Download ``remote_path`` to a temp file; yield (tmp_path, sha256,
        size). Temp file is removed on exit unless the caller moves it."""
        fd, tmp_path = tempfile.mkstemp(prefix="vault-")
        os.close(fd)
        h = hashlib.sha256()
        size = 0
        try:
            if self.use_sudo:
                _in, out, err = self._exec("sudo -n cat -- " + shlex.quote(remote_path))
                with open(tmp_path, "wb") as local_fh:
                    while True:
                        chunk = out.read(65536)
                        if not chunk:
                            break
                        h.update(chunk)
                        local_fh.write(chunk)
                        size += len(chunk)
                rc = out.channel.recv_exit_status()
                if rc != 0:
                    msg = err.read().decode("utf-8", "replace").strip()
                    raise OSError("sudo cat %s failed (rc=%d): %s" % (remote_path, rc, msg[:160]))
            else:
                assert self._sftp is not None
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
