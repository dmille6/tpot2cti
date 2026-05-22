"""
Logging helpers for tpot2cti.

Implements the ``setup_logging()`` / ``restore_logging()`` pair documented
in ``docs/LESSONS_LEARNED_FROM_V0.md`` §8.1. The pycti library's
:class:`OpenCTIConnectorHelper.__init__` internally calls
:func:`logging.basicConfig` which removes any handlers we had already
attached to the root logger. Our defense:

1. Call :func:`setup_logging` once at process start. It attaches a stdout
   handler and (optionally) a daily-rotating file handler, and caches
   references to them in a module-global.

2. Construct ``OpenCTIConnectorHelper(...)``. This clobbers the root
   logger.

3. Call :func:`restore_logging` to re-attach the cached handlers.

Logs are written as JSON, one event per line, per V1_SPEC §3.

The file destination defaults to ``/var/log/tpot2cti/<connector_name>.log``
when ``connector_name`` is set, falling back to stdout-only if the path
is not writable (which is the common case in tests / dev environments).
"""

from __future__ import annotations

import json
import logging
import os
import sys
from logging.handlers import TimedRotatingFileHandler
from typing import Optional

__all__ = ["setup_logging", "restore_logging", "JsonFormatter"]

# Cached *config* attached by setup_logging(). restore_logging() rebuilds
# the file handler from scratch (rather than reusing the cached instance)
# because pycti's basicConfig() closes the file handle, and re-attaching
# the same TimedRotatingFileHandler object to root.handlers does NOT
# reopen the file — leading to a silent "all subsequent file writes are
# dropped" failure (per 2026-05-22 logging audit #L1).
_cached_stdout_handler: Optional[logging.Handler] = None
_cached_file_config: Optional[dict] = None  # {"path", "retention_days", "level", "formatter"}
_cached_level: int = logging.INFO

#: Logger names whose INFO chatter we silence after restore_logging().
#: Per logging audit L3 + L8: pycti's ``api`` logger emits ~12 lines per
#: STIX object created and elastic_transport's retry chatter duplicates
#: errors we log with better context.  Setting them to WARNING cuts
#: docker-log volume roughly 4× and keeps the remaining lines actually
#: scannable.  Operators wanting the chatter back can set
#: ``LOG_LEVEL=DEBUG`` to override.
_NOISY_LOGGERS = ("api", "pycti", "elastic_transport", "elastic_transport.transport",
                  "elastic_transport.node_pool")


class JsonFormatter(logging.Formatter):
    """
    Minimal JSON log formatter.

    Emits one JSON object per record with the fields V1_SPEC §3 calls
    for: timestamp, level, logger name, message, and (optionally) a
    ``connector`` tag. Exception info is rendered into an ``exc_info``
    string field when present.
    """

    def __init__(self, connector_name: Optional[str] = None) -> None:
        """
        Args:
            connector_name: If set, every emitted record carries a
                ``"connector": <name>`` field. Useful when multiple
                connectors share a log aggregator.
        """
        super().__init__()
        self.connector_name = connector_name

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        """Render ``record`` as a single-line JSON string.

        Timestamp is strict ISO-8601 with milliseconds and ``+00:00``
        separator (not ``+0000``) so picky parsers — ``datetime.fromisoformat``
        pre-3.11, some Go and Rust libraries — accept it.  Millisecond
        precision avoids non-deterministic ordering during publish bursts
        (per logging audit #L11).
        """
        from datetime import datetime, timezone
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds")
        payload: dict[str, object] = {
            "ts": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if self.connector_name:
            payload["connector"] = self.connector_name
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    log_retention_days: int = 30,
    connector_name: Optional[str] = None,
) -> None:
    """
    Configure the root logger with a stdout handler and (optionally) a
    daily-rotating file handler.

    Call this BEFORE constructing :class:`OpenCTIConnectorHelper`. The
    helper's ``__init__`` will clobber the handlers; call
    :func:`restore_logging` immediately after to put them back.

    Args:
        log_level: One of ``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``,
            ``CRITICAL``. Case-insensitive. Invalid values fall back to
            ``INFO``.
        log_file: Explicit path for the rotating file handler. If
            ``None`` and ``connector_name`` is set, defaults to
            ``/var/log/tpot2cti/<connector_name>.log``. If both are
            ``None``, no file handler is attached (stdout only).
        log_retention_days: Number of rotated backups to keep. Files are
            rotated at midnight and the oldest are pruned beyond this
            count.
        connector_name: Tag added to every JSON record as ``connector``
            and used to derive the default log-file path.

    Notes:
        File-handler creation is wrapped in try/except: if the target
        directory is not writable (a common case in dev and CI), the
        function logs a warning to stdout and continues with stdout
        only. Logging is never allowed to fail the process.
    """
    global _cached_stdout_handler, _cached_file_config, _cached_level

    level = getattr(logging, log_level.upper(), logging.INFO)
    _cached_level = level

    formatter = JsonFormatter(connector_name=connector_name)

    # Always-on stdout handler.  Cached as an instance because stdout
    # never closes underneath us (unlike a file handle pycti might cycle).
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(level)
    stdout_handler.setFormatter(formatter)
    _cached_stdout_handler = stdout_handler

    handlers: list[logging.Handler] = [stdout_handler]

    # Optional rotating file handler — config-cached (not instance-cached)
    # so restore_logging() can rebuild from scratch.  See _NOISY_LOGGERS
    # comment + audit #L1 for the rationale.
    resolved_path = _resolve_log_file(log_file, connector_name)
    if resolved_path is not None:
        _cached_file_config = {
            "path": resolved_path,
            "retention_days": log_retention_days,
            "level": level,
            "formatter": formatter,
        }
        file_handler = _make_file_handler(
            resolved_path, log_retention_days, level, formatter
        )
        if file_handler is not None:
            handlers.append(file_handler)
    elif _cached_file_config is not None:
        # 2026-05-22 audit L1 follow-on: defensive callers (e.g.
        # ``OpenCTIClient.__init__``) re-invoke ``setup_logging()`` with
        # no ``log_file`` arg to make sure handlers exist.  Pre-fix this
        # wiped the file-handler config that main.py had carefully set
        # up — silently breaking durable JSON logs.  Now we preserve the
        # already-cached file config so the second call is truly a
        # safe-to-re-run no-op (still re-binds stdout, still resets the
        # root level, but keeps the file handler alive).
        file_handler = _make_file_handler(
            _cached_file_config["path"],
            _cached_file_config["retention_days"],
            level,
            formatter,
        )
        if file_handler is not None:
            # Update cached config to the latest level/formatter so a
            # genuinely-different call (e.g. raising LOG_LEVEL at runtime)
            # actually takes effect on the next restore_logging.
            _cached_file_config["level"] = level
            _cached_file_config["formatter"] = formatter
            handlers.append(file_handler)
    # else: no log_file requested AND no prior cached config — stdout only.

    root = logging.getLogger()
    root.setLevel(level)
    # Clear anything inherited (test-runner handlers, prior setup, etc.)
    # before attaching ours, so we don't double-emit.
    for existing in list(root.handlers):
        root.removeHandler(existing)
    for handler in handlers:
        root.addHandler(handler)


def restore_logging() -> None:
    """
    Re-attach the handlers configured by :func:`setup_logging` to the
    root logger.

    Necessary because :class:`OpenCTIConnectorHelper.__init__` calls
    :func:`logging.basicConfig`, which adds its own handler and (in
    some pycti versions) removes ours.  Per 2026-05-22 audit #L1: the
    file handler in particular has to be REBUILT from cached config —
    pycti closes the underlying file descriptor, and re-adding the
    same handler instance doesn't reopen the file (silent write-drop
    failure since project inception until this fix).

    We also turn down a handful of third-party loggers whose INFO chatter
    drowns out the operator-actionable lines (per audit L3 + L8).
    Operators wanting the noise back can run with ``LOG_LEVEL=DEBUG``.

    Idempotent: safe to call multiple times, and a no-op if
    :func:`setup_logging` was never called.
    """
    if _cached_stdout_handler is None:
        return

    root = logging.getLogger()
    root.setLevel(_cached_level)

    # Strip every handler — including any pycti-installed ones AND any
    # stale instances of our own.  We rebuild fresh below.
    for existing in list(root.handlers):
        root.removeHandler(existing)
        # Close file handles we owned so the OS frees them; stdout
        # handlers don't need closing.
        if not isinstance(existing, logging.StreamHandler) or hasattr(existing, "baseFilename"):
            try:
                existing.close()
            except Exception:
                pass

    # Re-add stdout (instance is stable — sys.stdout doesn't go away).
    root.addHandler(_cached_stdout_handler)

    # REBUILD the file handler from cached config rather than reusing
    # the (potentially-closed) instance from setup_logging().
    if _cached_file_config is not None:
        fh = _make_file_handler(
            _cached_file_config["path"],
            _cached_file_config["retention_days"],
            _cached_file_config["level"],
            _cached_file_config["formatter"],
        )
        if fh is not None:
            root.addHandler(fh)

    # Mute noisy third-party loggers (audit L3, L8). Only if our own
    # level is > DEBUG — at DEBUG we want everything.
    if _cached_level > logging.DEBUG:
        for name in _NOISY_LOGGERS:
            logging.getLogger(name).setLevel(logging.WARNING)


def _resolve_log_file(
    log_file: Optional[str], connector_name: Optional[str]
) -> Optional[str]:
    """
    Decide which file path (if any) to use for the rotating handler.

    Precedence:
        1. Explicit ``log_file`` argument.
        2. ``/var/log/tpot2cti/<connector_name>.log`` if ``connector_name``
           is set.
        3. ``None`` (no file handler).
    """
    if log_file:
        return log_file
    if connector_name:
        return f"/var/log/tpot2cti/{connector_name}.log"
    return None


def _make_file_handler(
    path: str,
    retention_days: int,
    level: int,
    formatter: logging.Formatter,
) -> Optional[logging.Handler]:
    """
    Build a :class:`TimedRotatingFileHandler` for ``path``.

    Returns ``None`` (and logs a warning to stderr) if the directory is
    not creatable or the file is not writable. Logging is best-effort:
    we never let a missing ``/var/log`` mount break the importer.
    """
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        handler = TimedRotatingFileHandler(
            path,
            when="midnight",
            interval=1,
            backupCount=retention_days,
            encoding="utf-8",
            utc=True,
        )
        handler.setLevel(level)
        handler.setFormatter(formatter)
        return handler
    except OSError as exc:
        # Use stderr directly — root logger may not be ready yet.
        sys.stderr.write(
            f"tpot2cti.logging: could not open log file {path!r}: {exc}; "
            "continuing with stdout only\n"
        )
        return None


if __name__ == "__main__":
    setup_logging(
        log_level="DEBUG",
        connector_name="tpot2cti-smoke",
        log_file=None,
    )
    log = logging.getLogger("tpot2cti.smoke")
    log.info("setup_logging OK")
    restore_logging()
    log.info("restore_logging OK (idempotent)")
    restore_logging()
