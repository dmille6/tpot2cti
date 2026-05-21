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

# Cached handlers attached by setup_logging(). restore_logging() re-attaches
# these to the root logger after pycti clobbers it. Kept at module scope
# (not on a class) so it survives across import boundaries.
_cached_handlers: list[logging.Handler] = []
_cached_level: int = logging.INFO


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
        """Render ``record`` as a single-line JSON string."""
        payload: dict[str, object] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
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
    global _cached_handlers, _cached_level

    level = getattr(logging, log_level.upper(), logging.INFO)
    _cached_level = level

    formatter = JsonFormatter(connector_name=connector_name)

    handlers: list[logging.Handler] = []

    # Always-on stdout handler.
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(level)
    stdout_handler.setFormatter(formatter)
    handlers.append(stdout_handler)

    # Optional rotating file handler.
    resolved_path = _resolve_log_file(log_file, connector_name)
    if resolved_path is not None:
        file_handler = _make_file_handler(
            resolved_path, log_retention_days, level, formatter
        )
        if file_handler is not None:
            handlers.append(file_handler)

    _cached_handlers = handlers

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
    some pycti versions) removes ours. We blow away whatever pycti
    left behind and reinstall our cached set.

    Idempotent: safe to call multiple times, and a no-op if
    :func:`setup_logging` was never called.
    """
    if not _cached_handlers:
        return

    root = logging.getLogger()
    root.setLevel(_cached_level)
    for existing in list(root.handlers):
        # If the handler is one of ours, leave it; otherwise drop it.
        if existing not in _cached_handlers:
            root.removeHandler(existing)
    for handler in _cached_handlers:
        if handler not in root.handlers:
            root.addHandler(handler)


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
