"""JSON-structured logging for the credentials sidecar.

Mirrors the JSON shape of ``tpot2cti.log.JsonFormatter`` (the core
importer's logger). Duplicated here so the sidecar doesn't import from
the core package — per V1_SPEC §8.1 the sidecars are independent
processes that just happen to share style.

One event per line; fields: ts, level, logger, message, connector,
and (when present) exc_info.
"""

from __future__ import annotations

import json
import logging
import sys


class JsonFormatter(logging.Formatter):
    """Render each log record as a single-line JSON object."""

    def __init__(self, connector_name: str = "tpot2cti-credentials") -> None:
        super().__init__()
        self.connector_name = connector_name

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "connector": self.connector_name,
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging(level: str = "INFO", connector_name: str = "tpot2cti-credentials") -> None:
    """Configure root logger with a single stdout JSON handler."""
    lvl = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(lvl)
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(lvl)
    handler.setFormatter(JsonFormatter(connector_name=connector_name))
    root.addHandler(handler)
