"""JSON-structured logging for the vault sidecar.

Same shape as ``tpot2cti.log.JsonFormatter`` (the core importer's
logger). Duplicated locally so the sidecar process is independent of
the core importer (per V1_SPEC §8.2).
"""

from __future__ import annotations

import json
import logging
import sys


class JsonFormatter(logging.Formatter):
    """Render each log record as one JSON object per line."""

    def __init__(self, connector_name: str = "tpot2cti-vault") -> None:
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


def setup_logging(level: str = "INFO", connector_name: str = "tpot2cti-vault") -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(lvl)
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(lvl)
    handler.setFormatter(JsonFormatter(connector_name=connector_name))
    root.addHandler(handler)
