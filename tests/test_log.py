"""Logging contract — setup → basicConfig → restore preserves file output.

Per the 2026-05-22 logging audit #L1: pycti's OpenCTIConnectorHelper
calls logging.basicConfig() at __init__ time which silently disconnects
our file handler.  restore_logging() must REBUILD it from cached
config; reusing the original instance leads to silent write-drops.
"""

from __future__ import annotations

import json
import logging
import re

import pytest

from tpot2cti import log as tlog


@pytest.fixture(autouse=True)
def _reset_logging():
    """Restore the root logger between tests so handlers don't leak."""
    yield
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
        try:
            h.close()
        except Exception:
            pass


def test_setup_then_basicconfig_then_restore_preserves_file(tmp_path):
    """setup → pycti-style basicConfig → restore: file lines still land."""
    log_file = tmp_path / "smoke.log"
    tlog.setup_logging(log_level="DEBUG", log_file=str(log_file))
    logging.getLogger("smoke").info("phase-1")

    # Simulate pycti's clobber.
    logging.basicConfig(force=True, level=logging.INFO)
    tlog.restore_logging()
    logging.getLogger("smoke").info("phase-2")

    # Force flush.
    for h in logging.getLogger().handlers:
        h.flush()
    contents = log_file.read_text()
    assert "phase-1" in contents
    assert "phase-2" in contents, (
        "restore_logging() must rebuild the file handler, not reuse the "
        "closed instance (audit #L1)"
    )


def test_timestamp_is_strict_iso8601_with_ms(tmp_path):
    """The JSON formatter emits ts with milliseconds and +00:00."""
    log_file = tmp_path / "iso.log"
    tlog.setup_logging(log_level="DEBUG", log_file=str(log_file))
    logging.getLogger("smoke").info("hello")
    for h in logging.getLogger().handlers:
        h.flush()
    line = log_file.read_text().splitlines()[0]
    payload = json.loads(line)
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+00:00$", payload["ts"]), payload["ts"]


def test_noisy_loggers_muted_after_restore(tmp_path):
    """restore_logging() raises pycti/elastic-transport loggers to WARNING."""
    tlog.setup_logging(log_level="INFO", log_file=str(tmp_path / "n.log"))
    logging.basicConfig(force=True)
    tlog.restore_logging()
    for name in ("pycti", "elastic_transport"):
        assert logging.getLogger(name).level >= logging.WARNING, name


def test_restore_logging_idempotent(tmp_path):
    """Calling restore_logging twice in a row does not crash."""
    tlog.setup_logging(log_level="INFO", log_file=str(tmp_path / "i.log"))
    tlog.restore_logging()
    tlog.restore_logging()


def test_restore_logging_noop_before_setup():
    """restore_logging() is safe before setup_logging() (idempotent)."""
    tlog.restore_logging()  # MUST NOT raise


def test_defensive_zero_arg_setup_preserves_file_handler(tmp_path):
    """L1 follow-on (2026-05-22): an 8-hour soak revealed that
    ``OpenCTIClient.__init__`` was calling ``setup_logging()`` with no
    args as a defensive "make sure handlers exist" measure — but the
    zero-arg call resolved to ``log_file=None`` and wiped the cached
    file_handler config that main.py had carefully set up.  Result:
    every subsequent ``restore_logging()`` had nothing to rebuild, and
    durable file logs were silently broken for the entire process
    lifetime (only the 2-line startup banner reached disk; 8 hours of
    cycle telemetry stayed in docker-json only).

    This test pins the contract: a zero-arg ``setup_logging()`` call
    AFTER a real init MUST preserve the file_handler config, so a
    later ``restore_logging()`` continues to drive file writes.
    """
    import json
    import logging as _logging
    log_path = tmp_path / "preserve.log"

    # Step 1: real init from main.py
    tlog.setup_logging(log_level="INFO", log_file=str(log_path), connector_name="t")
    log = _logging.getLogger("preserve.test")
    log.info("before-defensive-call")

    # Step 2: defensive zero-arg call (the buggy pattern)
    tlog.setup_logging()

    # Step 3: simulate pycti's basicConfig
    _logging.basicConfig(level=_logging.WARNING)
    for h in list(_logging.getLogger().handlers):
        try:
            h.close()
        except Exception:
            pass

    # Step 4: restore — MUST rebuild file handler from preserved cache
    tlog.restore_logging()
    log.info("after-restore")

    # Verify both lines reached the file
    lines = [json.loads(ln) for ln in log_path.read_text().splitlines() if ln.strip()]
    msgs = [ln["message"] for ln in lines]
    assert "before-defensive-call" in msgs, "pre-defensive-call line lost"
    assert "after-restore" in msgs, (
        "post-restore line lost — the defensive zero-arg setup_logging() "
        "wiped the file-handler config (regression of L1 follow-on bug)"
    )
