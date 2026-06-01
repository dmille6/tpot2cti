"""main._connect_opencti — patient startup wait for a cold OpenCTI.

Pins the 2026-06-01 fix: instead of crashing on the first unreachable
probe (which crash-looped the container after a stack restart until
OpenCTI warmed up), we poll + retry within
``cfg.opencti.connect_timeout_seconds``. A real misconfiguration
(ConfigError) must still fail fast — retrying can't help it.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tpot2cti import main
from tpot2cti.config import ConfigError, OpenCTIConfig


def _cfg(timeout):
    return SimpleNamespace(
        opencti=OpenCTIConfig(
            url="http://opencti:8080",
            admin_token="t",
            connect_timeout_seconds=timeout,
        )
    )


@pytest.fixture(autouse=True)
def _no_real_io(monkeypatch):
    # Never actually open a socket or sleep during these tests.
    monkeypatch.setattr(main, "wait_for_host", lambda *a, **k: True)
    monkeypatch.setattr(main.time, "sleep", lambda *_: None)


def test_returns_client_on_first_success(monkeypatch):
    calls = []

    def fake_client(cfg, *, connector_id):
        calls.append(connector_id)
        return "CLIENT"

    monkeypatch.setattr(main, "OpenCTIClient", fake_client)
    out = main._connect_opencti(_cfg(300), connector_id="abc")
    assert out == "CLIENT"
    assert calls == ["abc"]  # exactly one construction


def test_retries_transient_failures_then_succeeds(monkeypatch):
    attempts = {"n": 0}

    def flaky_client(cfg, *, connector_id):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise ValueError("OpenCTI API is not reachable")  # pycti's error
        return "CLIENT"

    monkeypatch.setattr(main, "OpenCTIClient", flaky_client)
    out = main._connect_opencti(_cfg(300), connector_id="abc")
    assert out == "CLIENT"
    assert attempts["n"] == 3  # two failures absorbed, third succeeded


def test_config_error_is_not_retried(monkeypatch):
    attempts = {"n": 0}

    def bad_config_client(cfg, *, connector_id):
        attempts["n"] += 1
        raise ConfigError("connector_id is empty")

    monkeypatch.setattr(main, "OpenCTIClient", bad_config_client)
    with pytest.raises(ConfigError):
        main._connect_opencti(_cfg(300), connector_id="")
    assert attempts["n"] == 1  # failed fast, no retry loop


def test_gives_up_after_deadline(monkeypatch):
    def always_fails(cfg, *, connector_id):
        raise ValueError("OpenCTI API is not reachable")

    monkeypatch.setattr(main, "OpenCTIClient", always_fails)
    # timeout=0 ⇒ one attempt, then the deadline is already past ⇒ re-raise.
    with pytest.raises(ValueError):
        main._connect_opencti(_cfg(0), connector_id="abc")
