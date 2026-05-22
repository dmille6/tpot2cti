"""config.load_config — env override + required-field validation."""

from __future__ import annotations

import pytest

from tpot2cti.config import ConfigError, load_config


_REQUIRED_ENV = {
    "TPOT_HOST": "tpot.example",
    "OPENCTI_ADMIN_TOKEN": "00000000-0000-0000-0000-000000000000",
    "TPOT2CTI_CONNECTOR_ID": "00000000-0000-0000-0000-000000000001",
}


def test_load_config_uses_env_dict():
    """The env_dict parameter overrides os.environ for tests."""
    cfg = load_config(env_dict=dict(_REQUIRED_ENV, TPOT_HOST="custom.host"))
    assert cfg.tpot.host == "custom.host"


def test_missing_required_raises_config_error():
    """Omitting TPOT_HOST raises ConfigError, not KeyError or ValueError."""
    bad = dict(_REQUIRED_ENV)
    bad.pop("TPOT_HOST")
    with pytest.raises(ConfigError):
        load_config(env_dict=bad)


def test_runtime_config_fields_populate():
    """RuntimeConfig has the three audit-#4 fields with defaults."""
    cfg = load_config(env_dict=dict(_REQUIRED_ENV))
    assert cfg.runtime.state_db_path == "/data/state.db"
    assert cfg.runtime.health_bind == "0.0.0.0:8080"
    assert cfg.runtime.daily_creds_lookback_days == 7


def test_runtime_config_env_overrides():
    """Env vars override the RuntimeConfig defaults."""
    env = dict(_REQUIRED_ENV, TPOT2CTI_STATE_DB="/tmp/x.db",
               TPOT2CTI_HEALTH_BIND="127.0.0.1:9090",
               TPOT2CTI_CREDS_LOOKBACK_DAYS="14")
    cfg = load_config(env_dict=env)
    assert cfg.runtime.state_db_path == "/tmp/x.db"
    assert cfg.runtime.health_bind == "127.0.0.1:9090"
    assert cfg.runtime.daily_creds_lookback_days == 14


def test_bad_confidence_rejected():
    """TPOT2CTI_DEFAULT_CONFIDENCE outside [0,100] raises ConfigError."""
    env = dict(_REQUIRED_ENV, TPOT2CTI_DEFAULT_CONFIDENCE="200")
    with pytest.raises(ConfigError):
        load_config(env_dict=env)


def test_bad_tlp_rejected():
    """An unrecognized TLP level raises ConfigError."""
    env = dict(_REQUIRED_ENV, TPOT2CTI_DEFAULT_TLP="pink")
    with pytest.raises(ConfigError):
        load_config(env_dict=env)


def test_default_ignore_types_includes_p0f_and_ssh_rsa():
    """Default ignore list has the two known-noise types from audit #8."""
    cfg = load_config(env_dict=dict(_REQUIRED_ENV))
    assert "P0f" in cfg.cycle.ignore_types
    assert "ssh-rsa" in cfg.cycle.ignore_types


def test_honeypot_ips_parsed_as_frozenset():
    """TPOT_HONEYPOT_IPS is comma-split and trimmed."""
    env = dict(_REQUIRED_ENV, TPOT_HONEYPOT_IPS="1.1.1.1, 2.2.2.2,  ,3.3.3.3")
    cfg = load_config(env_dict=env)
    assert cfg.tpot.honeypot_ips == frozenset({"1.1.1.1", "2.2.2.2", "3.3.3.3"})
