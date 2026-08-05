"""T-Pot's `type` is the honeypot's own output, so it sometimes isn't a
honeypot name at all — and the highest-value Cowrie event is one of the
casualties.

Measured on the live hive, 2026-08-05, over 35 days:

    type=ssh-rsa      3,844  |
    type=ssh-ed25519    250  |  ALL are cowrie.login.success — successful
    type=ssh-dss         98  |  public-key root logins, carrying the
                             |  attacker's SSH key and fingerprint.
    path=/data/cowrie/log/cowrie.json on 100% of them.

`_PARSER_DISPATCH` and the registry both key on `type`, so these never
reached CowrieParser, and `TPOT2CTI_IGNORE_TYPES` listed two of them, so
they were dropped at the ES query before anything could count them.
"""
from __future__ import annotations

import pytest

import tpot2cti.main  # noqa: F401 — forces every parser to register
from tpot2cti.parsers import TYPE_RECOVERIES, _type_from_path, dispatch, registered_types


def _cowrie_pubkey_doc(reported_type="ssh-rsa"):
    """Shaped after a real hive doc."""
    return {
        "type": reported_type,
        "path": "/data/cowrie/log/cowrie.json",
        "eventid": "cowrie.login.success",
        "message": "public key login attempt for [root] succeeded",
        "username": "root",
        "fingerprint": "e0:16:77:74:92:85:8e:25:5d:41:80:de:02:c1:fb:a7",
        "src_ip": "203.0.113.44",
        "session": "abc123",
        "dst_port": 22,
        "@timestamp": "2026-08-05T10:00:00.000Z",
        "t-pot_hostname": "sensor01",
    }


@pytest.mark.parametrize("bogus", ["ssh-rsa", "ssh-ed25519", "ssh-dss"])
def test_a_pubkey_login_is_recovered_as_cowrie(bogus):
    assert bogus not in registered_types(), (
        f"{bogus} now has its own parser — this test's premise is stale"
    )
    assert _type_from_path(_cowrie_pubkey_doc(bogus)) == "Cowrie"


@pytest.mark.parametrize("bogus", ["ssh-rsa", "ssh-ed25519", "ssh-dss"])
def test_the_recovered_doc_actually_parses(bogus):
    """Recovery is worthless if the doc still yields nothing."""
    TYPE_RECOVERIES.clear()
    event = dispatch(_cowrie_pubkey_doc(bogus))
    assert event is not None, "recovered doc still did not parse"
    assert event.event_type == "Cowrie"
    assert event.src_ip == "203.0.113.44"
    assert TYPE_RECOVERIES.get((bogus, "Cowrie")) == 1, "recovery was not counted"


def test_a_registered_type_is_never_re_routed():
    """The guard that makes this safe: a `type` naming a real parser is
    trusted as-is, so path recovery cannot hijack a good doc. Galah's LLM
    subtypes DO have parsers and must take their own path, not Galah's."""
    for registered in ("Cowrie", "Galah", "invalidJSONResponse",
                       "contentGenerationError"):
        assert registered in registered_types()
        doc = {"type": registered, "path": "/data/cowrie/log/cowrie.json"}
        # _type_from_path would say "Cowrie", but dispatch must not consult it.
        TYPE_RECOVERIES.clear()
        dispatch(doc)
        assert not TYPE_RECOVERIES, (
            f"{registered} was re-routed by path despite having a parser"
        )


def test_recovery_is_derived_not_hardcoded():
    """`/data/<name>/` is matched case-insensitively against the registry,
    so a honeypot added later is covered without editing this function."""
    assert _type_from_path({"path": "/data/mailoney/log/commands.log"}) == "Mailoney"
    assert _type_from_path({"path": "/data/conpot/log/conpot.json"}) == "ConPot"
    assert _type_from_path({"path": "/data/GALAH/log/x.json"}) == "Galah"


@pytest.mark.parametrize("path", [
    "", "/", "/var/log/syslog", "/data", "/data/",
    "/data/not-a-honeypot/log/x.json", "relative/data/cowrie/x.json",
])
def test_unrecognisable_paths_recover_nothing(path):
    """Must fail closed — a wrong guess would mis-attribute an event to a
    honeypot that never saw it."""
    assert _type_from_path({"path": path}) is None


def test_a_missing_path_is_not_a_crash():
    assert _type_from_path({}) is None
    assert _type_from_path({"path": None}) is None
    assert _type_from_path({"path": 12345}) is None


def test_recoveries_are_counted_per_pair():
    TYPE_RECOVERIES.clear()
    for _ in range(3):
        dispatch(_cowrie_pubkey_doc("ssh-rsa"))
    dispatch(_cowrie_pubkey_doc("ssh-ed25519"))
    assert TYPE_RECOVERIES == {("ssh-rsa", "Cowrie"): 3, ("ssh-ed25519", "Cowrie"): 1}


def test_the_counter_reaches_the_cycle_summary():
    """A recovery nobody reports is the same silent-drop defect in a new
    costume."""
    import inspect
    from tpot2cti import main
    src = inspect.getsource(main.run_cycle)
    assert "TYPE_RECOVERIES.clear()" in src, "counter is never reset per cycle"
    assert "type_recoveries" in src, "recoveries are absent from the cycle summary"
