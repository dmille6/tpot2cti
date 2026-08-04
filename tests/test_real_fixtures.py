"""Regression tests: every parser against REAL (sanitized) ELK event data.

Fixtures in tests/fixtures/real/<type>.jsonl are real T-Pot ES `_source`
docs exported from the production ELK stack, then sanitized (attacker +
honeypot-infra IPs remapped to TEST-NET ranges, persona creds/hostnames
scrubbed, geoip faked) — structure, eventids and malware hashes preserved.

These guard against a parser silently breaking on real-world doc shapes
(the unit tests use synthetic docs; these use the real thing). Verified
2026-06-02: all 22 types parse with zero exceptions.
"""

from __future__ import annotations

import glob
import json
import os

import pytest

import tpot2cti.parsers as P

_FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "real")
_FIXTURES = sorted(glob.glob(os.path.join(_FIXTURE_DIR, "*.jsonl")))
_IDS = [os.path.basename(f)[:-6] for f in _FIXTURES]


def _load(path):
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


@pytest.mark.parametrize("path", _FIXTURES, ids=_IDS)
def test_real_docs_parse_without_exceptions(path):
    docs = _load(path)
    assert docs, f"empty fixture {path}"
    doc_type = docs[0].get("type", "")
    # Every type must have a DEDICATED parser (not just the fallback).
    assert doc_type in set(P.registered_types()), (
        f"{os.path.basename(path)}: doc type {doc_type!r} has no dedicated parser"
    )
    parser = P.get_parser(doc_type)

    parsed = []
    for d in docs:
        ev = parser.parse(d)          # must not raise on real data
        if ev is not None:
            parsed.append(ev)
    # At least one real doc of each type should produce an event (the rest
    # may be intentionally dropped, e.g. suricata non-alert telemetry).
    assert parsed, f"{os.path.basename(path)}: parser dropped ALL real docs"

    parser.correlate(parsed)   # must not raise


def test_cowrie_real_extraction_is_rich():
    """The flagship parser must still pull commands / creds / malware /
    success out of real Cowrie event shapes (regression guard)."""
    docs = _load(os.path.join(_FIXTURE_DIR, "cowrie.jsonl"))
    parser = P.get_parser("Cowrie")
    sessions = parser.correlate([e for e in (parser.parse(d) for d in docs) if e])
    assert sessions
    any_cmd = any(s.commands for s in sessions)
    any_cred = any(s.credentials_tried for s in sessions)
    any_mal = any(s.malware_hashes for s in sessions)
    any_success = any(s.auth_success for s in sessions)
    assert any_cmd, "no commands extracted from real Cowrie data"
    assert any_cred, "no credentials extracted from real Cowrie data"
    assert any_mal, "no malware hashes extracted from real Cowrie data"
    assert any_success, "no successful auth extracted from real Cowrie data"


def test_fixtures_are_sanitized():
    """Guard: no real persona tokens or honeypot WAN IP leaked into fixtures."""
    import re
    bad = re.compile(r"louisiana|lcia|99\.18\.26\.", re.I)
    for f in _FIXTURES:
        text = open(f, encoding="utf-8").read()
        assert not bad.search(text), f"unsanitized data in {os.path.basename(f)}"
