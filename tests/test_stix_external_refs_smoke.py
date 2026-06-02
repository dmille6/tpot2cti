"""Smoke test for tpot2cti.stix.external_refs (migrated from its old
`if __name__` block so CI runs it)."""
from __future__ import annotations

import tpot2cti.stix.external_refs as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_external_refs_smoke():
    refs = for_ipv4("1.2.3.4")
    assert len(refs) == 5
    assert refs[0]["source_name"] == "AbuseIPDB"
    assert "1.2.3.4" in refs[0]["url"]

    refs = for_ipv6("2001:db8::1")
    assert len(refs) == 2

    refs = for_file_sha256("ABC123" + "0" * 58)
    assert all("abc123" in r["url"].lower() or r["source_name"] == "Hybrid Analysis"
               or "/sample/" in r["url"] for r in refs)

    refs = for_url("http://evil.example.com/x.sh")
    assert len(refs) >= 1

    refs = for_domain("evil.example.com")
    assert len(refs) >= 2

    refs = for_autonomous_system(15169)
    assert len(refs) == 2
    assert "AS15169" in refs[0]["url"]

    # Empty inputs return empty lists, not None
    assert for_ipv4("") == []
    assert for_file_sha256("") == []
    assert for_autonomous_system(None) == []

    print("OK")
