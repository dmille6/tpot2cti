"""benign-scanner allowlist — yaml load + ASN/org match."""

from __future__ import annotations

from datetime import datetime, timezone

from tpot2cti.benign_filter import BenignScannerFilter
from tpot2cti.parsers.base import ParsedEvent


def _mk(asn=None, org=""):
    return ParsedEvent(
        src_ip="1.2.3.4",
        timestamp=datetime.now(timezone.utc),
        sensor_hostname="node1",
        event_type="Suricata",
        src_asn=asn,
        src_as_org=org,
    )


def test_yaml_loads_at_least_one_rule():
    """The shipped benign_scanners.yaml loads with non-zero rules."""
    f = BenignScannerFilter.from_yaml()
    assert len(f) >= 5


def test_google_asn_matches():
    """Google ASN 15169 -> 'google'."""
    f = BenignScannerFilter.from_yaml()
    assert f.match(_mk(asn=15169, org="Google LLC")) == "google"


def test_unknown_ip_does_not_match():
    """A random ASN+org returns None."""
    f = BenignScannerFilter.from_yaml()
    assert f.match(_mk(asn=99999, org="Random ISP")) is None


def test_org_keyword_substring_match():
    """An org name containing 'shodan' (case-insensitive) matches."""
    f = BenignScannerFilter.from_yaml()
    assert f.match(_mk(asn=0, org="Shodan LLC")) == "shodan"


def test_empty_filter_matches_nothing():
    """A filter constructed from no rules never matches."""
    assert BenignScannerFilter([]).match(_mk(asn=15169, org="Google")) is None


def test_missing_yaml_file_returns_empty_filter(tmp_path):
    """An absent yaml file yields a no-op filter, never raises."""
    f = BenignScannerFilter.from_yaml(path=tmp_path / "missing.yaml")
    assert len(f) == 0
