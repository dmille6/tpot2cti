"""Unit tests for tpot2cti.port_intel — port/service mapping, scan
classification, and payload fingerprinting (the Honeytrap full-squeeze)."""
from __future__ import annotations

from tpot2cti import port_intel


def test_service_and_family_lookup():
    assert port_intel.service_for_port(2082) == "cPanel"
    assert port_intel.family_for_port(2082) == "cpanel"
    assert port_intel.family_for_port(2087) == "cpanel"  # WHM-SSL → same family
    assert port_intel.service_for_port(23) == "Telnet"
    assert port_intel.family_for_port(2323) == "telnet"  # alt telnet → telnet
    assert port_intel.service_for_port(65000) is None
    assert port_intel.service_for_port(None) is None


def test_summarize_ports_sorted_annotated_and_capped():
    out = port_intel.summarize_ports({2087, 22, 2082})
    # sorted ascending, each annotated with its service
    assert out == "tcp/22 (SSH), tcp/2082 (cPanel), tcp/2087 (WHM-SSL)"
    # cap collapses the tail
    many = port_intel.summarize_ports(set(range(1, 50)), cap=5)
    assert "+44 more" in many
    assert port_intel.summarize_ports(set()) == ""


def test_classify_scan_shapes():
    labels, phrase = port_intel.classify_scan({4444})
    assert "scan:single" in labels and "single-port probe" in phrase

    labels, phrase = port_intel.classify_scan({2082, 2083, 2086})
    assert "scan:multi-port" in labels
    assert "target:cpanel" in labels
    assert labels.count("target:cpanel") == 1  # one family label, not three
    assert "cpanel" in phrase

    labels, phrase = port_intel.classify_scan({2082, 2083, 2086, 2087, 2095, 2096})
    assert "scan:vertical" in labels
    assert "target:cpanel" in labels
    assert "6 ports" in phrase

    # Broad recon across many families (6 ports → vertical + broad)
    labels, _ = port_intel.classify_scan({22, 80, 445, 3389, 6379, 27017})
    assert "scan:vertical" in labels
    assert "recon:broad" in labels

    # Five distinct-family ports is still multi-port, but broad
    labels, _ = port_intel.classify_scan({22, 80, 445, 3389, 6379})
    assert "scan:multi-port" in labels
    assert "recon:broad" in labels

    labels, phrase = port_intel.classify_scan(set())
    assert labels == []


def test_fingerprint_http_request():
    fp = port_intel.fingerprint_payload("GET /admin HTTP/1.1\r\nHost: x\r\n", "")
    assert fp is not None
    assert fp["label"] == "proto:http"
    assert fp["http"] == {"method": "GET", "path": "/admin"}
    assert "HTTP GET" in fp["summary"]


def test_fingerprint_scanner_signature_beats_http():
    # An HTTP probe carrying a ZGrab marker is classified as the scanner.
    fp = port_intel.fingerprint_payload(
        "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 zgrab/0.x\r\n", ""
    )
    assert fp["label"] == "scanner:zgrab"
    assert "ZGrab" in fp["summary"]


def test_fingerprint_tls_clienthello_from_hex():
    fp = port_intel.fingerprint_payload("", "16030100a5deadbeef")
    assert fp["label"] == "proto:tls"
    assert "ClientHello" in fp["summary"]


def test_fingerprint_empty_is_none():
    assert port_intel.fingerprint_payload("", "") is None
    assert port_intel.fingerprint_payload(None, None) is None


def test_fingerprint_unknown_bytes_still_summarized():
    fp = port_intel.fingerprint_payload("\x01\x02random", "0102")
    assert fp is not None
    assert fp["label"] is None
    assert "no known signature" in fp["summary"]
