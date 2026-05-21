"""tpot2cti — pivot-menu external_references for STIX observables.

Returns STIX 2.1 `external_references` dicts that give the OpenCTI
analyst one-click pivots to authoritative threat-intel lookup pages
(AbuseIPDB, VirusTotal, Shodan, Censys, GreyNoise, etc.). Analysts open
the IP page during triage far more often than they open the Indicator
page, so the pivot menu belongs on the observable too — not only the
indicator.

Adapted from the PoC at
/home/mike/poc/tsec-tpot-connectors/shared/tsec_external_refs.py
(see also docs/LESSONS_LEARNED_FROM_V0.md §6 and the first-live-install
postmortem on "thin objects").

Field name is the STIX 2.1 standard `external_references` — NOT the
x_opencti_-prefixed form. The x_opencti_ prefix is reserved for
non-standard fields; external_references is in-spec.

All pivots are vendor-neutral public lookup pages — no API keys
required for analyst navigation. The links resolve in any modern
browser. If a vendor changes their URL scheme we update here; existing
emissions get the new URL automatically on the next cycle's upsert.
"""

from __future__ import annotations

from typing import List, Dict, Optional


# ---------------------------------------------------------------------------
# IP pivots (v4 and v6)
# ---------------------------------------------------------------------------

def for_ipv4(ip: str) -> List[Dict[str, str]]:
    """Pivot menu for a public IPv4 address.

    Returns one external_reference dict per pivot source. Order is the
    one analysts visit most often during triage.
    """
    if not ip:
        return []
    return [
        {
            "source_name": "AbuseIPDB",
            "url": f"https://www.abuseipdb.com/check/{ip}",
            "description": (
                "AbuseIPDB community-reported abuse history — confidence "
                "score, report categories, reporter count."
            ),
        },
        {
            "source_name": "VirusTotal",
            "url": f"https://www.virustotal.com/gui/ip-address/{ip}",
            "description": (
                "VirusTotal aggregated detections, passive DNS, "
                "communicating malware samples, WHOIS."
            ),
        },
        {
            "source_name": "Shodan",
            "url": f"https://www.shodan.io/host/{ip}",
            "description": (
                "Shodan host profile — exposed services, banners, "
                "vulnerabilities, honeypot score."
            ),
        },
        {
            "source_name": "Censys",
            "url": f"https://search.censys.io/hosts/{ip}",
            "description": (
                "Censys host scan history — open ports, TLS certificates, "
                "protocol details."
            ),
        },
        {
            "source_name": "GreyNoise",
            "url": f"https://viz.greynoise.io/ip/{ip}",
            "description": (
                "GreyNoise classification — benign scanner, malicious "
                "actor, or unknown internet noise."
            ),
        },
    ]


def for_ipv6(ip: str) -> List[Dict[str, str]]:
    """Pivot menu for an IPv6 address. Subset of v4 — not every vendor
    has a stable IPv6 lookup URL."""
    if not ip:
        return []
    return [
        {
            "source_name": "VirusTotal",
            "url": f"https://www.virustotal.com/gui/ip-address/{ip}",
            "description": "VirusTotal aggregated detections + passive DNS for this IPv6.",
        },
        {
            "source_name": "Censys",
            "url": f"https://search.censys.io/hosts/{ip}",
            "description": "Censys host scan history (IPv6).",
        },
    ]


# ---------------------------------------------------------------------------
# File hash pivots
# ---------------------------------------------------------------------------

def for_file_sha256(sha256: str) -> List[Dict[str, str]]:
    """Pivot menu for a file by SHA-256 hash."""
    if not sha256:
        return []
    sha256 = sha256.lower()
    return [
        {
            "source_name": "VirusTotal",
            "url": f"https://www.virustotal.com/gui/file/{sha256}",
            "description": (
                "VirusTotal per-engine detections, behavior analysis, "
                "and YARA matches."
            ),
        },
        {
            "source_name": "MalwareBazaar",
            "url": f"https://bazaar.abuse.ch/sample/{sha256}/",
            "description": (
                "MalwareBazaar sample page — signatures, downloads, "
                "tag taxonomy."
            ),
        },
        {
            "source_name": "Hybrid Analysis",
            "url": f"https://www.hybrid-analysis.com/sample/{sha256}",
            "description": "Hybrid Analysis sandbox report (if available).",
        },
    ]


# ---------------------------------------------------------------------------
# URL / domain pivots
# ---------------------------------------------------------------------------

def for_url(url: str) -> List[Dict[str, str]]:
    """Pivot menu for a URL. VirusTotal supports URL lookups via base64-url
    encoding of the URL; we keep things simple and just point at VT's URL
    search page with the URL pre-filled as a search query."""
    if not url:
        return []
    return [
        {
            "source_name": "VirusTotal",
            "url": f"https://www.virustotal.com/gui/search/{url}",
            "description": (
                "VirusTotal URL/domain search — detections, redirects, "
                "communicating files."
            ),
        },
        {
            "source_name": "urlscan.io",
            "url": f"https://urlscan.io/search/#{url}",
            "description": "urlscan.io search — screenshot, DOM, response chain.",
        },
    ]


def for_domain(fqdn: str) -> List[Dict[str, str]]:
    """Pivot menu for a domain (DNS hostname)."""
    if not fqdn:
        return []
    return [
        {
            "source_name": "VirusTotal",
            "url": f"https://www.virustotal.com/gui/domain/{fqdn}",
            "description": "VirusTotal domain page — DNS records, subdomains, sibling indicators.",
        },
        {
            "source_name": "urlscan.io",
            "url": f"https://urlscan.io/domain/{fqdn}",
            "description": "urlscan.io scans of this domain.",
        },
        {
            "source_name": "Shodan",
            "url": f"https://www.shodan.io/search?query=hostname%3A{fqdn}",
            "description": "Shodan hosts with this hostname in their banners.",
        },
    ]


# ---------------------------------------------------------------------------
# AS pivots
# ---------------------------------------------------------------------------

def for_autonomous_system(asn: Optional[int]) -> List[Dict[str, str]]:
    """Pivot menu for an autonomous system by ASN."""
    if asn is None:
        return []
    return [
        {
            "source_name": "Hurricane Electric BGP",
            "url": f"https://bgp.he.net/AS{asn}",
            "description": (
                "Hurricane Electric BGP toolkit — peers, prefixes, IPs, "
                "and history."
            ),
        },
        {
            "source_name": "RIPEstat",
            "url": f"https://stat.ripe.net/AS{asn}",
            "description": "RIPE NCC statistics for this AS.",
        },
    ]


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
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
