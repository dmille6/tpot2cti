"""Our own attack surface is not an indicator.

Measured on the live corpus 2026-08-06 after a 19-day backfill: 53,880 Url
observables — the LARGEST object type, bigger than ipv4-addr — and every
sampled value was a sensor's own address:

    https://<sensor-ip>/vtigercrm/AboSala7.php?asd
    https://<sensor-ip>/panel/webadmin.php?

Those are attackers probing us. Publishing them tells a consumer that OUR
surface is attacker infrastructure.

The dominant producer is h0neytr4p.py:387, which reconstructs a full URL from
the inbound `Host` header plus the request URI — NOT the Suricata SNI path
that docs/EVIDENCE.md named.
"""
from __future__ import annotations

import pytest

from tpot2cti.redact import SensorRedactor
from tpot2cti.stix.builder import STIXBuilder

SENSOR_IP = "99.18.26.18"
SENSOR_HOST = "db1.persona.example"   # sensors are reached by FQDN


@pytest.fixture()
def b(cfg):
    bl = STIXBuilder(cfg)
    bl._redactor = SensorRedactor([SENSOR_HOST], [SENSOR_IP, "10.0.0.0/8"],
                                  secret="test")
    return bl


@pytest.mark.parametrize("url", [
    f"https://{SENSOR_IP}/vtigercrm/AboSala7.php?asd",
    f"http://{SENSOR_IP}/panel/webadmin.php",
    f"https://{SENSOR_HOST}/wp-login.php",
    f"http://{SENSOR_HOST}:8080/settings.json",
    "http://10.4.5.6/admin",              # inside a configured net
    f"https://{SENSOR_IP}:8443/recordings/Go.php",
])
def test_a_url_on_our_own_surface_is_refused(b, url):
    assert b.build_url(url) is None, f"still publishing our own surface: {url}"
    assert b.rejected_own_surface_urls >= 1


def test_genuine_attacker_urls_are_untouched(b):
    """The positive control. Over-refusing would destroy the actual product."""
    for url in ("http://evil.example/x.sh",
                "https://cdn-n5f.pages.dev/a",
                "tftp://185.62.190.11/bins.sh",
                "http://8.8.8.8/payload"):
        assert b.build_url(url) is not None, f"refused a real IoC: {url}"
    assert b.rejected_own_surface_urls == 0


def test_jndi_payloads_are_exempt(b):
    """Log4Shell hosts are unresolved templates by design, the payload IS the
    evidence, and build_unattributed_payload_objects anchors an entire
    Sighting/Note/CVE graph on the URL id — refusing one would silently
    delete that graph."""
    exfil = "ldap://x-${sys:java.version}.c2.example/a"
    assert b.build_url(exfil) is not None
    # even when the JNDI host IS ours, the payload is still the evidence
    assert b.build_url(f"ldap://{SENSOR_IP}/Exploit") is not None
    assert b.rejected_own_surface_urls == 0


def test_the_refusal_is_counted_separately(b):
    """`rejected_urls` alone cannot distinguish 'malformed' from 'we stopped
    publishing our own surface'."""
    b.build_url("/bare-path")                       # malformed
    b.build_url(f"https://{SENSOR_IP}/x")           # own surface
    assert b.rejected_urls == 2
    assert b.rejected_own_surface_urls == 1


def test_a_bare_sensor_hostname_is_still_refused(b):
    """A hostname with no TLD (`hivev2`) is refused by valid_url BEFORE the
    guard sees it — different path, same outcome. Asserted so the guard's
    counter is not credited with a rejection it did not make."""
    before = b.rejected_own_surface_urls
    assert b.build_url("https://hivev2/wp-login.php") is None
    assert b.rejected_own_surface_urls == before, (
        "the own-surface counter claimed a rejection valid_url made"
    )


def test_no_redactor_means_no_crash(cfg):
    """The guard must never break the builder if redaction is unconfigured."""
    bl = STIXBuilder(cfg)
    bl._redactor = None
    assert bl.build_url("http://evil.example/x") is not None
