"""Sensor identity must not reach a shareable STIX object.

Measured on the live corpus 2026-08-05: 1,034 Notes and 4,442 Sighting
descriptions embedded a sensor-side public IP, and every parser-labelled
object carried a `sensor:<hostname>` label. A honeypot's value depends on
not being identifiable as one — published sensor addresses get null-routed
or fed garbage.

Redaction lives in the publisher, not the builders, because
`sensor_hostname` appears 59 times in stix/builder.py alone and every
emission path funnels through publish() — including the three (malware
ingest, noisefloor, blocklists) that never touch the builder.
"""
from __future__ import annotations

import pytest

from tpot2cti.redact import SensorRedactor, from_env

ENV = {
    "TPOT2CTI_SENSOR_HOSTNAMES": "hivev2,rail-prod-01",
    "TPOT_HONEYPOT_IPS": "99.18.26.18,99.18.26.21",
    "TPOT2CTI_EXCLUDED_SRC_NETS": "10.0.0.0/8",
    "TPOT2CTI_REDACTION_SECRET": "test-secret",
}


def _r():
    return from_env(ENV)


def test_a_sensor_hostname_never_survives_a_description():
    r = _r()
    o = r.redact({"type": "indicator", "description":
                  "Malicious IP 1.2.3.4 observed via Cowrie on sensor 'hivev2'."})
    assert "hivev2" not in o["description"]
    assert "sensor-" in o["description"], "correlation pseudonym was lost"


def test_a_sensor_address_never_survives_a_note():
    r = _r()
    o = r.redact({"type": "note", "content":
                  "Attacker engaged T-Pot sensor at 99.18.26.18 port 8443"})
    assert "99.18.26.18" not in o["content"]
    assert "<sensor-address>" in o["content"]


@pytest.mark.parametrize("field", [
    "description", "x_opencti_description", "content", "abstract", "name",
])
def test_every_human_readable_field_is_scrubbed(field):
    r = _r()
    o = r.redact({"type": "note", field: "seen on hivev2 / 99.18.26.21"})
    assert "hivev2" not in o[field] and "99.18.26.21" not in o[field]


def test_sensor_labels_are_pseudonymised_not_dropped():
    r = _r()
    o = r.redact({"type": "url", "x_opencti_labels":
                  ["sensor:hivev2", "cowrie", "honeypot"]})
    labels = o["x_opencti_labels"]
    assert "sensor:hivev2" not in labels
    assert any(l.startswith("sensor:sensor-") for l in labels), labels
    assert "cowrie" in labels and "honeypot" in labels, "unrelated labels lost"


def test_an_unconfigured_sensor_is_still_pseudonymised_in_labels():
    """The label is the one place the hostname is recoverable from the object
    itself, so an operator who has not enumerated every sensor still gets
    label redaction."""
    o = _r().redact({"type": "url", "x_opencti_labels": ["sensor:never-listed"]})
    assert o["x_opencti_labels"] == ["sensor:sensor-6cfdeece"] or \
        o["x_opencti_labels"][0].startswith("sensor:sensor-")
    assert "never-listed" not in o["x_opencti_labels"][0]


def test_pseudonyms_are_stable_and_distinct():
    """Stable so cross-object correlation survives; distinct so two sensors
    do not collapse into one."""
    a, b = _r(), _r()
    x = a.redact({"description": "hivev2"})["description"]
    y = b.redact({"description": "hivev2"})["description"]
    z = a.redact({"description": "rail-prod-01"})["description"]
    assert x == y, "pseudonym is not stable across runs"
    assert x != z, "two sensors collapsed to one pseudonym"


def test_the_pseudonym_is_not_the_hostname_hashed_without_a_secret():
    """An outside reader must not be able to confirm a guessed hostname."""
    import hashlib
    plain = hashlib.sha256(b"hivev2").hexdigest()[:8]
    got = _r().redact({"description": "hivev2"})["description"]
    assert plain not in got


def test_redaction_is_on_by_default_in_the_publisher():
    """The un-bypassable property. A producer that constructs a Publisher
    without thinking about redaction must still get it."""
    import inspect
    from tpot2cti import publisher
    src = inspect.getsource(publisher.Publisher.__init__)
    assert "from_env" in src, "Publisher no longer defaults the redactor on"
    pub_src = inspect.getsource(publisher.Publisher.publish)
    assert "self.redactor.redact_all(objects)" in pub_src, (
        "publish() no longer redacts — every emission path leaks again"
    )


def test_objects_without_text_are_untouched():
    r = _r()
    o = {"type": "ipv4-addr", "value": "1.2.3.4"}
    assert r.redact(o) == o
    assert r.redactions == 0


def test_an_empty_configuration_does_not_crash():
    r = SensorRedactor([], [], secret="s")
    o = {"type": "note", "content": "nothing to redact"}
    assert r.redact(o)["content"] == "nothing to redact"


# ── CIDR containment (the security control was false) ────────────────────

def test_an_address_inside_a_configured_net_is_redacted():
    """The bug: nets were compiled into the same regex as bare addresses, so
    `10.0.0.0/8` only ever matched the literal TEXT "10.0.0.0/8". An actual
    sensor address inside that net — the entire reason to configure a net —
    passed through unredacted."""
    r = SensorRedactor([], ["10.0.0.0/8"], secret="s")
    out = r.redact({"content": "attacker reached 10.4.5.6 on the sensor net"})
    assert "10.4.5.6" not in out["content"]
    assert "<sensor-address>" in out["content"]


def test_addresses_outside_the_net_are_left_alone():
    """Positive control — over-redacting would destroy the attacker IPs that
    are the actual product."""
    r = SensorRedactor([], ["10.0.0.0/8"], secret="s")
    out = r.redact({"content": "attacker 8.8.8.8 hit 203.0.113.9"})
    assert "8.8.8.8" in out["content"] and "203.0.113.9" in out["content"]
    assert r.redactions == 0


def test_ipv6_containment():
    r = SensorRedactor([], ["2001:db8::/32"], secret="s")
    out = r.redact({"content": "from 2001:db8::dead:beef inbound"})
    assert "2001:db8::dead:beef" not in out["content"]


def test_a_v4_address_is_not_matched_against_a_v6_net():
    r = SensorRedactor([], ["2001:db8::/32"], secret="s")
    out = r.redact({"content": "plain 10.4.5.6 here"})
    assert "10.4.5.6" in out["content"]


def test_literal_addresses_still_work_alongside_nets():
    r = SensorRedactor([], ["10.0.0.0/8", "203.0.113.7"], secret="s")
    out = r.redact({"content": "10.1.2.3 and 203.0.113.7 and 8.8.4.4"})
    assert "10.1.2.3" not in out["content"] and "203.0.113.7" not in out["content"]
    assert "8.8.4.4" in out["content"]


def test_the_default_secret_is_flagged():
    """A pseudonym derived from a public constant is confirmable by anyone."""
    assert SensorRedactor([], [], secret="").using_default_secret is True
    assert SensorRedactor([], [], secret="real").using_default_secret is False


# ── redaction must be visible, and must handle mapped v6 ─────────────────

def test_an_ipv4_mapped_ipv6_literal_is_redacted():
    """`::ffff:10.0.0.1` parses as version 6 but denotes a version-4
    address. Without unmapping, the version guard silently rejects every
    match and the token leaks."""
    r = SensorRedactor([], ["10.0.0.0/8"], secret="s")
    out = r.redact({"content": "mapped ::ffff:10.0.0.1 here"})
    assert "::ffff:10.0.0.1" not in out["content"]
    assert r.counts.get("address-in-sensor-net") == 1


def test_a_mapped_address_outside_the_net_is_kept():
    r = SensorRedactor([], ["10.0.0.0/8"], secret="s")
    out = r.redact({"content": "v6 ::ffff:8.8.8.8 stays"})
    assert "8.8.8.8" in out["content"] and r.redactions == 0


def test_redactions_are_counted_by_reason():
    """A bare total cannot distinguish 'we pseudonymised a label' from 'we
    destroyed an attacker IP because a configured net was too broad'."""
    r = SensorRedactor(["hivev2"], ["10.0.0.0/8", "203.0.113.7"], secret="s")
    r.redact({"content": "hivev2 at 203.0.113.7 saw 10.4.5.6",
              "x_opencti_labels": ["sensor:hivev2"]})
    assert r.counts["sensor-hostname"] >= 1
    assert r.counts["configured-address"] >= 1
    assert r.counts["address-in-sensor-net"] >= 1
    assert r.counts["sensor-label"] >= 1
    assert sum(r.counts.values()) == r.redactions


def test_begin_cycle_resets_counts():
    r = SensorRedactor([], ["10.0.0.0/8"], secret="s")
    r.redact({"content": "10.1.1.1"})
    assert r.redactions == 1
    r.begin_cycle()
    assert r.redactions == 0 and r.counts == {}


def test_the_publisher_logs_the_breakdown():
    """A control that rewrites published text silently is indistinguishable
    from one that is broken."""
    import inspect
    from tpot2cti import publisher
    src = inspect.getsource(publisher.Publisher.publish)
    assert "begin_cycle()" in src, "counters are never reset per publish"
    assert "sensor redaction" in src, "redaction count is never logged"
