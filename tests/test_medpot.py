"""Medpot parser — parse / correlate / substance.

Migrated from the parser's old ``if __name__ == "__main__"`` smoke test so
CI (``pytest``) actually runs it. The cross-parser contract (parse returns
an event, reads dst_port, handles missing src_ip, correlates, build-path
emits STIX) is covered generically in test_parsers.py; this file pins the
Medpot-specific behavior (HL7 msg_type capture + always-substantive).
"""

from __future__ import annotations

from datetime import datetime, timezone

from tpot2cti.parsers.medpot import MedpotParser


def _docs(now):
    return [
        {  # ADT^A01 admit, with geoip
            "@timestamp": now.isoformat(), "type": "Medpot",
            "src_ip": "203.0.113.77", "src_port": 50050, "dst_port": 2575,
            "msg_type": "ADT^A01", "t-pot_hostname": "node1",
            "geoip": {"country_iso_code": "DE", "country_name": "Germany",
                      "asn": 3320, "organization": "Deutsche Telekom AG"},
        },
        {  # ORM^O01 order, minimal
            "@timestamp": now.isoformat(), "type": "Medpot",
            "src_ip": "198.51.100.31", "dst_port": 2575, "msg_type": "ORM^O01",
        },
        {  # no msg_type — still substantive
            "@timestamp": now.isoformat(), "type": "Medpot", "src_ip": "192.0.2.42",
        },
    ]


def test_parse_and_correlate_msg_type():
    now = datetime.now(timezone.utc)
    parser = MedpotParser()
    events = [parser.parse(d) for d in _docs(now)]
    assert all(e is not None for e in events)

    sessions = parser.correlate(events)
    assert len(sessions) == 3
    # HL7 message type is mirrored onto session.meta for the builder.
    assert sessions[0].meta.get("msg_type") == "ADT^A01"
    assert sessions[1].meta.get("msg_type") == "ORM^O01"
    # A doc with no msg_type leaves meta clean (no empty key).
    assert "msg_type" not in sessions[2].meta


def test_default_hl7_port_applied():
    now = datetime.now(timezone.utc)
    # dst_port absent → falls back to the conventional HL7 MLLP port.
    ev = MedpotParser().parse(
        {"@timestamp": now.isoformat(), "type": "Medpot", "src_ip": "192.0.2.42"}
    )
    assert ev is not None and ev.dst_port == 2575


def test_every_session_is_substantive():
    now = datetime.now(timezone.utc)
    parser = MedpotParser()
    sessions = parser.correlate([parser.parse(d) for d in _docs(now)])
    assert all(parser.has_substance(s) is True for s in sessions)


def test_malformed_docs_return_none():
    parser = MedpotParser()
    assert parser.parse({}) is None                      # no src_ip
    assert parser.parse({"src_ip": "1.2.3.4"}) is None    # no @timestamp
