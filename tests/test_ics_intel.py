"""ICS intelligence (2026-09-30): the ConPot parser, the ICS evidence class,
ICS labels, the SNMP refusals and research scanners.

Fixtures: ``tests/fixtures/ics/*.jsonl`` are real hive documents (ConPot
sessions and ICS emulator rows logged as Heralding), redacted: TEST-NET
addresses, generic sensor names, responses and SNMP values replaced, dotted
OIDs stored in ConPot's tuple form, addresses inside hex payloads rewritten
to a same-length documentation address. ``scenario`` names what each one is.
They are NOT under tests/fixtures/real, so the DR-02 cycle bundle does not
read them.

The write/control frames in section 2b are SYNTHETIC: in the 35 days of data
behind this change there was no Modbus, S7, IEC-104, ENIP, BACnet, DNP3,
OPC UA, HART-IP or GE-SRTP write at all (one SNMP Set, which is a fixture).
"""
from __future__ import annotations

import copy
import json
import struct
import tempfile
from collections import defaultdict
from pathlib import Path

import pytest

from tests import dr02_harness as H
from tpot2cti import evidence, ics
from tpot2cti.benign_filter import BenignScannerFilter
from tpot2cti.main import run_cycle
from tpot2cti.parsers.conpot import ConPotParser
from tpot2cti.parsers.heralding import HeraldingParser
from tpot2cti.state import CycleState
from tpot2cti.stix_ids import attacker_ip_indicator_id, attacker_ip_observable_id

FIX = Path(__file__).parent / "fixtures" / "ics"
GATE = "TPOT2CTI_EVIDENCE_GATE"
DECOUPLED = "TPOT2CTI_SIGHTINGS_DECOUPLED"
REFUSALS = "TPOT2CTI_ICS_REFUSALS"


def _load(name):
    return [json.loads(l) for l in (FIX / name).read_text(encoding="utf-8").splitlines() if l.strip()]


CONPOT = _load("conpot_ics.jsonl")
HERALD = _load("heralding_ics.jsonl")


def _routable(docs, base="45.30"):
    """Fixture addresses are TEST-NET (the cycle drops those as internal):
    map each to a stable routable one, as the DR-02 harness does."""
    m = {}
    out = []
    for d in docs:
        d = copy.deepcopy(d)
        ip = d["src_ip"]
        if ip not in m:
            m[ip] = f"{base}.{len(m) // 250}.{len(m) % 250 + 1}"
        d["src_ip"] = m[ip]
        out.append(d)
    return out


def _scenario(name, docs=CONPOT):
    out = [d for d in docs if d["scenario"] == name]
    assert out, name
    return out


def _conpot_session(name, *, research_scanner=None):
    p = ConPotParser()
    evs = [p.parse(d) for d in _routable(_scenario(name))]
    if research_scanner:
        for e in evs:
            e.meta["research_scanner"] = research_scanner
    (s,) = p.correlate(evs)
    return s


def _herald_session(name):
    """The FIRST emulator row of a scenario, as its own session."""
    p = HeraldingParser()
    evs = [p.parse(d) for d in _routable(_scenario(name, HERALD)[:1], base="45.31")]
    (s,) = p.correlate(evs)
    return s


# ---------------------------------------------------------------------------
# 1. The parser defect: protocol from data_type, sessions from `id`
# ---------------------------------------------------------------------------

def test_protocol_comes_from_data_type_never_from_event_type():
    p = ConPotParser()
    for d in CONPOT:
        ev = p.parse(d)
        assert ev.protocol == ics.conpot_protocol(d)
        assert ev.protocol not in ("new_connection", "connection_lost", "snmpv2 bulk", None)
        assert ev.session_id == d["id"]


def test_one_conpot_session_per_id():
    by_id = defaultdict(list)
    for d in CONPOT:
        by_id[d["id"]].append(d)
    p = ConPotParser()
    sessions = p.correlate([p.parse(d) for d in CONPOT])
    assert len(sessions) == len(by_id)
    for s in sessions:
        assert s.event_count == len(by_id[s.session_id])
        assert s.meta["ics"]["protocols"] == [ics.conpot_protocol(by_id[s.session_id][0])]


def test_a_doc_without_an_id_is_still_summarised():
    d = dict(_scenario("snmp_get")[0])
    d.pop("id")
    p = ConPotParser()
    (s,) = p.correlate([p.parse(d)])
    assert s.meta["ics"]["snmp_only"] is True


def test_the_legacy_protocol_field_still_works():
    d = {"@timestamp": "2026-09-01T00:00:00Z", "src_ip": "198.51.100.1",
         "protocol": "modbus", "request": "b'000100000006010300000001'"}
    ev = ConPotParser().parse(d)
    assert ev.protocol == "modbus"
    assert ev.meta["ics_finding"]["tier"] == "interaction"


def test_requests_are_deduplicated_per_session():
    s = _conpot_session("snmp_bulk")
    assert s.event_count == 4 and len(s.protocol_requests) == 1
    assert s.commands == []


# ---------------------------------------------------------------------------
# 2a. Classification of real documents
# ---------------------------------------------------------------------------

EXPECTED_CONPOT = {
    # scenario: (tier, protocol, a function substring or None)
    "modbus_fc43": ("interaction", "modbus", "FC43"),
    "modbus_umas": ("interaction", "modbus", "UMAS"),
    "s7_szl": ("interaction", "s7comm", "SZL read"),
    "s7_scanner": ("interaction", "s7comm", "SZL read"),
    "snmp_bulk": ("interaction", "snmp", "bulk"),
    "snmp_get": ("interaction", "snmp", "get"),
    "snmp_getnext": ("interaction", "snmp", "getnext"),
    "snmp_set": ("write", "snmp", "set"),
    "iec104_connect": ("connect", "iec104", None),
    "enip_connect": ("connect", "enip", None),
    "bacnet_connect": ("connect", "bacnet", None),
    "http_get": ("interaction", "http", "HTTP /"),
    "http_invalid": ("invalid", "http", None),
    "ftp_cmd": ("interaction", "ftp", "FTP"),
    "ipmi_auth": ("interaction", "ipmi", None),
    "kamstrup_mgmt_http": ("invalid", "kamstrup-management", None),
}


@pytest.mark.parametrize("scenario", sorted(EXPECTED_CONPOT))
def test_real_conpot_sessions_classify(scenario):
    tier, proto, fn = EXPECTED_CONPOT[scenario]
    s = _conpot_session(scenario)
    summ = s.meta["ics"]
    assert summ["tier"] == tier and summ["protocols"] == [proto]
    if fn:
        assert any(fn in f for f in summ["functions"]), summ["functions"]
    assert summ["write"] is (tier == "write")


def test_the_whole_s7_identity_sequence_is_seen():
    fs = _conpot_session("s7_szl").meta["ics"]["functions"]
    assert "COTP Connect Request" in fs and "Setup Communication" in fs
    assert any(f.startswith("SZL read 0x") for f in fs)


def test_snmp_flags():
    assert _conpot_session("snmp_bulk").meta["ics"]["snmp_bulk_only"] is True
    get = _conpot_session("snmp_get").meta["ics"]
    assert get["snmp_only"] is True and get["snmp_bulk_only"] is False
    assert _conpot_session("snmp_set").meta["ics"]["write_functions"] == ["SNMP set 1.3.6.1.2.1.1.1.0"]


@pytest.mark.parametrize("doc", HERALD, ids=[d["scenario"] for d in HERALD])
def test_real_emulator_rows_classify(doc):
    proto, tier = doc["scenario"].split(":")
    f = ics.classify_doc(doc)
    assert (f.protocol, f.tier) == (proto, tier)


# ---------------------------------------------------------------------------
# 2b. Write / control: SYNTHETIC frames (none occurred in 35 days)
# ---------------------------------------------------------------------------

def mbap(unit, pdu, tid=1):
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def s7_job(fn, extra=b"", data=b"", tpkt_delta=0):
    par = bytes([fn]) + extra
    s7 = b"\x32\x01\x00\x00\x00\x01" + struct.pack(">HH", len(par), len(data)) + par + data
    cotp = b"\x02\xf0\x80"
    return b"\x03\x00" + struct.pack(">H", 4 + len(cotp) + len(s7) + tpkt_delta) + cotp + s7


S7_ITEM = bytes.fromhex("120a10020001000184000000")      # one S7ANY item, DB1.DBX0.0 byte
S7_PI = b"\x00\x00\x00\x00\x00\x09P_PROGRAM"


def dnp3_frame(link_fc, user=b"", prm=True):
    """A DNP3 link frame with correct CRCs (link header, then 16-byte blocks)."""
    ctrl = 0x80 | (0x40 if prm else 0) | link_fc
    head = bytes([0x05, 0x64, 5 + len(user), ctrl, 0x01, 0x00, 0x04, 0x00])
    out = head + ics.dnp3_crc(head).to_bytes(2, "little")
    for i in range(0, len(user), 16):
        blk = user[i:i + 16]
        out += blk + ics.dnp3_crc(blk).to_bytes(2, "little")
    return out


def iec_i(typeid, cot=6):
    asdu = bytes([typeid, 1, cot, 0, 1, 0, 0x01, 0x00, 0x00, 0x01])
    apdu = b"\x00\x00\x00\x00" + asdu
    return b"\x68" + bytes([len(apdu)]) + apdu


def enip(cmd, data=b""):
    return struct.pack("<HHII8sI", cmd, len(data), 0, 0, b"\x00" * 8, 0) + data


def cpf_ucmm(cip):
    items = struct.pack("<HH", 0, 0) + struct.pack("<HH", 0x00B2, len(cip)) + cip
    return struct.pack("<IHH", 0, 0, 2) + items


def bacnet_confirmed(svc):
    return b"\x81\x0a\x00\x11\x01\x04" + bytes([0x00, 0x05, 0x01, svc]) + b"\x0c\x02\x00\x00\x01\x19\x4d"


def opcua_msg(node, ns=0, size_delta=0):
    body = struct.pack("<IIII", 1, 1, 1, 1) + bytes([0x01, ns]) + struct.pack("<H", node) + b"\x00" * 8
    return b"MSGF" + struct.pack("<I", 8 + len(body) + size_delta) + body


def hartip(msg_id, pdu=b"", count_delta=0):
    return bytes([1, 0, msg_id, 0]) + struct.pack(">HH", 1, 8 + len(pdu) + count_delta) + pdu


SYNTHETIC = [
    # (label, classifier, payload, tier, function substring)
    ("modbus FC6", ics.classify_modbus, mbap(1, b"\x06\x00\x01\x00\x2a"), "write", "FC6"),
    ("modbus FC16", ics.classify_modbus, mbap(1, b"\x10\x00\x00\x00\x01\x02\x00\x07"), "write", "FC16"),
    ("modbus FC23", ics.classify_modbus,
     mbap(1, b"\x17\x00\x00\x00\x01\x00\x05\x00\x01\x02\x00\x07"), "write", "FC23"),
    ("modbus FC6 header only (NEGATIVE)", ics.classify_modbus, mbap(1, b"\x06"), "invalid", "malformed"),
    ("modbus FC6 short body (NEGATIVE)", ics.classify_modbus, mbap(1, b"\x06\x00\x01"), "invalid", None),
    ("modbus FC16 byte count wrong (NEGATIVE)", ics.classify_modbus,
     mbap(1, b"\x10\x00\x00\x00\x02\x02\x00\x07"), "invalid", None),
    ("modbus FC5 bad value (NEGATIVE)", ics.classify_modbus, mbap(1, b"\x05\x00\x01\x12\x34"), "invalid", None),
    ("modbus FC3 zero quantity (NEGATIVE)", ics.classify_modbus, mbap(1, b"\x03\x00\x00\x00\x00"), "invalid", None),
    ("modbus FC8 restart", ics.classify_modbus, mbap(1, b"\x08\x00\x01\x00\x00"), "write", "sub 1"),
    ("modbus FC8 echo", ics.classify_modbus, mbap(1, b"\x08\x00\x00\x12\x34"), "interaction", "FC8"),
    ("modbus UMAS stop", ics.classify_modbus, mbap(0, b"\x5a\x00\x41"), "write", "UMAS 0x41"),
    ("modbus read then write", ics.classify_modbus,
     mbap(1, b"\x03\x00\x00\x00\x01") + mbap(1, b"\x05\x00\x01\xff\x00", tid=2), "write", "FC5"),
    ("modbus FC0 (LDAP bytes)", ics.classify_modbus, bytes.fromhex("30840000000602000000"), "invalid", None),
    ("s7 Write Var", ics.classify_s7, s7_job(0x05, b"\x01" + S7_ITEM, b"\x00\x04\x00\x08\x01"),
     "write", "Write Var"),
    ("s7 PLC Stop", ics.classify_s7, s7_job(0x29, S7_PI), "write", "PLC Stop"),
    ("s7 Request Download", ics.classify_s7, s7_job(0x1A, b"\x00" * 9), "write", "Download"),
    ("s7 Read Var", ics.classify_s7, s7_job(0x04, b"\x01" + S7_ITEM), "interaction", "Read Var"),
    ("s7 Upload is a read", ics.classify_s7, s7_job(0x1E, b"\x00" * 7), "interaction", "Upload"),
    ("s7 Start Upload is a read", ics.classify_s7, s7_job(0x1D, b"\x00" * 17), "interaction", "Start Upload"),
    ("s7 Write Var bad TPKT length (NEGATIVE)", ics.classify_s7,
     s7_job(0x05, b"\x01" + S7_ITEM, b"\x00\x04\x00\x08\x01", tpkt_delta=5), "invalid", None),
    ("s7 Write Var lengths disagree (NEGATIVE)", ics.classify_s7,
     s7_job(0x05, b"\x01" + S7_ITEM, b"\x00\x04\x00\x08\x01")[:-2] + b"\x00\x00"[:0], "invalid", None),
    ("s7 Write Var without data (NEGATIVE)", ics.classify_s7, s7_job(0x05, b"\x01" + S7_ITEM), "invalid", None),
    ("s7 PLC Stop header only (NEGATIVE)", ics.classify_s7, s7_job(0x29), "invalid", None),
    ("s7 HTTP on 102", ics.classify_s7, b"GET / HTTP/1.1\r\n\r\n", "invalid", None),
    ("iec104 single command act", ics.classify_iec104, iec_i(45), "write", "C_SC_NA_1"),
    ("iec104 double command act", ics.classify_iec104, iec_i(46), "write", "C_DC_NA_1"),
    ("iec104 set-point time-tagged", ics.classify_iec104, iec_i(61), "write", "type 61"),
    ("iec104 reset process", ics.classify_iec104, iec_i(105), "write", "reset process"),
    ("iec104 command, cot 7 (confirm)", ics.classify_iec104, iec_i(45, cot=7), "interaction", None),
    ("iec104 GI", ics.classify_iec104, iec_i(100), "interaction", "interrogation"),
    ("iec104 STARTDT", ics.classify_iec104, b"\x68\x04\x07\x00\x00\x00", "handshake", "STARTDT"),
    ("iec104 TESTFR", ics.classify_iec104, b"\x68\x04\x43\x00\x00\x00", "handshake", "TESTFR"),
    # The review's "commands" were web bytes ConPot mis-decoded: raw
    # decoding never takes them for an APCI.
    ("iec104 TLS ClientHello", ics.classify_iec104, bytes.fromhex("160301020001"), "invalid", None),
    ("iec104 HTTP", ics.classify_iec104, b"GET / HTTP/1.1\r\nSec-Fetch-Mode: navigate\r\n", "invalid", None),
    ("enip RegisterSession", ics.classify_enip, enip(0x65, b"\x01\x00\x00\x00"), "handshake", None),
    ("enip ListIdentity", ics.classify_enip, enip(0x63), "interaction", "ListIdentity"),
    ("enip Set_Attribute_Single", ics.classify_enip,
     enip(0x6F, cpf_ucmm(b"\x10\x03\x20\x01\x24\x01\x30\x01\x00")), "write", "Set_Attribute_Single"),
    ("enip Unconnected_Send(Write_Tag)", ics.classify_enip,
     enip(0x6F, cpf_ucmm(b"\x52\x02\x20\x06\x24\x01\x0a\xf0" + struct.pack("<H", 4) + b"\x4d\x01\x00\x00")),
     "write", "Write_Tag"),
    ("enip Get_Attribute_Single", ics.classify_enip,
     enip(0x6F, cpf_ucmm(b"\x0e\x03\x20\x01\x24\x01\x30\x01")), "interaction", "0x0e"),
    ("bacnet WriteProperty", ics.classify_bacnet, bacnet_confirmed(15), "write", "WriteProperty"),
    ("bacnet ReinitializeDevice", ics.classify_bacnet, bacnet_confirmed(20), "write", "Reinitialize"),
    ("bacnet ReadProperty", ics.classify_bacnet, bacnet_confirmed(12), "interaction", "ReadProperty"),
    ("bacnet Who-Is", ics.classify_bacnet, b"\x81\x0b\x00\x08\x01\x00\x10\x08", "interaction", "Who-Is"),
    ("dnp3 Direct Operate", ics.classify_dnp3, dnp3_frame(4, b"\xc0\xc0\x05\x0c\x01"), "write", "Direct Operate"),
    ("dnp3 Assign Class", ics.classify_dnp3, dnp3_frame(4, b"\xc0\xc0\x16\x3c\x02\x06"), "write", "Assign Class"),
    ("dnp3 Read", ics.classify_dnp3, dnp3_frame(4, b"\xc0\xc0\x01\x3c\x02\x06"), "interaction", "Read"),
    ("dnp3 link status", ics.classify_dnp3, dnp3_frame(9), "handshake", "Request Link Status"),
    ("dnp3 operate, header CRC wrong (NEGATIVE)", ics.classify_dnp3,
     bytes.fromhex("056410c4010000040000") + b"\xc0\xc0\x05\x0c\x01", "invalid", "CRC"),
    ("dnp3 operate, data CRC wrong (NEGATIVE)", ics.classify_dnp3,
     dnp3_frame(4, b"\xc0\xc0\x05\x0c\x01")[:-2] + b"\x00\x00", "invalid", "CRC"),
    ("dnp3 operate without transport FIR (NEGATIVE)", ics.classify_dnp3,
     dnp3_frame(4, b"\x80\xc0\x05\x0c\x01"), "invalid", "FIR"),
    ("dnp3 operate, frame shorter than its length (NEGATIVE)", ics.classify_dnp3,
     dnp3_frame(4, b"\xc0\xc0\x05\x0c\x01" + b"\x00" * 20)[:30], "invalid", None),
    ("dnp3 outstation frame (NEGATIVE)", ics.classify_dnp3, dnp3_frame(4, b"\xc0\xc0\x05", prm=False),
     "invalid", "secondary"),
    ("opcua WriteRequest", ics.classify_opcua, opcua_msg(673), "write", "WriteRequest"),
    ("opcua CallRequest", ics.classify_opcua, opcua_msg(712), "write", "CallRequest"),
    ("opcua ReadRequest", ics.classify_opcua, opcua_msg(631), "interaction", "631"),
    ("opcua MSG, size larger than the bytes (NEGATIVE)", ics.classify_opcua,
     opcua_msg(673, size_delta=40), "invalid", "size"),
    ("opcua MSG, truncated below a request (NEGATIVE)", ics.classify_opcua, opcua_msg(673)[:20], "invalid", None),
    ("opcua MSG, namespace 1 (NEGATIVE)", ics.classify_opcua, opcua_msg(673, ns=1), "invalid", "namespace"),
    ("hartip write polling address", ics.classify_hartip, hartip(3, bytes([0x02, 0x80, 6, 1, 0])),
     "write", "command 6"),
    ("hartip read unique id", ics.classify_hartip, hartip(3, bytes([0x02, 0x80, 0, 0])),
     "interaction", "command 0"),
    ("hartip byte count wrong (NEGATIVE)", ics.classify_hartip,
     hartip(3, bytes([0x02, 0x80, 6, 1, 0]), count_delta=9), "invalid", None),
    ("srtp write system memory", ics.classify_srtp, bytes([0x02]) + b"\x00" * 41 + b"\x07" + b"\x00" * 13, "write", "Write System"),
    ("srtp short status", ics.classify_srtp, bytes([0x02]) + b"\x00" * 41 + b"\x00" + b"\x00" * 13, "interaction", None),
]


@pytest.mark.parametrize("label,fn,payload,tier,sub", SYNTHETIC, ids=[s[0] for s in SYNTHETIC])
def test_synthetic_frames(label, fn, payload, tier, sub):
    f = fn(payload)
    assert f.tier == tier, (label, f)
    if sub:
        assert sub in (f.function or ""), (label, f)


def test_text_protocol_writes():
    assert ics.classify_kamstrup_mgmt("!SI 192.0.2.5").tier == "write"
    assert ics.classify_kamstrup_mgmt("!RR").tier == "write"
    assert ics.classify_kamstrup_mgmt("!AC").tier == "interaction"
    assert ics.classify_kamstrup_mgmt("!AC 1 192.0.2.5").tier == "write"
    assert ics.classify_kamstrup_mgmt("GET / HTTP/1.1").tier == "invalid"
    assert ics.classify_guardian("AST S60200", None).tier == "write"
    assert ics.classify_guardian("AST I20100", None).tier == "interaction"
    # ConPot logs AST <request[1:7]> for ANY input: an SSH banner or HTTP is
    # not a set command (NEGATIVE)
    for junk in ("AST SH-2.0", "AST ET / H", "AST S6020", "AST Sabcde", "AST i2010x"):
        assert ics.classify_guardian(junk, None).tier == "invalid", junk


def test_capture_shim_forms():
    """The ops ics-full-capture shims log IEC-104 and BACnet frames as bare
    hex and ENIP as ``cmd=<n> len=<n> sctx=<hex>`` (optional ``cip=<svc>``)."""
    base = dict(_scenario("iec104_connect")[0], event_type=None)
    assert ics.classify_conpot(dict(base, conpot_request=iec_i(45).hex())).tier == "write"
    assert ics.classify_conpot(dict(base, conpot_request="68040700000")).tier in ("handshake", "invalid")
    assert ics.classify_conpot(dict(base, conpot_request="680407000000")).tier == "handshake"
    enip_doc = dict(_scenario("enip_connect")[0], event_type=None)
    for req, tier in (("cmd=99 len=0 sctx=4f495359534e4543", "interaction"),
                      ("cmd=101 len=4 sctx=00", "handshake"),
                      ("cmd=111 len=30 sctx=00 cip=16", "write"),
                      ("cmd=111 len=30 sctx=00", "interaction"),
                      ("cmd=7 len=0 sctx=", "invalid")):
        assert ics.classify_conpot(dict(enip_doc, conpot_request=req)).tier == tier, req
    bac = dict(_scenario("bacnet_connect")[0], event_type=None)
    assert ics.classify_conpot(dict(bac, conpot_request=bacnet_confirmed(15).hex())).tier == "write"


def test_snmp_set_needs_a_parsed_oid():
    d = dict(_scenario("snmp_set")[0])
    d = next(x for x in _scenario("snmp_set") if x.get("event_type") == "SNMPv2 Set")
    assert ics.classify_conpot(d).tier == "write"
    for req in ('{"val": "x"}', "not json", None):
        assert ics.classify_conpot(dict(d, conpot_request=req)).tier == "invalid", req


def test_tls_on_the_ftp_port_is_not_an_ftp_command():
    d = next(x for x in _scenario("ftp_cmd") if x.get("conpot_request"))
    assert ics.classify_conpot(d).tier == "interaction"
    assert ics.classify_conpot(dict(d, conpot_request="b'160301020001'")).tier == "invalid"
    assert ics.classify_conpot(dict(d, conpot_request="b'\\x16\\x03\\x01\\x02\\x00'")).tier == "invalid"


def test_empty_enip_sendrrdata_is_not_interaction():
    assert ics.classify_enip(enip(0x6F)).tier == "invalid"
    assert ics.classify_enip(enip(0x6F, struct.pack("<IHH", 0, 0, 0))).tier == "invalid"
    assert ics.classify_enip(enip(0x63)[:-2] + b"\x05\x00").tier in ("interaction", "invalid")
    bad = struct.pack("<HHII8sI", 0x6F, 200, 0, 0, b"\x00" * 8, 0)    # declares 200 bytes, has 0
    assert ics.classify_enip(bad).tier == "invalid"
    d = dict(_scenario("enip_connect")[0], event_type=None)
    assert ics.classify_conpot(dict(d, conpot_request="cmd=111 len=0 sctx=00")).tier == "invalid"


def test_the_structured_field_contract_wins():
    base = dict(_scenario("iec104_connect")[0])
    for d in (dict(base, ics={"write": True, "function": "C_SC_NA_1 single command"}),
              dict(base, **{"ics.write": True, "ics.function": "C_SC_NA_1 single command"}),
              dict(base, ics={"write": "true"})):
        f = ics.classify_doc(d)
        assert f.write and f.structured
    assert ics.classify_doc(dict(base, ics={"write": False})).tier == "connect"


def test_decoders_never_raise_on_garbage():
    import random
    rnd = random.Random(1)
    for fn in (ics.classify_modbus, ics.classify_s7, ics.classify_iec104, ics.classify_enip,
               ics.classify_bacnet, ics.classify_dnp3, ics.classify_opcua,
               ics.classify_hartip, ics.classify_srtp, ics.classify_kamstrup):
        for n in (0, 1, 7, 8, 24, 60, 300):
            for _ in range(30):
                fn(bytes(rnd.randrange(256) for _ in range(n)))
    for v in (None, "", "b''", "b'zz'", "b'\\x", "…", "tcp-connect-only", 5, {"a": 1}):
        ics.payload_bytes(v)


# ---------------------------------------------------------------------------
# 3. The ICS evidence class (shadow first)
# ---------------------------------------------------------------------------

CENSYS = {"vendor": "censys", "basis": "asn:398324", "list": "benign-allowlist"}
DRIFTNET = {"vendor": "driftnet", "basis": "rdns:internet-measurement.com", "list": "heuristic"}


@pytest.mark.parametrize("session,reason", [
    (lambda: _conpot_session("modbus_fc43"), evidence.REASON_ICS_INTERACTION),
    (lambda: _conpot_session("s7_szl"), evidence.REASON_ICS_INTERACTION),
    (lambda: _conpot_session("s7_scanner", research_scanner=DRIFTNET), evidence.REASON_ICS_SCANNER),
    (lambda: _conpot_session("iec104_connect"), evidence.REASON_ICS_CONNECT),
    (lambda: _conpot_session("enip_connect"), evidence.REASON_ICS_CONNECT),
    (lambda: _conpot_session("kamstrup_mgmt_http"), evidence.REASON_ICS_CONNECT),
    (lambda: _conpot_session("snmp_get"), evidence.REASON_ICS_SNMP),
    (lambda: _conpot_session("snmp_bulk"), evidence.REASON_ICS_SNMP),
    (lambda: _conpot_session("snmp_set"), evidence.REASON_ICS_WRITE),
    (lambda: _conpot_session("http_get"), evidence.REASON_STUB_ACCEPT),
    (lambda: _herald_session("dnp3:handshake"), evidence.REASON_ICS_HANDSHAKE),
    (lambda: _herald_session("dnp3:interaction"), evidence.REASON_ICS_INTERACTION),
    (lambda: _herald_session("opcua:connect"), evidence.REASON_ICS_CONNECT),
    (lambda: _herald_session("ge-srtp:handshake"), evidence.REASON_ICS_HANDSHAKE),
], ids=["modbus-id-read", "s7-szl", "s7-scanner", "iec104-connect", "enip-connect",
        "kamstrup-http", "snmp-get", "snmp-bulk", "snmp-set", "http", "dnp3-link",
        "dnp3-fc23", "opcua-connect", "srtp-init"])
def test_ics_decisions(session, reason):
    d = evidence.decide(session(), site="driveby")
    assert d.reason == reason
    # decision 2026-09-30: only a write/control command mints an Indicator
    assert d.accept is (reason in (evidence.REASON_ICS_WRITE, evidence.REASON_STUB_ACCEPT))


def test_a_scanner_that_writes_is_still_write_evidence():
    s = _conpot_session("snmp_set", research_scanner=DRIFTNET)
    assert evidence.decide(s, site="driveby").reason == evidence.REASON_ICS_WRITE


def test_s7_handshake_alone_is_refused():
    p = ConPotParser()
    docs = [d for d in _routable(_scenario("s7_szl"))
            if "0300001611e0" in (d.get("conpot_request") or "") or d.get("event_type")]
    (s,) = p.correlate([p.parse(d) for d in docs])
    assert s.meta["ics"]["tier"] == "handshake"
    assert evidence.decide(s, site="driveby").reason == evidence.REASON_ICS_HANDSHAKE


def test_ics_reasons_are_bounded_counter_keys():
    for r in (evidence.REASON_ICS_WRITE, evidence.REASON_ICS_INTERACTION, evidence.REASON_ICS_SCANNER,
              evidence.REASON_ICS_HANDSHAKE, evidence.REASON_ICS_CONNECT, evidence.REASON_ICS_SNMP):
        assert r.isascii() and " " not in r and len(r) <= 32


# ---------------------------------------------------------------------------
# 4. Through the builder: labels, score, refusals
# ---------------------------------------------------------------------------

def _build(env, sessions, method="build_conpot_session"):
    b = H._fixed_builder(H.make_cfg(env))
    objs = []
    for s in sessions:
        with b.session_context(s):
            objs.extend(getattr(b, method)(s))
    return b.finalize_bundle(objs), b


def _by_id(objs, oid):
    return next((o for o in objs if o.get("id") == oid), None)


def test_labels_follow_v1_spellings_and_valid_requests_only():
    s = _conpot_session("modbus_fc43")
    objs, _ = _build({}, [s])
    obs = _by_id(objs, attacker_ip_observable_id(s.src_ip))
    ind = _by_id(objs, attacker_ip_indicator_id(s.src_ip))
    for labels in (obs["x_opencti_labels"], ind["labels"]):
        assert {"targeting:ics", "ics:modbus", "ics:protocol-interaction", "conpot"} <= set(labels)
        assert "ics:write-control" not in labels
    assert "ICS depth: interaction" in obs["x_opencti_description"]
    # a port touch gets targeting:ics but no protocol label
    assert "ics" in obs["x_opencti_labels"] and "ics" in ind["labels"]
    s2 = _conpot_session("enip_connect")
    objs2, _ = _build({}, [s2])
    labels2 = _by_id(objs2, attacker_ip_observable_id(s2.src_ip))["x_opencti_labels"]
    assert "targeting:ics" in labels2 and "ics:ethernet-ip" not in labels2
    # HTTP / FTP on the emulator is not ICS targeting
    for name in ("http_get", "ftp_cmd"):
        s3 = _conpot_session(name)
        objs3, _ = _build({}, [s3])
        labels3 = _by_id(objs3, attacker_ip_observable_id(s3.src_ip))["x_opencti_labels"]
        assert "targeting:ics" not in labels3 and "ics" not in labels3, name


def test_one_address_on_two_industrial_protocols_gets_the_union_and_multi_protocol():
    a = _conpot_session("modbus_fc43")
    b_ = _conpot_session("s7_szl")
    b_.src_ip = a.src_ip
    for e in b_.events:
        e.src_ip = a.src_ip
    objs, _ = _build({}, [a, b_])
    for oid, key in ((attacker_ip_observable_id(a.src_ip), "x_opencti_labels"),
                     (attacker_ip_indicator_id(a.src_ip), "labels")):
        labels = set(_by_id(objs, oid)[key])
        assert {"ics:modbus", "ics:s7", "ics:multi-protocol", "ics", "targeting:ics"} <= labels
    single, _ = _build({}, [_conpot_session("modbus_fc43")])
    assert "ics:multi-protocol" not in _by_id(single, attacker_ip_observable_id(a.src_ip))["x_opencti_labels"]


def test_a_write_scores_higher_and_says_so():
    s = _conpot_session("snmp_set")
    objs, _ = _build({}, [s])
    ind = _by_id(objs, attacker_ip_indicator_id(s.src_ip))
    assert {"ics:write-control", "ics:snmp"} <= set(ind["labels"])
    assert "ICS write/control: SNMP set" in ind["description"]
    plain = _conpot_session("snmp_set")
    plain.meta["ics"] = dict(plain.meta["ics"], write=False, tier="interaction")
    objs_p, _ = _build({REFUSALS: "false"}, [plain])
    ind_p = _by_id(objs_p, attacker_ip_indicator_id(plain.src_ip))
    assert ind["x_opencti_score"] == min(100, ind_p["x_opencti_score"] + 30)


@pytest.mark.parametrize("gate", ["off", "shadow", "enforce"])
def test_snmp_only_mints_no_indicator_in_any_gate_mode(gate):
    s = _conpot_session("snmp_get")
    objs, b = _build({GATE: gate, DECOUPLED: "true"}, [s])
    assert _by_id(objs, attacker_ip_indicator_id(s.src_ip)) is None
    assert _by_id(objs, attacker_ip_observable_id(s.src_ip)) is not None
    assert attacker_ip_observable_id(s.src_ip) in {
        o["sighting_of_ref"] for o in objs if o.get("type") == "sighting"}
    assert b.ics_refused == {"ics-snmp-only": 1}
    withheld = attacker_ip_indicator_id(s.src_ip)
    assert not [o for o in objs if withheld in json.dumps(o)]


def test_the_refusal_switch_restores_the_indicator():
    s = _conpot_session("snmp_get")
    objs, b = _build({REFUSALS: "false"}, [s])
    assert _by_id(objs, attacker_ip_indicator_id(s.src_ip)) is not None
    assert b.ics_refused == {}


def test_allowlisted_scanner_is_labelled_never_an_indicator():
    s = _conpot_session("s7_scanner", research_scanner=CENSYS)
    objs, b = _build({GATE: "shadow", DECOUPLED: "true"}, [s])
    assert _by_id(objs, attacker_ip_indicator_id(s.src_ip)) is None
    obs = _by_id(objs, attacker_ip_observable_id(s.src_ip))
    assert {"scanner:research", "scanner:censys", "ics:s7"} <= set(obs["x_opencti_labels"])
    assert "Research scanner: censys (basis asn:398324" in obs["x_opencti_description"]
    assert b.ics_refused == {"ics-research-scanner-allowlisted": 1}


def test_heuristic_scanner_is_shadow_first():
    s = _conpot_session("s7_scanner", research_scanner=DRIFTNET)
    objs, b = _build({GATE: "shadow", DECOUPLED: "true"}, [s])
    assert _by_id(objs, attacker_ip_indicator_id(s.src_ip)) is not None
    assert b.gate_stats.refused == {evidence.REASON_ICS_SCANNER: 1}
    objs_e, b_e = _build({GATE: "enforce", DECOUPLED: "true"},
                         [_conpot_session("s7_scanner", research_scanner=DRIFTNET)])
    assert _by_id(objs_e, attacker_ip_indicator_id(s.src_ip)) is None
    assert b_e.gate_stats.indicators_withheld == 1


def test_shadow_output_equals_off_for_ics_sessions():
    names = ["modbus_fc43", "s7_szl", "iec104_connect", "snmp_set", "http_get"]
    off, _ = _build({DECOUPLED: "true"}, [_conpot_session(n) for n in names])
    shadow, b = _build({GATE: "shadow", DECOUPLED: "true"}, [_conpot_session(n) for n in names])
    assert H.serialize(off) == H.serialize(shadow)
    assert b.gate_stats.accepted == {evidence.REASON_ICS_WRITE: 1, evidence.REASON_STUB_ACCEPT: 1}
    assert b.gate_stats.refused == {evidence.REASON_ICS_INTERACTION: 2, evidence.REASON_ICS_CONNECT: 1}


def test_enforce_mints_only_the_write_and_keeps_the_rest_as_observables():
    names = ["modbus_fc43", "s7_szl", "iec104_connect", "snmp_set"]
    sessions = [_conpot_session(n) for n in names]
    for i, s in enumerate(sessions):           # one address each
        s.src_ip = f"45.32.0.{i + 1}"
        for e in s.events:
            e.src_ip = s.src_ip
    objs, b = _build({GATE: "enforce", DECOUPLED: "true"}, sessions)
    ind = {o["id"] for o in objs if o.get("type") == "indicator"}
    sighted = {o["sighting_of_ref"] for o in objs if o.get("type") == "sighting"}
    for s in sessions:
        has = attacker_ip_indicator_id(s.src_ip) in ind
        assert has is bool(s.meta["ics"]["write"]), s.meta["ics"]["functions"]
        assert _by_id(objs, attacker_ip_observable_id(s.src_ip)) is not None
        assert attacker_ip_observable_id(s.src_ip) in sighted


def test_emulator_rows_are_ics_not_credentials():
    s = _herald_session("opcua:handshake")
    assert s.credentials_tried == [] and s.protocols == {"opcua"}
    assert s.protocol_requests and s.protocol_requests[0].startswith("48454c")
    objs, _ = _build({}, [s], method="build_heralding_session")
    ind = _by_id(objs, attacker_ip_indicator_id(s.src_ip))
    assert ind["name"].startswith("ICS Emulator Probe - ")
    assert "credential-capture" not in ind["labels"]
    assert {"ics-scada", "heralding", "targeting:ics", "ics:opc-ua"} <= set(ind["labels"])
    assert any(o.get("type") == "attack-pattern" and o["name"] == "ICS/SCADA protocol interaction"
               for o in objs)


def test_real_heralding_credentials_are_untouched():
    d = {"@timestamp": "2026-09-01T00:00:00Z", "type": "Heralding", "src_ip": "198.51.100.3",
         "proto": "ftp", "username": "admin", "password": "admin", "session_id": "1"}
    p = HeraldingParser()
    (s,) = p.correlate([p.parse(d)])
    assert s.credentials_tried == [("admin", "admin")] and "ics" not in s.meta


# ---------------------------------------------------------------------------
# 5. A whole cycle: reflection drop, research scanners kept, counters
# ---------------------------------------------------------------------------

def _cycle(env=None):
    docs = _routable(CONPOT + HERALD)
    cfg = H.make_cfg(env or {})
    with tempfile.TemporaryDirectory() as td:
        state = CycleState(db_path=Path(td) / "state.db")
        pub = H.CapturingPublisher()
        summary = run_cycle(cfg, state, H.FakeES(docs, {}), lambda: H._fixed_builder(cfg), pub,
                            now=H.FIXED_NOW, benign_filter=BenignScannerFilter.from_yaml())
        kv = state.get("last_cycle_ics")
    ip = {d["scenario"]: d["src_ip"] for d in docs}
    return pub.objects, summary, json.loads(kv), ip


def test_cycle_drops_the_reflection_shape_and_keeps_scanners():
    objs, summary, kv, ip = _cycle({GATE: "shadow", DECOUPLED: "true"})
    ids = {o["id"] for o in objs}
    text = json.dumps(objs)
    # the GetBulk-only source: nothing at all
    assert ip["snmp_bulk"] not in text
    assert summary["ics"]["snmp_reflection_dropped"]["sessions"] == 1
    assert summary["ics"]["snmp_reflection_dropped"]["events"] == 4
    # SNMP Get: observable, no indicator
    assert attacker_ip_observable_id(ip["snmp_get"]) in ids
    assert attacker_ip_indicator_id(ip["snmp_get"]) not in ids
    # the Censys S7 source is on the benign allowlist: kept, labelled, no indicator
    obs = _by_id(objs, attacker_ip_observable_id(ip["s7_scanner"]))
    assert obs is not None and "scanner:censys" in obs["x_opencti_labels"]
    assert attacker_ip_indicator_id(ip["s7_scanner"]) not in ids
    assert summary["ics"]["research_scanner_events"].get("benign-allowlist", 0) >= 6
    # the SNMP Set is the one write
    assert summary["ics"]["write_sessions_total"] == 1
    assert summary["ics"]["write_sessions"][0]["functions"] == ["SNMP set 1.3.6.1.2.1.1.1.0"]
    assert attacker_ip_indicator_id(ip["snmp_set"]) in ids
    assert kv == json.loads(json.dumps(summary["ics"], default=str))
    assert summary["ics"]["indicator_refused"].get("ics-snmp-only", 0) >= 2


def test_cycle_with_refusals_off_is_the_old_behaviour():
    objs, summary, _, ip = _cycle({REFUSALS: "false"})
    ids = {o["id"] for o in objs}
    assert attacker_ip_indicator_id(ip["snmp_bulk"]) in ids
    assert attacker_ip_indicator_id(ip["snmp_get"]) in ids
    assert ip["s7_scanner"] not in json.dumps(objs), "allowlisted scanners dropped as before"
    assert summary["ics"]["snmp_reflection_dropped"]["sessions"] == 0
    assert summary["drop_reasons"]["benign_scanner"] > 0


def test_health_reports_ics(tmp_path):
    from tpot2cti.health import HealthStatus
    state = CycleState(db_path=tmp_path / "s.db")
    state.set("last_cycle_ics", json.dumps({"write_sessions_total": 1}))
    hs = HealthStatus.__new__(HealthStatus)
    hs._state = state
    assert hs._ics() == {"last_cycle": {"write_sessions_total": 1}}


# ---------------------------------------------------------------------------
# 6. The DR-02 rebaseline is scoped to ConPot
# ---------------------------------------------------------------------------

def test_rebaseline_is_recorded_not_overwritten():
    g = H.golden_original()
    assert g["generated_from"].startswith("origin/main 71e47ec")
    rb = g["rebaselines"][-1]
    assert "ConPot" in rb["reason"] and rb["unchanged_without"] == ["conpot.jsonl"]
    assert H.golden()["cycle"] == rb["cycle"] != g["cycle"]
    assert H.golden()["direct"] == g["direct"], "the direct bundle has no ConPot and must not move"


def test_everything_but_conpot_is_byte_identical_to_the_parent_commit(tmp_path):
    rb = H.golden_original()["rebaselines"][-1]
    objs, *_ = H.cycle_bundle(tmp_path, exclude=tuple(rb["unchanged_without"]))
    assert H.digest(objs) == rb["cycle_without"]
