"""ICS/OT request classification: what did an industrial-protocol session DO?

Pure functions, standard library only (no tpot2cti imports), so the same file
can be vendored by an out-of-process alert watcher and must stay importable on
a bare Python 3.

Three questions, asked of every ConPot document and every ICS row from the
companion emulators that log as ``Heralding`` (DNP3, OPC UA, HART-IP, GE-SRTP):

  1. **Which protocol?** ConPot names it in ``data_type`` (``modbus``,
     ``s7comm``, ``IEC104`` ...). ``event_type`` is the lifecycle or
     operation (``NEW_CONNECTION``, ``SNMPv2 Bulk``) or null for a data
     document, never the protocol.
  2. **How deep?** One of five tiers, lowest to highest:

        connect      a connection event, or no request at all
        invalid      bytes arrived, but they are not this protocol
                     (HTTP/TLS on an industrial port, a truncated frame)
        handshake    a valid frame that only opens or keeps a session:
                     S7 COTP connect / Setup Communication, IEC-104
                     STARTDT/TESTFR/S-frames, OPC UA HEL/OPN, ENIP
                     RegisterSession, DNP3 link-layer only, HART-IP session
                     initiate, the GE-SRTP 56-byte init
        interaction  a valid request beyond the handshake (identity reads,
                     register reads, SZL reads, general interrogation ...)
        write        a write or control function (see WRITE_* below)

  3. **Write or control?** The tables below. They follow the ICS/OT review of
     2026-09-30 (Modbus FC 5/6/15/16/21/22/23, S7 0x05/0x1A-0x1F/0x28/0x29,
     IEC-104 actuation and parameter ASDUs with a valid APCI, SNMP Set,
     BACnet write/control services, CIP Set-Attribute*/Write-Tag, DNP3
     write/operate/restart) plus the equivalents for the other protocols.

Decoders never raise: anything unparseable is ``invalid`` (bytes present) or
``connect`` (nothing present). Validity is decided from the bytes, never from
the port.

A deployment may also ship pre-decoded fields. A document carrying
``ics.write: true`` (nested ``{"ics": {"write": true}}`` or the dotted key) is
a write whatever its payload says; ``ics.function`` and ``ics.protocol`` are
used when present. That is the field contract with the log-shipping side.
"""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from typing import Iterable, Optional

# ---------------------------------------------------------------------------
# Protocols and labels
# ---------------------------------------------------------------------------

#: ConPot ``data_type`` -> canonical protocol token.
_CONPOT_PROTOCOLS = {
    "modbus": "modbus",
    "s7comm": "s7comm",
    "iec104": "iec104",
    "enip": "enip",
    "bacnet": "bacnet",
    "snmp": "snmp",
    "ipmi": "ipmi",
    "http": "http",
    "ftp": "ftp",
    "tftp": "tftp",
    "kamstrup_protocol": "kamstrup",
    "kamstrup_meter": "kamstrup",
    "kamstrup_management_protocol": "kamstrup-management",
    "guardian_ast": "guardian_ast",
}

#: Heralding ``proto`` values that are ICS emulators, not credential services.
FAKE_ICS_PROTOCOLS = {
    "dnp3": "dnp3",
    "opcua": "opcua",
    "opc-ua": "opcua",
    "hartip": "hartip",
    "hart-ip": "hartip",
    "ge-srtp": "ge-srtp",
    "srtp": "ge-srtp",
}

#: Canonical protocol -> the OpenCTI label v1 used for it. Spellings match
#: the v1 ``ics:*`` labels so dashboards survive the v1 -> v2 cutover
#: (``ics:ethernet-ip``, not ``ics:enip``). ``ics:snmp`` and ``ics:kamstrup``
#: are new: v1 had no label for them.
PROTOCOL_LABELS = {
    "modbus": "ics:modbus",
    "s7comm": "ics:s7",
    "iec104": "ics:iec104",
    "enip": "ics:ethernet-ip",
    "bacnet": "ics:bacnet",
    "dnp3": "ics:dnp3",
    "opcua": "ics:opc-ua",
    "hartip": "ics:hart-ip",
    "ge-srtp": "ics:ge-srtp",
    "guardian_ast": "ics:veeder-root",
    "kamstrup": "ics:kamstrup",
    "kamstrup-management": "ics:kamstrup",
    "snmp": "ics:snmp",
}

#: Industrial protocols: only these count toward the ICS evidence class.
#: SNMP, HTTP, FTP and IPMI ride on the same emulators but are generic IT
#: services.
INDUSTRIAL = frozenset({
    "modbus", "s7comm", "iec104", "enip", "bacnet", "dnp3", "opcua",
    "hartip", "ge-srtp", "guardian_ast", "kamstrup", "kamstrup-management",
})

LABEL_TARGETING = "targeting:ics"
LABEL_INTERACTION = "ics:protocol-interaction"
LABEL_WRITE = "ics:write-control"
LABEL_SCANNER = "scanner:research"

TIERS = ("connect", "invalid", "handshake", "interaction", "write")
_RANK = {t: i for i, t in enumerate(TIERS)}

#: ConPot lifecycle event types (no request content).
LIFECYCLE = frozenset({
    "NEW_CONNECTION", "CONNECTION_LOST", "CONNECTION_CLOSED",
    "CONNECTION_TERMINATED", "CONNECTION_TIMEOUT", "CONNECTION_FAILED",
})


def conpot_protocol(doc: dict) -> Optional[str]:
    """The canonical protocol of a ConPot document, from ``data_type``.

    Falls back to the historical ``protocol``/``app`` fields. ``event_type``
    is used only when it is itself a known protocol token (older builds),
    never a lifecycle name like ``NEW_CONNECTION``.
    """
    for key in ("data_type", "protocol", "app"):
        v = doc.get(key)
        if v:
            v = str(v).strip().lower()
            return _CONPOT_PROTOCOLS.get(v, v)
    ev = str(doc.get("event_type") or "").strip().lower()
    return _CONPOT_PROTOCOLS.get(ev)


def fake_protocol(proto) -> Optional[str]:
    """Canonical protocol for a Heralding ``proto`` value, if it is an ICS
    emulator; None for every real Heralding credential service."""
    if not proto:
        return None
    return FAKE_ICS_PROTOCOLS.get(str(proto).strip().lower())


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    """What one document shows. ``function`` is a short human label."""
    protocol: Optional[str]
    tier: str
    function: Optional[str] = None
    #: True when the request came from pre-decoded ``ics.*`` fields.
    structured: bool = False

    @property
    def write(self) -> bool:
        return self.tier == "write"

    @property
    def valid(self) -> bool:
        return _RANK[self.tier] >= _RANK["handshake"]

    def to_dict(self) -> dict:
        """JSON-safe form (what parsers put in ``event.meta``)."""
        return {"protocol": self.protocol, "tier": self.tier,
                "function": self.function, "structured": self.structured}

    @classmethod
    def coerce(cls, v) -> Optional["Finding"]:
        """A Finding from a Finding or its :meth:`to_dict` form."""
        if v is None or isinstance(v, Finding):
            return v
        if isinstance(v, dict) and v.get("tier") in _RANK:
            return cls(v.get("protocol"), v["tier"], v.get("function"),
                       bool(v.get("structured")))
        return None


def _f(protocol, tier, function=None, structured=False) -> Finding:
    return Finding(protocol, tier, function, structured)


# ---------------------------------------------------------------------------
# Payload helpers
# ---------------------------------------------------------------------------

_HEX_BYTES_RE = re.compile(r"^b'([0-9a-fA-F]*)'$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def payload_bytes(value) -> Optional[bytes]:
    """Raw bytes from the forms ConPot and the emulators log.

    * ``b'0300001611e0...'``  hex inside a bytes repr (Modbus, S7, Kamstrup)
    * ``b'\\x06\\x00\\xff...'`` a Python bytes literal (IPMI, FTP)
    * ``0564...`` / ``0564...…``  bare hex, possibly cut with an ellipsis
      (the emulators keep the first 120 bytes)

    None when there is nothing, or nothing decodable.
    """
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    s = str(value).strip()
    if not s:
        return None
    m = _HEX_BYTES_RE.match(s)
    if m:
        h = m.group(1)
        if len(h) % 2 == 0:
            try:
                return bytes.fromhex(h)
            except ValueError:
                return None
    if s.startswith(("b'", 'b"')) and len(s) < 200_000:
        try:
            v = ast.literal_eval(s)
            if isinstance(v, bytes):
                return v
        except (ValueError, SyntaxError, MemoryError, RecursionError):
            pass
        return None
    s = s.rstrip("…").rstrip(".")
    if _HEX_RE.match(s):
        if len(s) % 2:
            s = s[:-1]
        try:
            return bytes.fromhex(s)
        except ValueError:
            return None
    return None


def _u16be(b: bytes, i: int) -> int:
    return int.from_bytes(b[i:i + 2], "big")


def _u16le(b: bytes, i: int) -> int:
    return int.from_bytes(b[i:i + 2], "little")


# ---------------------------------------------------------------------------
# Modbus/TCP
# ---------------------------------------------------------------------------

MODBUS_FC = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
    4: "Read Input Registers", 5: "Write Single Coil", 6: "Write Single Register",
    7: "Read Exception Status", 8: "Diagnostics", 11: "Get Comm Event Counter",
    12: "Get Comm Event Log", 15: "Write Multiple Coils",
    16: "Write Multiple Registers", 17: "Report Server ID",
    20: "Read File Record", 21: "Write File Record", 22: "Mask Write Register",
    23: "Read/Write Multiple Registers", 24: "Read FIFO Queue",
    43: "Encapsulated Interface Transport", 90: "Schneider UMAS",
}
WRITE_MODBUS_FC = frozenset({5, 6, 15, 16, 21, 22, 23})
#: FC 8 sub-functions that change device state: Restart Communications,
#: Force Listen Only Mode, Clear Counters and Diagnostic Register.
CONTROL_MODBUS_DIAG = frozenset({0x01, 0x04, 0x0A})
#: Schneider UMAS (FC 0x5A) function codes that write or change PLC state,
#: from public protocol analyses: write variables / coils-registers,
#: download sequence, start and stop PLC.
WRITE_UMAS = frozenset({0x23, 0x25, 0x33, 0x34, 0x35, 0x40, 0x41})


def classify_modbus(b: bytes) -> Finding:
    best = None
    i = 0
    while i + 8 <= len(b):
        pid = _u16be(b, i + 2)
        ln = _u16be(b, i + 4)
        unit, fc = b[i + 6], b[i + 7]
        if pid != 0 or not (2 <= ln <= 254) or i + 6 + ln > len(b) \
                or fc == 0 or fc >= 0x80:
            break
        pdu = b[i + 8:i + 6 + ln]
        name = f"FC{fc} {MODBUS_FC.get(fc, 'function %d' % fc)}"
        tier = "interaction"
        if fc in WRITE_MODBUS_FC:
            tier = "write"
        elif fc == 8 and len(pdu) >= 2 and _u16be(pdu, 0) in CONTROL_MODBUS_DIAG:
            tier = "write"
            name = f"FC8 Diagnostics sub {_u16be(pdu, 0)}"
        elif fc == 90 and len(pdu) >= 2:
            name = f"FC90 UMAS 0x{pdu[1]:02x}"
            if pdu[1] in WRITE_UMAS:
                tier = "write"
        f = _f("modbus", tier, f"{name} unit {unit}")
        if best is None or _RANK[f.tier] > _RANK[best.tier]:
            best = f
        i += 6 + ln
    return best or _f("modbus", "invalid", "not Modbus/TCP framed")


# ---------------------------------------------------------------------------
# S7comm (TPKT / COTP / S7)
# ---------------------------------------------------------------------------

S7_JOB = {
    0x00: "CPU services", 0x04: "Read Var", 0x05: "Write Var",
    0x1A: "Request Download", 0x1B: "Download Block", 0x1C: "Download Ended",
    0x1D: "Start Upload", 0x1E: "Upload", 0x1F: "End Upload",
    0x28: "PI Service", 0x29: "PLC Stop", 0xF0: "Setup Communication",
}
WRITE_S7_JOB = frozenset({0x05, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28, 0x29})
S7_UD_GROUP = {1: "Programmer commands", 2: "Cyclic data", 3: "Block functions",
               4: "CPU functions", 5: "Security", 6: "PBC", 7: "Time functions"}


def classify_s7(b: bytes) -> Finding:
    if len(b) < 7 or b[0] != 0x03:
        return _f("s7comm", "invalid", "not TPKT")
    cotp_len = b[4]
    pdu_type = b[5] & 0xF0
    if pdu_type == 0xE0:
        return _f("s7comm", "handshake", "COTP Connect Request")
    if pdu_type != 0xF0:
        return _f("s7comm", "invalid", f"COTP type 0x{pdu_type:02x}")
    s = b[5 + cotp_len:]
    if not s:
        return _f("s7comm", "handshake", "COTP DT empty")
    if s[0] == 0x72:
        return _f("s7comm", "interaction", "S7comm-plus PDU")
    if s[0] != 0x32 or len(s) < 10:
        return _f("s7comm", "invalid", "COTP DT non-S7")
    rosctr = s[1]
    plen = _u16be(s, 6)
    hdr = 10 if rosctr in (1, 7) else 12
    par = s[hdr:hdr + plen]
    if rosctr == 1 and par:
        fn = par[0]
        name = S7_JOB.get(fn, f"job 0x{fn:02x}")
        if fn == 0xF0:
            return _f("s7comm", "handshake", "Setup Communication")
        if fn in WRITE_S7_JOB:
            return _f("s7comm", "write", name)
        return _f("s7comm", "interaction", name)
    if rosctr == 7 and len(par) >= 8:
        grp = par[5] & 0x0F
        sub = par[6]
        name = f"Userdata {S7_UD_GROUP.get(grp, grp)} sub {sub}"
        data = s[hdr + plen:]
        if grp == 4 and sub == 1 and len(data) >= 8:
            name = f"SZL read 0x{_u16be(data, 4):04x}"
        return _f("s7comm", "interaction", name)
    return _f("s7comm", "invalid", f"S7 rosctr {rosctr}")


# ---------------------------------------------------------------------------
# IEC 60870-5-104
# ---------------------------------------------------------------------------

#: Command ASDUs that act on the process: single/double/regulating step,
#: set-points, bitstring (45-51) and their time-tagged forms (58-64); reset
#: process (105); parameter loading and activation (110-113).
WRITE_IEC104 = frozenset(set(range(45, 52)) | set(range(58, 65)) | {105, 110, 111, 112, 113})
IEC104_NAMES = {45: "C_SC_NA_1 single command", 46: "C_DC_NA_1 double command",
                47: "C_RC_NA_1 regulating step", 48: "C_SE_NA_1 set-point",
                49: "C_SE_NB_1 set-point", 50: "C_SE_NC_1 set-point",
                51: "C_BO_NA_1 bitstring", 100: "C_IC_NA_1 interrogation",
                101: "C_CI_NA_1 counter interrogation", 102: "C_RD_NA_1 read",
                103: "C_CS_NA_1 clock sync", 105: "C_RP_NA_1 reset process"}
_IEC_U = {0x07: "STARTDT act", 0x13: "STOPDT act", 0x43: "TESTFR act",
          0x0B: "STARTDT con", 0x23: "STOPDT con", 0x83: "TESTFR con"}


def classify_iec104(b: bytes) -> Finding:
    best = None
    i = 0
    while i + 6 <= len(b) and b[i] == 0x68:
        ln = b[i + 1]
        apdu = b[i + 2:i + 2 + ln]
        if ln < 4 or len(apdu) < ln:
            break
        c1 = apdu[0]
        if c1 & 0x01 == 0:                         # I-format
            asdu = apdu[4:]
            if len(asdu) < 6:
                f = _f("iec104", "invalid", "short ASDU")
            else:
                tid, cot = asdu[0], asdu[2] & 0x3F
                name = IEC104_NAMES.get(tid, f"type {tid}")
                if tid in WRITE_IEC104 and cot in (6, 8):   # activation / deactivation
                    f = _f("iec104", "write", f"{name} cot {cot}")
                elif 1 <= tid <= 127:
                    f = _f("iec104", "interaction", f"{name} cot {cot}")
                else:
                    f = _f("iec104", "invalid", f"type {tid}")
        elif c1 & 0x03 == 0x01:                    # S-format
            f = _f("iec104", "handshake", "S-frame")
        else:                                      # U-format
            f = _f("iec104", "handshake", _IEC_U.get(c1, f"U 0x{c1:02x}"))
        if best is None or _RANK[f.tier] > _RANK[best.tier]:
            best = f
        i += 2 + ln
    return best or _f("iec104", "invalid", "no APCI start 0x68")


# ---------------------------------------------------------------------------
# EtherNet/IP + CIP
# ---------------------------------------------------------------------------

ENIP_CMD = {0x0000: "NOP", 0x0004: "ListServices", 0x0063: "ListIdentity",
            0x0064: "ListInterfaces", 0x0065: "RegisterSession",
            0x0066: "UnRegisterSession", 0x006F: "SendRRData", 0x0070: "SendUnitData"}
#: CIP services that write or change state.
WRITE_CIP = {0x02: "Set_Attributes_All", 0x04: "Set_Attribute_List",
             0x05: "Reset", 0x06: "Start", 0x07: "Stop", 0x08: "Create",
             0x09: "Delete", 0x10: "Set_Attribute_Single", 0x4D: "Write_Tag",
             0x4E: "Read_Modify_Write_Tag", 0x53: "Write_Tag_Fragmented"}


def _cip_service(msg: bytes) -> Optional[int]:
    if len(msg) < 2:
        return None
    svc = msg[0] & 0x7F
    path_end = 2 + 2 * msg[1]
    if svc == 0x52 and len(msg) >= path_end + 5:          # Unconnected_Send
        size = _u16le(msg, path_end + 2)
        inner = msg[path_end + 4:path_end + 4 + size]
        if inner:
            return inner[0] & 0x7F
    return svc


def classify_enip(b: bytes) -> Finding:
    if len(b) < 24:
        return _f("enip", "invalid", "short encapsulation header")
    cmd = _u16le(b, 0)
    name = ENIP_CMD.get(cmd)
    if name is None:
        return _f("enip", "invalid", f"command 0x{cmd:04x}")
    if cmd in (0x0000, 0x0065, 0x0066):
        return _f("enip", "handshake", name)
    if cmd in (0x0004, 0x0063, 0x0064):
        return _f("enip", "interaction", name)
    data = b[24:24 + _u16le(b, 2)]
    if len(data) >= 8:
        count = _u16le(data, 6)
        j = 8
        for _ in range(min(count, 8)):
            if j + 4 > len(data):
                break
            itype, ilen = _u16le(data, j), _u16le(data, j + 2)
            item = data[j + 4:j + 4 + ilen]
            if itype in (0x00B2, 0x00B1):
                msg = item[2:] if itype == 0x00B1 else item
                svc = _cip_service(msg)
                if svc is not None:
                    if svc in WRITE_CIP:
                        return _f("enip", "write", f"{name} CIP {WRITE_CIP[svc]}")
                    return _f("enip", "interaction", f"{name} CIP 0x{svc:02x}")
            j += 4 + ilen
    return _f("enip", "interaction", name)


_ENIP_TEXT = re.compile(r"cmd=(0x[0-9a-fA-F]+|\d+)")
_ENIP_CIP_HINT = re.compile(r"cip=(0x[0-9a-fA-F]+|\d+)")


def classify_enip_text(text: str) -> Finding:
    """The capture shim's text form, ``cmd=<n> len=<n> sctx=<hex>`` with an
    optional ``cip=<service>`` hint (ops ics-full-capture field contract):
    ConPot's ENIP server parses the frame, and the shim logs what it parsed."""
    m = _ENIP_TEXT.search(text or "")
    if not m:
        return _f("enip", "invalid", "no ENIP command")
    cmd = int(m.group(1), 0)
    name = ENIP_CMD.get(cmd)
    if name is None:
        return _f("enip", "invalid", f"command 0x{cmd:04x}")
    if cmd in (0x0000, 0x0065, 0x0066):
        return _f("enip", "handshake", name)
    h = _ENIP_CIP_HINT.search(text)
    if h:
        svc = int(h.group(1), 0) & 0x7F
        if svc in WRITE_CIP:
            return _f("enip", "write", f"{name} CIP {WRITE_CIP[svc]}")
        return _f("enip", "interaction", f"{name} CIP 0x{svc:02x}")
    return _f("enip", "interaction", name)


# ---------------------------------------------------------------------------
# BACnet/IP
# ---------------------------------------------------------------------------

BACNET_CONFIRMED = {12: "ReadProperty", 14: "ReadPropertyMultiple",
                    15: "WriteProperty", 16: "WritePropertyMultiple",
                    7: "AtomicWriteFile", 6: "AtomicReadFile",
                    8: "AddListElement", 9: "RemoveListElement",
                    10: "CreateObject", 11: "DeleteObject",
                    17: "DeviceCommunicationControl", 20: "ReinitializeDevice",
                    27: "LifeSafetyOperation"}
WRITE_BACNET_CONFIRMED = frozenset({7, 8, 9, 10, 11, 15, 16, 17, 20, 27})
BACNET_UNCONFIRMED = {0: "I-Am", 1: "I-Have", 6: "TimeSynchronization",
                      7: "Who-Has", 8: "Who-Is", 9: "UTCTimeSynchronization",
                      10: "WriteGroup"}
WRITE_BACNET_UNCONFIRMED = frozenset({10})


def classify_bacnet(b: bytes) -> Finding:
    if len(b) < 6 or b[0] != 0x81:
        return _f("bacnet", "invalid", "no BVLC")
    npdu = b[10:] if b[1] == 0x04 else b[4:]
    if len(npdu) < 2 or npdu[0] != 0x01:
        return _f("bacnet", "invalid", "bad NPDU version")
    ctrl = npdu[1]
    j = 2
    try:
        if ctrl & 0x20:
            j += 3 + npdu[j + 2]
        if ctrl & 0x08:
            j += 3 + npdu[j + 2]
        if ctrl & 0x20:
            j += 1
    except IndexError:
        return _f("bacnet", "invalid", "short NPDU")
    if ctrl & 0x80:
        return _f("bacnet", "interaction", "network layer message")
    apdu = npdu[j:]
    if not apdu:
        return _f("bacnet", "invalid", "no APDU")
    ptype = apdu[0] >> 4
    if ptype == 0:
        k = 5 if apdu[0] & 0x08 else 3
        if len(apdu) <= k:
            return _f("bacnet", "invalid", "short confirmed request")
        svc = apdu[k]
        name = BACNET_CONFIRMED.get(svc, f"confirmed service {svc}")
        return _f("bacnet", "write" if svc in WRITE_BACNET_CONFIRMED else "interaction", name)
    if ptype == 1:
        if len(apdu) < 2:
            return _f("bacnet", "invalid", "short unconfirmed request")
        svc = apdu[1]
        name = BACNET_UNCONFIRMED.get(svc, f"unconfirmed service {svc}")
        return _f("bacnet", "write" if svc in WRITE_BACNET_UNCONFIRMED else "interaction", name)
    return _f("bacnet", "invalid", f"APDU type {ptype} from a client")


# ---------------------------------------------------------------------------
# DNP3 (link frame 0x0564)
# ---------------------------------------------------------------------------

DNP3_APP_FC = {0: "Confirm", 1: "Read", 2: "Write", 3: "Select", 4: "Operate",
               5: "Direct Operate", 6: "Direct Operate No Ack",
               13: "Cold Restart", 14: "Warm Restart", 15: "Initialize Data",
               16: "Initialize Application", 17: "Start Application",
               18: "Stop Application", 19: "Save Configuration",
               20: "Enable Unsolicited", 21: "Disable Unsolicited",
               22: "Assign Class", 23: "Delay Measurement", 27: "Delete File",
               31: "Activate Configuration"}
WRITE_DNP3 = frozenset({2, 3, 4, 5, 6, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 31})
_DNP3_LINK = {0: "Reset Link States", 2: "Test Link States", 9: "Request Link Status"}


def classify_dnp3(b: bytes) -> Finding:
    if len(b) < 10 or b[0:2] != b"\x05\x64":
        return _f("dnp3", "invalid", "no 0x0564 link frame")
    lfc = b[3] & 0x0F
    if lfc in (3, 4) and len(b) > 12:
        fc = b[12]
        name = f"app FC{fc} {DNP3_APP_FC.get(fc, '')}".rstrip()
        return _f("dnp3", "write" if fc in WRITE_DNP3 else "interaction", name)
    return _f("dnp3", "handshake", f"link {_DNP3_LINK.get(lfc, 'function %d' % lfc)}")


# ---------------------------------------------------------------------------
# OPC UA binary
# ---------------------------------------------------------------------------

#: Binary-encoding NodeIds of service requests that change the server.
WRITE_OPCUA = {673: "WriteRequest", 712: "CallRequest", 488: "AddNodesRequest",
               494: "AddReferencesRequest", 500: "DeleteNodesRequest",
               506: "DeleteReferencesRequest", 700: "HistoryUpdateRequest"}


def classify_opcua(b: bytes) -> Finding:
    head = b[:3]
    if head in (b"HEL", b"OPN", b"CLO", b"RHE"):
        return _f("opcua", "handshake", head.decode())
    if head != b"MSG":
        return _f("opcua", "invalid", "no OPC UA message header")
    if len(b) < 27:
        return _f("opcua", "interaction", "MSG")
    enc = b[24]
    node = None
    if enc == 0x00:
        node = b[25]
    elif enc == 0x01 and len(b) >= 28:
        node = _u16le(b, 26)
    elif enc == 0x02 and len(b) >= 31:
        node = int.from_bytes(b[27:31], "little")
    if node in WRITE_OPCUA:
        return _f("opcua", "write", f"MSG {WRITE_OPCUA[node]}")
    return _f("opcua", "interaction", f"MSG service {node}")


# ---------------------------------------------------------------------------
# HART-IP
# ---------------------------------------------------------------------------

#: HART universal and common-practice commands that write or act.
WRITE_HART = frozenset({6, 17, 18, 19, 22, 34, 35, 36, 37, 38, 40, 41, 42, 43,
                        44, 45, 46, 47, 49, 51, 53, 59, 79})
_HARTIP_MSG = {0: "Session Initiate", 1: "Session Close", 2: "Keep Alive",
               3: "Token-Passing PDU", 4: "Direct PDU", 5: "Read Audit Log"}


def classify_hartip(b: bytes) -> Finding:
    if len(b) < 8 or b[0] not in (1, 2):
        return _f("hartip", "invalid", "no HART-IP header")
    mid = b[2]
    name = _HARTIP_MSG.get(mid, f"message {mid}")
    if mid in (0, 1, 2):
        return _f("hartip", "handshake", name)
    if mid == 3 and len(b) > 9:
        delim = b[8]
        addr = 5 if delim & 0x80 else 1
        k = 9 + addr + ((delim >> 5) & 0x03)
        if len(b) > k:
            cmd = b[k]
            return _f("hartip", "write" if cmd in WRITE_HART else "interaction",
                      f"{name} command {cmd}")
    if mid in (3, 4, 5):
        return _f("hartip", "interaction", name)
    return _f("hartip", "invalid", name)


# ---------------------------------------------------------------------------
# GE-SRTP
# ---------------------------------------------------------------------------

#: Service request codes (byte 42 of a request) that write memory or change
#: the PLC: write system/task/program-block memory, set control ID, set PLC
#: state (run/stop), set time/date, clear fault table. From public protocol
#: analyses; no real write frame has been observed on our sensors.
WRITE_SRTP = {0x07: "Write System Memory", 0x08: "Write Task Memory",
              0x09: "Write Program Block Memory", 0x22: "Set Control ID",
              0x23: "Set PLC State", 0x24: "Set PLC Time/Date",
              0x39: "Clear Fault Table"}


def classify_srtp(b: bytes) -> Finding:
    if b and set(b) == {0}:
        return _f("ge-srtp", "handshake", "init (zero bytes)")
    if len(b) >= 43 and b[0] == 0x02:
        code = b[42]
        if code in WRITE_SRTP:
            return _f("ge-srtp", "write", WRITE_SRTP[code])
        return _f("ge-srtp", "interaction", f"service 0x{code:02x}")
    return _f("ge-srtp", "invalid", "not SRTP")


# ---------------------------------------------------------------------------
# Kamstrup meter / management, Guardian AST (Veeder-Root)
# ---------------------------------------------------------------------------

KAMSTRUP_MGMT_WRITE = frozenset({"!SA", "!SB", "!SC", "!SD", "!SH", "!SI", "!SK",
                                 "!SN", "!SP", "!SS", "!RC", "!RR"})
KAMSTRUP_MGMT_READ = frozenset({"!GC", "!GV", "!WM", "H"})


def classify_kamstrup(b: bytes) -> Finding:
    if len(b) >= 3 and b[0] == 0x80 and b[-1:] == b"\r":
        return _f("kamstrup", "interaction", "meter frame")
    return _f("kamstrup", "invalid", "non-Kamstrup bytes")


def classify_kamstrup_mgmt(text: str) -> Finding:
    tok = (text or "").strip().split(None, 1)
    if not tok:
        return _f("kamstrup-management", "connect")
    cmd = tok[0].upper()
    has_args = len(tok) > 1 and bool(tok[1].strip())
    if cmd in KAMSTRUP_MGMT_WRITE or (cmd in ("!AC", "!AS") and has_args):
        return _f("kamstrup-management", "write", cmd)
    if cmd in KAMSTRUP_MGMT_READ or cmd in ("!AC", "!AS"):
        return _f("kamstrup-management", "interaction", cmd)
    return _f("kamstrup-management", "invalid", "not a management command")


def classify_guardian(event_type: str, request) -> Finding:
    code = ""
    if event_type and str(event_type).startswith("AST "):
        code = str(event_type)[4:].strip()
    elif request:
        code = str(request).strip().lstrip("\x01").strip()
    if not code:
        return _f("guardian_ast", "connect")
    if code[:1] in ("S", "s"):
        return _f("guardian_ast", "write", f"ATG {code[:6]}")
    if code[:1] in ("I", "i"):
        return _f("guardian_ast", "interaction", f"ATG {code[:6]}")
    return _f("guardian_ast", "invalid", "not an ATG command")


# ---------------------------------------------------------------------------
# Document-level entry points
# ---------------------------------------------------------------------------

def structured(doc: dict) -> Optional[dict]:
    """The pre-decoded ``ics`` fields of a document, nested or dotted."""
    v = doc.get("ics")
    out = dict(v) if isinstance(v, dict) else {}
    for key in ("write", "function", "protocol"):
        if f"ics.{key}" in doc and key not in out:
            out[key] = doc[f"ics.{key}"]
    return out or None


def _truthy(v) -> bool:
    return v is True or str(v).strip().lower() in ("true", "1", "yes")


def _snmp_op(event_type: str) -> Optional[str]:
    et = (event_type or "").lower()
    for op in ("bulk", "getnext", "set", "get", "trap", "inform"):
        if op in et:
            return op
    return None


def _snmp_oid(request) -> Optional[str]:
    try:
        j = json.loads(request) if isinstance(request, str) else (request or {})
    except (TypeError, ValueError):
        return None
    oid = j.get("oid") if isinstance(j, dict) else None
    if not oid:
        return None
    oid = str(oid).strip()
    if oid.startswith("("):
        oid = oid.strip("() ").replace(", ", ".").replace(",", ".")
    return oid[:64]


def classify_conpot(doc: dict) -> Finding:
    """Classify one ConPot document."""
    proto = conpot_protocol(doc)
    st = structured(doc)
    if st and _truthy(st.get("write")):
        return _f(st.get("protocol") or proto, "write",
                  str(st.get("function") or "ics.write")[:80], structured=True)
    event_type = doc.get("event_type")
    request = doc.get("conpot_request")
    if request is None:
        request = doc.get("request")
    if proto == "snmp":
        op = _snmp_op(event_type)
        if op is None:
            return _f("snmp", "connect")
        oid = _snmp_oid(request)
        name = f"SNMP {op}" + (f" {oid}" if oid else "")
        return _f("snmp", "write" if op == "set" else "interaction", name)
    if proto == "guardian_ast":
        return classify_guardian(event_type, request)
    if proto == "ipmi":
        if event_type and event_type not in LIFECYCLE:
            return _f("ipmi", "interaction", str(event_type)[:40])
        b = payload_bytes(request)
        if b:
            return _f("ipmi", "handshake" if b[:1] == b"\x06" else "invalid",
                      "RMCP" if b[:1] == b"\x06" else "not RMCP")
        return _f("ipmi", "connect")
    if request in (None, "") or (isinstance(request, str) and not request.strip()):
        return _f(proto, "connect")
    if proto == "http":
        s = str(request)
        if s.startswith("(None,"):
            return _f("http", "invalid", "unparsed HTTP")
        m = re.match(r"\('([^']{0,80})", s)
        return _f("http", "interaction", f"HTTP {m.group(1) if m else ''}".strip())
    if proto == "ftp":
        b = payload_bytes(request)
        if b:
            return _f("ftp", "interaction",
                      "FTP " + b.split(b" ", 1)[0].strip().decode("latin-1")[:12].upper())
        return _f("ftp", "invalid", "not FTP")
    if proto == "enip" and isinstance(request, str) and "cmd=" in request:
        return classify_enip_text(request)
    if proto == "kamstrup-management":
        b = payload_bytes(request)
        text = b.decode("latin-1") if b is not None else str(request)
        return classify_kamstrup_mgmt(text)
    b = payload_bytes(request)
    if b is None:
        return _f(proto, "invalid", "undecodable payload")
    decoder = _DECODERS.get(proto)
    if decoder is None:
        return _f(proto, "interaction", None)
    return decoder(b)


_DECODERS = {
    "modbus": classify_modbus,
    "s7comm": classify_s7,
    "iec104": classify_iec104,
    "enip": classify_enip,
    "bacnet": classify_bacnet,
    "kamstrup": classify_kamstrup,
    "dnp3": classify_dnp3,
    "opcua": classify_opcua,
    "hartip": classify_hartip,
    "ge-srtp": classify_srtp,
}

#: What the emulators write when nothing but a TCP connect happened.
FAKE_CONNECT_ONLY = "tcp-connect-only"


def classify_fake(proto: str, payload) -> Finding:
    """Classify one ICS emulator row (logged as Heralding: ``proto`` names
    the protocol and ``password`` carries the first bytes, as hex)."""
    p = fake_protocol(proto) or str(proto)
    if payload is None or str(payload).strip() in ("", FAKE_CONNECT_ONLY) \
            or str(payload).startswith("tcp-connect"):
        return _f(p, "connect")
    b = payload_bytes(payload)
    if b is None:
        return _f(p, "invalid", "undecodable payload")
    decoder = _DECODERS.get(p)
    return decoder(b) if decoder else _f(p, "interaction")


def classify_doc(doc: dict) -> Optional[Finding]:
    """Any hive document -> Finding, or None when it is not ICS at all."""
    t = doc.get("type")
    st = structured(doc)
    if t == "ConPot":
        return classify_conpot(doc)
    if t == "Heralding" and fake_protocol(doc.get("proto")):
        if st and _truthy(st.get("write")):
            return _f(fake_protocol(doc.get("proto")), "write",
                      str(st.get("function") or "ics.write")[:80], structured=True)
        return classify_fake(doc.get("proto"), doc.get("password"))
    if st and _truthy(st.get("write")):
        return _f(st.get("protocol"), "write", str(st.get("function") or "ics.write")[:80],
                  structured=True)
    return None


# ---------------------------------------------------------------------------
# Session summary
# ---------------------------------------------------------------------------

_MAX_FUNCTIONS = 12


def summarize(findings: Iterable[Finding]) -> dict:
    """Roll one session's findings up into the dict the builder and the
    evidence gate read (``session.meta["ics"]``). JSON-safe, bounded."""
    findings = [f for f in (Finding.coerce(x) for x in findings) if f is not None]
    protos = sorted({f.protocol for f in findings if f.protocol})
    valid = sorted({f.protocol for f in findings if f.protocol and f.valid})
    tier = max((f.tier for f in findings), key=_RANK.__getitem__, default="connect")
    funcs: list[str] = []
    writes: list[str] = []
    snmp_ops: set[str] = set()
    for f in findings:
        if f.function and f.function not in funcs and len(funcs) < _MAX_FUNCTIONS:
            funcs.append(f.function)
        if f.write and f.function and f.function not in writes and len(writes) < _MAX_FUNCTIONS:
            writes.append(f.function)
        if f.protocol == "snmp" and f.function:
            snmp_ops.add(f.function.split()[1] if len(f.function.split()) > 1 else "")
    industrial_tier = max((f.tier for f in findings if f.protocol in INDUSTRIAL),
                          key=_RANK.__getitem__, default=None)
    snmp_only = bool(protos) and set(protos) == {"snmp"}
    return {
        "protocols": protos,
        "valid_protocols": valid,
        "tier": tier,
        "industrial_tier": industrial_tier,
        "write": tier == "write",
        "functions": funcs,
        "write_functions": writes,
        "snmp_ops": sorted(o for o in snmp_ops if o),
        "snmp_only": snmp_only,
        "snmp_bulk_only": snmp_only and snmp_ops == {"bulk"},
    }


def session_labels(summary: Optional[dict]) -> list[str]:
    """ICS labels for a session summary: ``targeting:ics`` for any touch,
    ``ics:<protocol>`` only for protocols with a VALID request (never for a
    port touch), ``ics:protocol-interaction`` for an industrial request
    beyond the handshake, ``ics:write-control`` for a write, and the
    research-scanner labels when the source was classified as one."""
    if not summary:
        return []
    out = [LABEL_TARGETING]
    for p in summary.get("valid_protocols") or ():
        lab = PROTOCOL_LABELS.get(p)
        if lab and lab not in out:
            out.append(lab)
    if summary.get("industrial_tier") in ("interaction", "write"):
        out.append(LABEL_INTERACTION)
    if summary.get("write"):
        out.append(LABEL_WRITE)
    rs = summary.get("research_scanner")
    if rs:
        out.append(LABEL_SCANNER)
        v = re.sub(r"[^a-z0-9.-]", "-", str(rs.get("vendor") or "").lower()).strip("-")
        if v:
            out.append(f"scanner:{v[:40]}")
    return out


# ---------------------------------------------------------------------------
# Research scanners (heuristic; the benign allowlist covers the rest)
# ---------------------------------------------------------------------------

#: AS-organisation substrings of research/census scanners that the benign
#: allowlist does not list. A heuristic: an AS name is not an identity.
SCANNER_AS_ORG = {
    "driftnet": "driftnet",
    "modat": "modat",
    "palo alto networks": "paloalto-xpanse",
    "alpha strike": "alphastrike",
    "arbor networks": "netscout-arbor",
    "internet measurement": "driftnet",
    "criminal ip": "criminalip",
    "leakix": "leakix",
}
#: Forward-confirmed reverse-DNS suffixes of the same kind of scanner.
SCANNER_RDNS = {
    "internet-measurement.com": "driftnet",
    "infrawat.ch": "infrawatch",
    "modat.io": "modat",
    "internet-census.org": "internet-census",
    "criminalip.com": "criminalip",
    "leakix.net": "leakix",
    "alphastrike.io": "alphastrike",
    "reposify.net": "reposify",
    "internet-albedo.net": "albedo",
    "cybcube.com": "cybercube",
    "recyber.net": "recyber",
    "deepfield.net": "netscout-arbor",
    "bufferover.run": "bufferover",
    "cyberresilience.io": "cyberresilience",
    "ipip.net": "ipip",
}


def heuristic_scanner(as_org: Optional[str], rdns_name: Optional[str]) -> Optional[dict]:
    """``{"vendor", "basis"}`` for a research scanner not on the benign
    allowlist, from a forward-confirmed PTR suffix or an AS-org substring;
    None otherwise."""
    name = (rdns_name or "").strip().rstrip(".").lower()
    if name:
        for suf, vendor in SCANNER_RDNS.items():
            if name == suf or name.endswith("." + suf):
                return {"vendor": vendor, "basis": f"rdns:{suf}"}
    org = (as_org or "").lower()
    if org:
        for kw, vendor in SCANNER_AS_ORG.items():
            if kw in org:
                return {"vendor": vendor, "basis": f"as-org:{kw}"}
    return None
