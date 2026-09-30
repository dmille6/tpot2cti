# ConPot parser — ICS/SCADA protocol honeypot

ConPot emulates industrial-control protocols (Modbus, S7comm, IEC 60870-5-104,
EtherNet/IP, BACnet, Kamstrup, Guardian AST) plus SNMP, HTTP, FTP and IPMI.
The classification of what a document shows lives in `tpot2cti/ics.py`
(standard library only, shared with out-of-process tooling).

## ES fields used

| Field | Meaning |
|---|---|
| `data_type` | **the protocol** (`modbus`, `s7comm`, `IEC104`, `enip`, `bacnet`, `snmp`, `http`, `ftp`, `ipmi`, `kamstrup_protocol`, `kamstrup_management_protocol`, `guardian_ast`) |
| `event_type` | the lifecycle (`NEW_CONNECTION`, `CONNECTION_LOST` ...) or the operation (`SNMPv2 Bulk`, `GET_CHANNEL_AUTH_CAPABILITIES`, `AST I20100`), null on a data document. Kept as `meta["conpot_event"]`, **never** the protocol |
| `id` | ConPot's session UUID, shared by the connect, data and disconnect documents of one source on one protocol (30 s idle timeout, so it can span TCP connections) |
| `conpot_request` (older docs: `request`) | the request: `b'<hex>'` (Modbus, S7, Kamstrup meter), a Python bytes literal (IPMI, FTP), JSON (SNMP), a repr tuple (HTTP), text (Kamstrup management), bare hex or `cmd=<n> ...` text from capture shims (IEC-104, BACnet, ENIP) |
| `ics.*` | optional pre-decoded fields from the log pipeline; `ics.write: true` makes a document a write whatever its payload says |

`protocol` / `app` are still read for older builds. Until 2026-09-30 the parser
read `protocol`, `app`, then `event_type`: ConPot sends neither of the first
two, so every session's "protocol" was `new_connection`, `snmpv2 bulk` or
nothing, and the session id (`id`) was never read, so every document was its
own one-event session.

## Correlation

`correlate_by_session_id` on `id`. Documents without one become one-event
sessions. Every session carries `meta["ics"]`, the roll-up of its documents:

| Key | |
|---|---|
| `protocols`, `valid_protocols` | protocols seen / with at least a valid handshake |
| `tier`, `industrial_tier` | deepest tier overall / on an industrial protocol: `connect` < `invalid` < `handshake` < `interaction` < `write` |
| `functions`, `write_functions` | short labels, e.g. `FC43 Encapsulated Interface Transport unit 0`, `SZL read 0x0011`, `SNMP set 1.3.6.1.2.1.1.1.0` (at most 12) |
| `write` | any write/control function |
| `snmp_only`, `snmp_bulk_only`, `snmp_ops` | SNMP shape (see the refusals in docs/EVIDENCE_GATE.md section 9) |
| `research_scanner` | `{vendor, basis, list}` when the cycle classified the source (allowlist or heuristic) |

Request blobs go to `session.protocol_requests` (deduplicated, at most 20), never
to `session.commands`.

## Tiers and write/control functions

See the module docstring and tables in `tpot2cti/ics.py`. Write/control:
Modbus FC 5/6/15/16/21/22/23, FC 8 restart/listen-only/clear, UMAS write,
download, start, stop; S7 Write Var, the download sequence, PI service, PLC
stop (the upload sequence reads the program: interaction);
IEC-104 command ASDUs 45-51 and 58-64, reset process, parameter loading, with
activation/deactivation cause and a valid APCI (bytes that are HTTP or TLS are
`invalid`, never a command); SNMP Set; BACnet WriteProperty(Multiple), file and
list writes, object create/delete, DeviceCommunicationControl,
ReinitializeDevice, WriteGroup; CIP Set_Attribute*, Write_Tag*, Reset, Start,
Stop, Create, Delete (including inside Unconnected_Send); Kamstrup management
set/restart/connect commands; Guardian AST `S` + five digits (ConPot logs
`AST <request[1:7]>` for any input, so anything else is `invalid`); DNP3
write, select/operate, restarts, application start/stop, assign class;
SNMP Set with a parsed OID.

Validity is checked before a tier is given: declared lengths against the
bytes and the minimum function-specific body (a header-only Modbus FC 6, a
byte count that disagrees, an S7 frame whose TPKT/COTP/S7 lengths disagree,
Write Var without data, PI service without its parameters are `invalid`);
S7 Read/Write Var items (0x12 variable specifications filling the
parameter) and Write Var data records (return code, transport size, length,
padding), the download block name `_<type><number><dest>` and length part,
PI service and PLC stop names; DNP3 link length, header CRC and the CRC of
every captured data block, PRM and transport FIR; emulator truncation is
explicit (a payload ending in an ellipsis), a frame declaring more bytes than
it has is invalid unless cut, and a cut OPC UA or HART-IP frame is at most
`interaction`; SNMP OIDs must be numeric (dotted or tuple); ENIP
declared length and a CIP request inside SendRRData/SendUnitData; OPC UA
message size and a namespace-0 service NodeId; HART-IP byte count; FTP
verbs must be alphabetic.

## ICS emulators logged as Heralding

Rows with `proto` in `dnp3`, `opcua`, `hartip`, `ge-srtp` come from ICS
emulators that write through Heralding's log: `username` is the protocol name
and `password` the first request bytes as hex (or `tcp-connect-only`). The
Heralding parser classifies them like ConPot requests (DNP3 link/application
function codes, OPC UA message types and service NodeIds, HART-IP message ids
and HART commands, GE-SRTP service request codes), records **no credential**,
and the builder emits them as ICS sessions ("ICS Emulator Probe", family label
`ics-scada`, AttackPattern "ICS/SCADA protocol interaction").

## STIX

As every protocol session (`_build_protocol_session`): the attacker graph,
a Note with the raw requests, the "ICS/SCADA protocol interaction"
AttackPattern. ICS labels on the observable and the Indicator (v1 spellings):
`targeting:ics` and `ics` for any session that touched an industrial protocol
(not for HTTP/FTP/SNMP/IPMI alone); `ics:modbus`, `ics:s7`, `ics:iec104`,
`ics:ethernet-ip`, `ics:bacnet`, `ics:dnp3`, `ics:opc-ua`, `ics:hart-ip`,
`ics:ge-srtp`, `ics:veeder-root`, `ics:kamstrup`, `ics:snmp` only for a
protocol with a valid request (never for a port touch);
`ics:multi-protocol` when one address used two or more industrial protocols
(across the bundle: the builder puts the union of an address's ICS labels on
its observable and Indicator); `ics:protocol-interaction` for an industrial
request beyond the handshake;
`ics:write-control` (and +30 score) for a write; `scanner:research` and
`scanner:<vendor>` for a research scanner. The descriptions state the depth,
the functions, the writes and the scanner basis.
