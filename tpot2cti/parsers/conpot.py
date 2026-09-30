"""ConPot parser — ICS/SCADA protocol honeypot.

See docs/parsers/conpot.md for protocol/ES-field/STIX/substance notes.
"""

from __future__ import annotations

import logging
from typing import Optional

from tpot2cti import ics
from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent
from tpot2cti.session.correlator import correlate_by_session_id

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Hard cap on the rendered length of the `request` blob preserved in
#: meta.  Some attackers send oversized payloads to probe for buffer
#: overflows; we keep enough bytes to be useful in a Note but not so
#: many that one anomalous probe blows up a STIX bundle.  Per the
#: lessons doc §6 (bundle dedup / size discipline).
REQUEST_BLOB_CAP = 1024

#: T-Pot type field value this parser handles.
TYPE_NAME = "ConPot"

#: Known ConPot protocol labels we surface verbatim into meta.
#: Anything outside this set is still preserved — we just lowercase
#: and pass through.  Listed here for documentation, not for
#: validation.
_KNOWN_PROTOCOLS: frozenset[str] = frozenset({
    "modbus",
    "s7comm",
    "iec104",
    "ipmi",
    "bacnet",
    "kamstrup",
    "guardian_ast",
    "enip",
    "http",
    "snmp",
})


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class ConPotParser(BaseParser):
    """Parser for T-Pot's ConPot ICS/SCADA honeypot.

    Documents are grouped into sessions by ConPot's session ``id``. Each
    document is classified by tpot2cti/ics.py (protocol from ``data_type``,
    depth tier, function), and the session carries the roll-up in
    ``session.meta["ics"]``: the builder turns it into labels, the evidence
    gate into an ICS evidence decision.
    """

    type_name = TYPE_NAME

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert one ConPot ES doc into a ParsedEvent.

        Returns None for malformed docs (no src_ip, no timestamp).  The
        ConPot ICS protocol identifier is stashed in `event.protocol`
        and mirrored into `event.meta["protocol"]` for the publisher.
        The raw `request` blob (function code, register read, etc.) is
        capped at `REQUEST_BLOB_CAP` characters and preserved in
        `event.meta["request"]`.

        Tolerant of missing/malformed fields — every failure path logs
        at DEBUG and returns None rather than raising (per V1_SPEC §7).
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("conpot: doc missing src_ip; skipping")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("conpot: doc missing/unparseable @timestamp; skipping")
            return None

        # ConPot names the protocol in `data_type` (modbus, s7comm, IEC104,
        # snmp ...). `event_type` is the lifecycle or operation
        # (NEW_CONNECTION, SNMPv2 Bulk) or null for a data document -- it
        # was read as the protocol until 2026-09-30, so every session was
        # "new_connection", "snmpv2 bulk" or nothing.
        protocol = self._derive_protocol(doc)

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or doc.get("hostname")
                or "unknown"
            ),
            event_type=TYPE_NAME,
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int(doc.get("dst_port") or doc.get("dest_port")),
            dst_ip=doc.get("dst_ip") or doc.get("dest_ip"),
            protocol=protocol,
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── Protocol-specific request blob (capped) ────────────────────
        # Hive logstash (2026-06-29) renames ConPot's payload fields to
        # conpot_* to avoid a shared-index mapping collision with Galah/
        # h0neytr4p's object request/response. Fall back to the bare
        # `request` for historical docs still indexed under the old name.
        request = doc.get("conpot_request") or doc.get("request")
        if request is None:
            request_str = ""
        elif isinstance(request, (dict, list)):
            # Some ConPot versions emit structured request objects (e.g.
            # parsed Modbus PDU dicts).  Render as a stable string so
            # the downstream Note body is reproducible across runs.
            try:
                import json
                request_str = json.dumps(request, sort_keys=True, default=str)
            except (TypeError, ValueError) as e:
                logger.debug(f"conpot: could not json-render request: {e}")
                request_str = str(request)
        else:
            request_str = str(request)

        if len(request_str) > REQUEST_BLOB_CAP:
            event.meta["request_truncated"] = True
            request_str = request_str[:REQUEST_BLOB_CAP]
        event.meta["request"] = request_str

        if protocol:
            event.meta["protocol"] = protocol

        # ConPot's session id is `id`: one UUID shared by the connect, data
        # and disconnect documents of one source on one protocol (30 s idle
        # timeout, so it can span TCP connections). correlate() groups on
        # it. `session`/`session_id` are kept for older builds.
        if (sid := doc.get("id") or doc.get("session") or doc.get("session_id")):
            event.session_id = str(sid)

        # What the document shows, protocol-wise (tpot2cti/ics.py): tier
        # (connect / invalid / handshake / interaction / write) and a short
        # function label. The raw lifecycle/operation stays in meta too.
        if (et := doc.get("event_type")):
            event.meta["conpot_event"] = str(et)[:64]
        finding = ics.classify_conpot(doc)
        event.meta["ics_finding"] = finding.to_dict()

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — group by ConPot's session id
    # ──────────────────────────────────────────────────────────────────
    # Until 2026-09-30 this was one event per session, and the session id
    # was never read (ConPot calls it `id`), so a connect, a Modbus request
    # and a disconnect were three unrelated "probes". Now the documents of
    # one ConPot session are one AttackSession. Documents without an id
    # still become one-event sessions.
    #
    # The `request` blob goes onto `session.protocol_requests` — NOT
    # `session.commands`, which means "commands the attacker RAN" and is
    # read as such by the score, the prose, the ATT&CK mapping and the
    # Process builder.

    def correlate(self, events):
        """Group by (id, sensor, src_ip); aggregate protocol, requests and
        the ICS summary (``session.meta["ics"]``, see tpot2cti/ics.py)."""
        sessions = correlate_by_session_id(events, aggregator=_aggregate_ics_session)
        # One-event sessions (no id) bypass the aggregator; summarise them too.
        for s in sessions:
            if "ics" not in s.meta:
                _aggregate_ics_session(s, s.events)
        return sessions

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _derive_protocol(doc: dict) -> Optional[str]:
        """The canonical protocol of a ConPot doc: `data_type` first, then
        the historical `protocol`/`app`; `event_type` only when it is itself
        a protocol name (see ics.conpot_protocol)."""
        return ics.conpot_protocol(doc)

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


def _aggregate_ics_session(session: AttackSession, events: list) -> None:
    """Session-level meta for a ConPot (or ICS-emulator) session.

    * ``session.meta["protocol"]``: the first protocol seen (one ConPot
      session is one protocol in practice).
    * ``session.meta["request"]`` / ``session.protocol_requests``: the
      non-empty request blobs, in order, deduplicated (a 30-second SNMP
      flood session repeats one request hundreds of times).
    * ``session.meta["ics"]``: ics.summarize() over the events' findings,
      plus ``research_scanner`` when the cycle classified the source as one.
    """
    findings = []
    seen_requests: set = set()
    for ev in events:
        m = ev.meta
        if (proto := m.get("protocol")):
            session.meta.setdefault("protocol", proto)
        if (request := m.get("request")):
            session.meta.setdefault("request", request)
            if request not in seen_requests and len(seen_requests) < _MAX_SESSION_REQUESTS:
                seen_requests.add(request)
                session.protocol_requests.append(str(request))
        if m.get("request_truncated"):
            session.meta["request_truncated"] = True
        if (f := m.get("ics_finding")) is not None:
            findings.append(f)
        if (rs := m.get("research_scanner")) and "research_scanner" not in session.meta:
            session.meta["research_scanner"] = rs
    summary = ics.summarize(findings)
    if (rs := session.meta.get("research_scanner")):
        summary["research_scanner"] = rs
    session.meta["ics"] = summary


#: Distinct request blobs kept per session (the Note renders them).
_MAX_SESSION_REQUESTS = 20


# Register on import
register(ConPotParser())
