"""ConPot parser — ICS/SCADA protocol honeypot.

ConPot emulates a handful of industrial-control protocols (Modbus,
S7comm, IEC-60870-5-104, IPMI, etc.).  Any probe against these
protocols on the open internet is, by itself, interesting — there is
no legitimate reason for a stranger to be speaking Modbus to a random
IP on TCP/502 — so every ConPot document we receive becomes a
substantive AttackSession.  No drive-by filter applies.

Per V1_SPEC.md §5.6:

  T-Pot doc fields used:
    src_ip, dst_port, protocol (modbus / s7comm / iec104 / ipmi / ...),
    request (varies by protocol — function code, register read blob,
    raw application-layer bytes, etc.)

  Event correlation:
    each ES doc is a discrete probe.  We use the default
    one-event-per-session correlator (BaseParser.correlate).

  STIX emitted per session (built downstream by the publisher):
    IPv4-Addr, AutonomousSystem, Location (via build_attacker_context),
    Indicator(ip), Sighting,
    Note with the protocol-specific request details,
    AttackPattern("industrial-protocol-recon") via Indicator.

  Relationships:
    Indicator → indicates → AttackPattern.

Per docs/LESSONS_LEARNED_FROM_V0.md §2 (substance filter):
    "Drive-by probes get one Sighting; substantive sessions get the
     full SDO graph."  For ConPot we deliberately treat every probe
     as substantive — these protocols are so rare on the open
     internet that even an empty connection has signal worth a Note
     and an ATT&CK link.  `has_substance()` is therefore overridden
     to always return True.

This parser only `parse()`s and supplies session metadata; the publisher
consumes `AttackSession.has_substance()` and reaches into
`session.meta` / `session.commands` / `events[0].meta` to construct the
STIX bundle.  We do NOT call STIXBuilder methods here — that lives in
the publisher layer (see tpot2cti/stix/builder.py).
"""

from __future__ import annotations

import logging
from typing import Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent

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

    Per V1_SPEC §5.6 every ConPot probe is substantive: even a bare
    Modbus connection to TCP/502 from a stranger is signal.  We use
    the default one-event-per-session correlator and override
    `has_substance()` to always return True.
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

        # T-Pot's ConPot logstash mapping sometimes carries the protocol
        # in `protocol`, sometimes in `app` or `event_type` depending on
        # the ConPot version.  Prefer the explicit `protocol` field.
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
        request = doc.get("request")
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

        # The ConPot session id (when present) helps the publisher
        # construct a deterministic STIX id; otherwise from_event() will
        # synthesize one.
        if (sid := doc.get("session") or doc.get("session_id")):
            event.session_id = str(sid)

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — default one-event-per-session is correct
    # ──────────────────────────────────────────────────────────────────
    # ConPot has no multi-event session abstraction at the T-Pot doc
    # level: each ES doc is a discrete probe of a single ICS protocol.
    # We inherit BaseParser.correlate which wraps each event in a
    # one-event AttackSession.  Per V1_SPEC §5.6 — see also the parser-
    # model overview in V1_SPEC §5 introduction.
    #
    # We DO populate session-level aggregate fields here so the
    # publisher doesn't have to reach into events[0]: the `request`
    # blob is also pushed onto `session.commands` (which the publisher
    # already knows how to render into Notes for protocols like
    # Cowrie), and protocol/request meta is mirrored onto session.meta.

    def correlate(self, events):
        """One-event-per-session, with session-level meta populated.

        We keep the default 1:1 mapping but enrich each AttackSession
        with `session.meta["protocol"]`, `session.meta["request"]`, and
        push the request blob onto `session.commands` so downstream
        consumers can render a Note without peeking into `events[0]`.
        """
        sessions: list[AttackSession] = []
        for ev in events:
            s = AttackSession.from_event(ev)
            # Mirror per-event meta onto the session for publisher access.
            if proto := ev.meta.get("protocol"):
                s.meta.setdefault("protocol", proto)
            if request := ev.meta.get("request"):
                s.meta.setdefault("request", request)
                # The publisher renders session.commands into Notes for
                # other parsers; reuse the same shape here so the
                # builder can produce a uniform "request blob" Note
                # without a ConPot-specific code path.  See
                # docs/LESSONS_LEARNED_FROM_V0.md §6 on Note shape reuse.
                s.commands.append(str(request))
            if ev.meta.get("request_truncated"):
                s.meta["request_truncated"] = True
            sessions.append(s)
        return sessions

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — ALWAYS True for ConPot
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """ConPot probes are inherently rare and always substantive.

        Per V1_SPEC §5.6 and the user-supplied Phase-4 spec: every
        ICS/SCADA probe — even an empty connection — is worth the full
        STIX SDO graph (IPv4 + AS + Location + Indicator + Sighting +
        Note + AttackPattern).  There is no legitimate reason for a
        stranger to speak Modbus or S7comm to your IP; the event of
        them trying IS the signal.

        See also docs/LESSONS_LEARNED_FROM_V0.md §2: the substance
        filter is per-protocol, not global.  For ConPot the filter
        is effectively "always on".
        """
        return True

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _derive_protocol(doc: dict) -> Optional[str]:
        """Pick the ICS protocol label from a ConPot doc.

        T-Pot's ConPot mapping is inconsistent across versions: some
        builds put the protocol under `protocol`, some under `app`,
        some derive it from `event_type` ("MODBUS", "S7Comm", etc.).
        We probe each in turn and lowercase the result.
        """
        for field in ("protocol", "app", "event_type"):
            v = doc.get(field)
            if v:
                return str(v).lower()
        return None

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


# Register on import
register(ConPotParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = ConPotParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: Modbus probe (substantive — every ICS probe is) ────────
    modbus_doc = {
        "@timestamp": now.isoformat(),
        "type": "ConPot",
        "src_ip": "203.0.113.7",
        "src_port": 51111,
        "dst_port": 502,
        "protocol": "modbus",
        "t-pot_hostname": "node1",
        "request": {
            "function_code": 3,
            "start_address": 0,
            "quantity": 10,
        },
        "geoip": {
            "country_iso_code": "RU",
            "country_name": "Russia",
            "asn": 12389,
            "organization": "Rostelecom",
        },
    }

    # ── Case 2: S7Comm probe with empty request (still substantive!) ───
    s7_doc = {
        "@timestamp": now.isoformat(),
        "type": "ConPot",
        "src_ip": "198.51.100.11",
        "src_port": 41010,
        "dst_port": 102,
        "protocol": "s7comm",
        "t-pot_hostname": "node1",
        "request": "",
    }

    # ── Case 3: IPMI probe with raw payload string ─────────────────────
    ipmi_doc = {
        "@timestamp": now.isoformat(),
        "type": "ConPot",
        "src_ip": "192.0.2.99",
        "dst_port": 623,
        "protocol": "ipmi",
        "request": "06 00 ff 07 00 00 00 00 00 00 00 00 09 20 18 c8 81 00 38 8e",
    }

    docs = [modbus_doc, s7_doc, ipmi_doc]
    events = [parser.parse(d) for d in docs]
    assert all(e is not None for e in events), "parse() returned None unexpectedly"
    print(f"parsed {len(events)} ConPot events")
    for e in events:
        print(
            f"  src_ip={e.src_ip:<16} protocol={e.protocol:<8} "
            f"request={e.meta.get('request')!r:.80s}"
        )

    sessions = parser.correlate(events)
    assert len(sessions) == 3, f"expected 3 sessions, got {len(sessions)}"
    print(f"\ncorrelated into {len(sessions)} session(s)")

    for s in sessions:
        sub = parser.has_substance(s)
        print(
            f"  session src_ip={s.src_ip:<16} "
            f"protocol={s.meta.get('protocol'):<8} "
            f"event_count={s.event_count} "
            f"has_substance={sub}"
        )
        # Every ConPot session is substantive per V1_SPEC §5.6.
        assert sub is True, f"ConPot session {s.src_ip} not substantive!"
        assert s.dst_ports, "session.dst_ports should be populated"
        assert s.protocols, "session.protocols should be populated"

    # The Modbus and IPMI sessions both carry a non-empty request blob;
    # the S7Comm session carried an empty string so should have no
    # command pushed onto session.commands.
    assert len(sessions[0].commands) == 1, "modbus session.commands missing request"
    assert len(sessions[1].commands) == 0, "s7 session.commands should be empty"
    assert len(sessions[2].commands) == 1, "ipmi session.commands missing request"

    # Malformed docs
    assert parser.parse({}) is None, "empty doc should yield None"
    assert parser.parse({"src_ip": "1.2.3.4"}) is None, "missing ts should yield None"

    print("\nOK")
