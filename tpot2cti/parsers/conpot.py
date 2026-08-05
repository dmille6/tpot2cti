"""ConPot parser — ICS/SCADA protocol honeypot.

See docs/parsers/conpot.md for protocol/ES-field/STIX/substance notes.
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
    the default one-event-per-session correlator; every session is
    substantive.
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
                # NOT `commands`. This is an HTTP request ConPot received, not
                # a command anyone executed. It was appended to `commands` to
                # reuse Note rendering, and six consumers then treated it as
                # execution — including `_is_bare_scan()`, so every ConPot
                # probe escaped the drive-by gate and collected +25 score plus
                # prose claiming shell activity. Note reuse was not worth that.
                s.protocol_requests.append(str(request))
            if ev.meta.get("request_truncated"):
                s.meta["request_truncated"] = True
            sessions.append(s)
        return sessions
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
