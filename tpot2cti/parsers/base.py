"""tpot2cti — parser base classes and shared data model.

Every per-protocol parser inherits from `BaseParser` and lives under
`tpot2cti/parsers/<protocol>.py`.  Parsers transform raw T-Pot
Elasticsearch documents into normalized `ParsedEvent` objects, then
correlate those events into `AttackSession` aggregates that the STIX
builder consumes.

The substance filter — the single most important pattern we learned
from V0 (see docs/LESSONS_LEARNED_FROM_V0.md §2) — lives on the
session, not the event.  Drive-by probes get one Sighting; substantive
sessions get the full SDO graph.  Every parser decides what "substance"
means for its protocol via the `has_substance()` method.

Per V1_SPEC.md §5 (parser interface):

    class BaseParser:
        type_name: str  # value of T-Pot's `type` field this parser handles

        def parse(self, doc: dict) -> ParsedEvent | None:
            '''Convert a T-Pot ES doc into a normalized internal event.
            Return None to skip the doc (e.g. malformed).'''
            ...

        def has_substance(self, event: ParsedEvent) -> bool:
            '''Whether to emit STIX for this event. Default True;
            parsers can suppress (e.g. low-noise TCP probes).'''
            ...
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Normalized data model — every parser produces these
# ---------------------------------------------------------------------------

@dataclass
class ParsedEvent:
    """One T-Pot ES document, parsed into a normalized form.

    Required fields are populated for every protocol; optional fields
    are populated when the protocol carries that information.  Parser-
    specific extras live in `meta` for downstream STIX builders to use
    without polluting this dataclass with every conceivable field.
    """

    # ─── required (every parser populates these) ──────────────────────
    src_ip: str
    timestamp: datetime
    sensor_hostname: str           # T-Pot's `t-pot_hostname` field
    event_type: str                # T-Pot's `type` field (Cowrie, Suricata, ...)

    # ─── optional, parser-dependent ───────────────────────────────────
    session_id: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None    # "ssh", "smb", "http", "modbus", etc.

    # ─── attacker provenance from logstash geoip enrichment ───────────
    # We never fetch geo ourselves (per V1_SPEC non-goals); we take
    # what logstash already added.  None when logstash didn't enrich.
    src_country_code: Optional[str] = None    # ISO 3166-1 alpha-2
    src_country_name: Optional[str] = None
    src_city: Optional[str] = None
    src_asn: Optional[int] = None
    src_as_org: Optional[str] = None

    # ─── opaque ───────────────────────────────────────────────────────
    raw_doc: dict = field(default_factory=dict)    # original ES _source
    meta: dict = field(default_factory=dict)        # parser-specific extras


@dataclass
class AttackSession:
    """One or more correlated `ParsedEvent`s.

    A session represents a logical attacker interaction.  For protocols
    with native session IDs (Cowrie, Heralding), this groups events
    sharing a session_id from the same src_ip.  For protocols without
    sessions (Suricata, ConPot), each event becomes its own session.

    `has_substance()` operates on the *session* — drive-by probes that
    open a connection and disconnect get observable+Sighting only;
    sessions with actual attack activity (commands, auth, malware
    drops, credential attempts, multiple events) get the full STIX
    graph.
    """

    src_ip: str
    sensor_hostname: str
    session_id: str               # synthetic if events lack one
    event_type: str               # primary type (taken from first event)
    first_seen: datetime
    last_seen: datetime
    events: list[ParsedEvent] = field(default_factory=list)

    # ─── aggregated session attributes (populated by per-parser correlate) ──
    dst_ports: set[int] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)

    # Substance signals
    auth_success: bool = False
    commands: list[str] = field(default_factory=list)
    malware_hashes: list[str] = field(default_factory=list)  # sha256s
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    credentials_tried: list[tuple[str, str]] = field(default_factory=list)
    #: The specific (username, password) the honeypot ACCEPTED, if any.
    #: Lets the per-IP credential Note flag which login worked. Populated
    #: by parsers that observe a successful auth (Cowrie, Heralding).
    successful_credential: Optional[tuple[str, str]] = None
    #: Per-download (sha256, source-URL) pairs as they appeared TOGETHER in
    #: a single download event — preserves the link that the flat
    #: malware_hashes / urls lists lose. Drives the builder's URL→File
    #: "downloaded-from" edge. Each entry: ``{"sha256": str, "url": str|None}``.
    downloads: list[dict] = field(default_factory=list)

    # Fingerprints
    hassh: Optional[str] = None
    ssh_version: Optional[str] = None
    ja3: Optional[str] = None
    ja3s: Optional[str] = None
    http_header_hash: Optional[str] = None

    # Planted SSH public keys — populated by parsers that observe post-
    # compromise key-planting (Outlaw botnet's `echo "ssh-rsa AAA..." >>
    # authorized_keys` is the canonical case but any actor that drops
    # their own SSH key triggers this).  Each entry is the dict
    # ``{"type": "ssh-rsa", "key": "<base64 blob>", "comment":
    # "<comment>", "fingerprint": "<sha256 hex of the blob>"}``. The
    # fingerprint is what the downstream Cryptographic-Key observable
    # uses as its deterministic UUID5 seed, so every attacker IP that
    # planted the same key links to the same SCO — one click in OpenCTI
    # to see the entire campaign.
    planted_ssh_keys: list[dict] = field(default_factory=list)

    # Per-parser extras (e.g., DICOM command type, SIP method)
    meta: dict = field(default_factory=dict)

    @property
    def event_count(self) -> int:
        return len(self.events)

    @classmethod
    def from_event(cls, event: ParsedEvent) -> "AttackSession":
        """Build a one-event session.  Default for parsers without sessions."""
        synthetic_session_id = (
            event.session_id
            or f"{event.sensor_hostname}:{event.src_ip}:{int(event.timestamp.timestamp() * 1000)}"
        )
        s = cls(
            src_ip=event.src_ip,
            sensor_hostname=event.sensor_hostname,
            session_id=synthetic_session_id,
            event_type=event.event_type,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            events=[event],
        )
        if event.dst_port is not None:
            s.dst_ports.add(event.dst_port)
        if event.dst_ip:
            s.dst_ips.add(event.dst_ip)
        if event.protocol:
            s.protocols.add(event.protocol)
        return s


# ---------------------------------------------------------------------------
# Parser base class
# ---------------------------------------------------------------------------

class BaseParser:
    """Base class for every per-protocol parser.

    Subclasses MUST set `type_name` to the value of T-Pot's `type` field
    they handle (e.g. "Cowrie", "Suricata").  Subclasses MUST implement
    `parse()`.  They MAY override `correlate()` and `has_substance()`.

    The default `correlate()` is one-event-per-session — correct for
    Suricata, ConPot, FATT and anything else without protocol sessions.
    Parsers with native sessions (Cowrie, Heralding) override to group
    by session_id.

    The default `has_substance()` returns True — full STIX graph for
    every session.  Parsers that have a meaningful "drive-by probe"
    notion override to suppress noise.  Per V1_SPEC §5.1 (Cowrie
    example): "Pure probe-and-leave noise gets one-line representation
    rather than full SDO graph."
    """

    #: The value of T-Pot's `type` field this parser handles
    #: (e.g. "Cowrie", "Suricata", "ConPot").  Subclasses MUST set.
    type_name: str = ""

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if not cls.type_name:
            # Allow abstract/intermediate subclasses; only complain at
            # registration time (parsers/__init__.py register()).
            return

    # ──────────────────────────────────────────────────────────────────
    # API every subclass implements
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert a T-Pot ES doc into a normalized ParsedEvent.

        Return None to skip the doc (e.g. malformed, missing src_ip).
        Logging at DEBUG when skipping is helpful for diagnostics.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.parse() must be implemented"
        )

    # ──────────────────────────────────────────────────────────────────
    # API with sensible defaults — override if needed
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events: Iterable[ParsedEvent]) -> list[AttackSession]:
        """Group events into sessions.

        Default: one event per session.  Correct for protocols without
        native session IDs (Suricata, ConPot, FATT).

        Parsers with native sessions override:

            def correlate(self, events):
                by_session = defaultdict(list)
                for e in events:
                    by_session[(e.session_id, e.sensor_hostname)].append(e)
                return [self._session_from_events(g) for g in by_session.values()]
        """
        return [AttackSession.from_event(e) for e in events]

    def has_substance(self, session: AttackSession) -> bool:
        """Whether this session warrants the full STIX SDO graph.

        Default: True (always full treatment).  Parsers override to
        suppress drive-by noise.  Standard pattern:

            def has_substance(self, session):
                return (
                    session.auth_success
                    or session.commands
                    or session.malware_hashes
                    or session.credentials_tried
                    or session.event_count > 2
                )
        """
        return True

    # ──────────────────────────────────────────────────────────────────
    # Helpers parsers can use
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_timestamp(doc: dict) -> Optional[datetime]:
        """Parse T-Pot's `@timestamp` field.  Returns timezone-aware UTC
        or None if missing/unparseable."""
        ts = doc.get("@timestamp")
        if not ts:
            return None
        if isinstance(ts, datetime):
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        try:
            # ES typically writes ISO 8601 with `Z` suffix
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except (TypeError, ValueError) as e:
            logger.debug(f"unparseable @timestamp {ts!r}: {e}")
            return None

    @staticmethod
    def _populate_geoip(doc: dict, event: ParsedEvent) -> None:
        """Populate event.src_country_code / src_city / src_asn from
        logstash's geoip enrichment, if present.  Mutates the event
        in place.  Safe to call on a doc without geoip enrichment.
        """
        geo = (doc.get("geoip") or doc.get("src_geoip") or {})
        if not isinstance(geo, dict):
            return
        if cc := geo.get("country_iso_code") or geo.get("country_code2"):
            event.src_country_code = str(cc).upper()
        if cn := geo.get("country_name"):
            event.src_country_name = str(cn)
        if city := geo.get("city_name") or geo.get("city"):
            event.src_city = str(city)
        if asn := geo.get("asn") or geo.get("as_org"):
            # ASN may be int or string
            try:
                event.src_asn = int(asn)
            except (TypeError, ValueError):
                pass
        if as_org := geo.get("organization") or geo.get("as_org"):
            event.src_as_org = str(as_org)

    @staticmethod
    def _require_field(doc: dict, *fields: str) -> Optional[Any]:
        """Return the first non-empty value among `fields`, or None."""
        for f in fields:
            v = doc.get(f)
            if v not in (None, "", [], {}):
                return v
        return None

    # ──────────────────────────────────────────────────────────────────
    # Defensive-read helpers for T-Pot's dual-spelled fields
    #
    # Per 2026-05-22 audit #10-11 (and the 2026-05-22 dst_port bug,
    # commit decc6df): T-Pot's logstash pipelines have shipped some
    # fields under multiple names across versions.  Confirmed dual-
    # spellings as of live ES sample 2026-05-22:
    #
    #   canonical → seen alternates
    #   ──────────────────────────────────────────────────────────────
    #   dest_port → dst_port   (real, every honeypot type)
    #   dest_ip   → dst_ip     (real, every honeypot type)
    #   src_port  → source_port (defensive — not currently shipping)
    #   proto     → protocol   (real, ``protocol`` appears under
    #                            ``attack_connection.protocol``)
    #
    # Always pass the CANONICAL T-Pot spelling first; the helper falls
    # through to legacy names in order.  Helpers chosen over inline
    # ``a or b or c`` so the convention is grep-able and a future
    # parser author sees the dual-spelling discipline documented.
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def pick(doc: dict, *fields: str, default: Any = None) -> Any:
        """First non-None doc[f] among ``fields``; ``default`` if none.

        Strict ``is not None`` test — preserves 0 / ""  / [] so caller
        can distinguish "field absent" from "field present with falsy
        value" (matters for e.g. ``dst_port=0`` ICMP probes).
        """
        for f in fields:
            v = doc.get(f)
            if v is not None:
                return v
        return default

    @classmethod
    def pick_int(cls, doc: dict, *fields: str, default: Optional[int] = None) -> Optional[int]:
        """``pick`` + ``int()`` coercion. Returns ``default`` on absence
        or non-coercible values."""
        v = cls.pick(doc, *fields)
        if v is None:
            return default
        try:
            return int(v)
        except (TypeError, ValueError):
            return default

    @classmethod
    def pick_str(cls, doc: dict, *fields: str, default: Optional[str] = None) -> Optional[str]:
        """``pick`` + ``str()`` coercion. Returns ``default`` on absence."""
        v = cls.pick(doc, *fields)
        return default if v is None else str(v)


# ---------------------------------------------------------------------------
# Smoke-test helpers — used by per-parser ``__main__`` blocks
# ---------------------------------------------------------------------------
# Per 2026-05-22 audit #15: several parsers' ``__main__`` smoke tests
# duplicated identical ``os.environ.setdefault`` boilerplate to satisfy
# load_config()'s required-vars check.  Pulled out so a future parser
# author writes one line, and any future env-var addition only touches
# this helper.

def _smoketest_env() -> None:
    """Seed the minimum env vars ``load_config()`` requires for smoke tests.

    Idempotent (``setdefault``) so importing this from a parser smoke
    test never clobbers a real container env.  Used only by per-parser
    ``__main__`` blocks; production code paths never call this.
    """
    import os
    os.environ.setdefault("TPOT_HOST", "test")
    os.environ.setdefault("OPENCTI_ADMIN_TOKEN", "00000000-0000-0000-0000-000000000000")
    os.environ.setdefault("TPOT2CTI_CONNECTOR_ID", "00000000-0000-0000-0000-000000000001")
