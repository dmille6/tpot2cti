"""Honeytrap parser — TCP/UDP catchall honeypot.

Honeytrap is T-Pot's default-route catchall: anything that hits a
port no other honeypot is listening on lands here.  Most of what we
see is one-packet probes from internet background radiation — a SYN,
a banner grab, an empty UDP packet — but occasionally an attacker
actually sends an exploit payload to a non-honeypotted port and that
payload is worth preserving.

Per V1_SPEC.md §5.4:

  T-Pot doc fields used:
    src_ip, dst_port, proto, payload_hex, payload_printable,
    attack_connection (metadata)

  Event correlation: each TCP connection or UDP datagram is one event.
  We use the default one-event-per-session correlator.

  STIX emitted:
    - IPv4-Addr (via builder.build_attacker_context)
    - Sighting (probe of port N)
    - Note if payload is non-trivial (more than 8 bytes printable)

  Substance filter: empty-payload probes get a minimal Sighting only.
  Sessions with > 8 bytes of printable payload get the full graph with
  a Note that preserves the captured bytes.
"""

from __future__ import annotations

import logging
from typing import Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent
from tpot2cti.stix.builder import STIXBuilder
from tpot2cti.stix_ids import generate_ipv4_id

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Threshold (in printable-payload bytes) above which a Honeytrap session
#: is treated as "substantive" and gets the full STIX graph including a
#: Note SDO.  Per V1_SPEC §5.4.
SUBSTANCE_PAYLOAD_THRESHOLD = 8

#: Cap on payload_printable bytes preserved in the Note body.
NOTE_PRINTABLE_CAP = 512

#: Cap on payload_hex bytes preserved in the Note body.
NOTE_HEX_CAP = 256


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class HoneytrapParser(BaseParser):
    """Parser for T-Pot's Honeytrap TCP/UDP catchall honeypot."""

    type_name = "Honeytrap"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert a Honeytrap ES doc into a ParsedEvent.

        Honeytrap nests most of its useful fields under
        `attack_connection` in some T-Pot versions and at top level in
        others; we look in both places.  Returns None for malformed
        docs (missing src_ip or @timestamp).
        """
        # attack_connection holds the per-connection metadata; some fields
        # are duplicated at the top level — prefer top-level then fall back.
        ac = doc.get("attack_connection") or {}
        if not isinstance(ac, dict):
            ac = {}

        src_ip = doc.get("src_ip") or ac.get("src_ip")
        if not src_ip:
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            return None

        dst_port = self._safe_int(doc.get("dst_port") or ac.get("dst_port"))
        proto = (doc.get("proto") or ac.get("protocol") or "").lower() or None

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or doc.get("host", {}).get("name")
                or "unknown"
            ),
            event_type="Honeytrap",
            src_port=self._safe_int(doc.get("src_port") or ac.get("src_port")),
            dst_port=dst_port,
            dst_ip=doc.get("dst_ip") or ac.get("dst_ip"),
            protocol=proto,
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # Payload bytes — store both representations in meta so the
        # builder can preserve them verbatim in the Note.
        payload_printable = (
            doc.get("payload_printable")
            or ac.get("payload_printable")
            or ""
        )
        payload_hex = (
            doc.get("payload_hex")
            or ac.get("payload_hex")
            or ""
        )
        event.meta["payload_printable"] = str(payload_printable)
        event.meta["payload_hex"] = str(payload_hex)
        if ac:
            event.meta["attack_connection"] = ac

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — we use the default (one event per session)
    # ──────────────────────────────────────────────────────────────────
    # Each TCP connection / UDP datagram is a Honeytrap event in its own
    # right; the inherited BaseParser.correlate() wraps each event in a
    # one-event AttackSession, which is exactly what V1_SPEC §5.4 asks
    # for.  No override needed.

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — substance filter per V1_SPEC §5.4
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """A Honeytrap session is substantive iff its single event
        captured more than `SUBSTANCE_PAYLOAD_THRESHOLD` bytes of
        printable payload.

        Empty-payload probes (SYN scans, single-packet UDP touches,
        banner-grab opens with no follow-up) fall through to the
        drive-by code path: IPv4-Addr + GeoIP + AS + IP Indicator +
        Sighting, no Note.
        """
        if not session.events:
            return False
        payload = session.events[0].meta.get("payload_printable") or ""
        return len(payload) > SUBSTANCE_PAYLOAD_THRESHOLD

    # ──────────────────────────────────────────────────────────────────
    # build() — full STIX graph for a substantive session
    # ──────────────────────────────────────────────────────────────────

    def build(self, session: AttackSession, builder: STIXBuilder) -> list[dict]:
        """Build the STIX graph for a substantive Honeytrap session.

        The caller (orchestrator) is expected to have already checked
        `has_substance()` and routed drive-by sessions to
        `builder.build_driveby_session()` instead.  This method assumes
        substance and always emits a Note SDO with the captured
        payload.
        """
        out: list[dict] = []
        if not session.events:
            return out

        event = session.events[0]

        # Foundation: sensor + attacker context (IPv4 + GeoIP + AS)
        out.extend(builder.build_sensor_context(session.sensor_hostname))
        out.extend(builder.build_attacker_context(event))

        ipv4_id = generate_ipv4_id(session.src_ip)

        # IP Indicator + based-on → IPv4 observable
        ip_ind = builder.build_ip_indicator(session.src_ip)
        if ip_ind:
            out.append(ip_ind)
            if rel := builder.build_relationship(
                ip_ind["id"], "based-on", ipv4_id,
                description=f"IP indicator for {session.src_ip}",
            ):
                out.append(rel)

            # Sighting on the IP Indicator
            sighting = builder.build_sighting(
                ip_ind["id"], session.sensor_hostname, session,
                count=session.event_count,
            )
            if sighting:
                out.append(sighting)

        # Note with the captured payload — pinned to the IPv4-Addr so
        # OpenCTI surfaces it on the IP's page (per V1_SPEC §5.4).
        note_body = self._render_note_body(session, event)
        if note_body:
            note = builder.build_session_note(
                session,
                body_md=note_body,
                abstract=(
                    f"Honeytrap payload from {session.src_ip} "
                    f"→ {event.protocol or 'tcp'}/{event.dst_port}"
                ),
                object_refs=[ipv4_id],
            )
            if note:
                out.append(note)

        return out

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _render_note_body(session: AttackSession, event: ParsedEvent) -> str:
        """Format the Note body (markdown) for a substantive session.

        Includes src_ip, dst_port, proto, capped payload_printable and
        payload_hex, and the timestamp.  Caps are applied per
        V1_SPEC §5.4 to keep the bundle small.
        """
        payload_printable = str(event.meta.get("payload_printable") or "")
        payload_hex = str(event.meta.get("payload_hex") or "")

        printable_excerpt = payload_printable[:NOTE_PRINTABLE_CAP]
        printable_truncated = len(payload_printable) > NOTE_PRINTABLE_CAP

        hex_excerpt = payload_hex[:NOTE_HEX_CAP]
        hex_truncated = len(payload_hex) > NOTE_HEX_CAP

        proto = (event.protocol or "tcp").lower()
        dst_port = event.dst_port if event.dst_port is not None else "?"

        lines = [
            f"# Honeytrap payload from `{session.src_ip}`",
            "",
            f"- **src_ip:** `{session.src_ip}`",
            f"- **dst_port:** `{dst_port}`",
            f"- **proto:** `{proto}`",
            f"- **timestamp:** `{event.timestamp.isoformat()}`",
            f"- **sensor:** `{session.sensor_hostname}`",
            "",
            "## payload (printable)",
            "",
            "```",
            printable_excerpt
            + ("\n... [truncated]" if printable_truncated else ""),
            "```",
            "",
            "## payload (hex)",
            "",
            "```",
            hex_excerpt + ("\n... [truncated]" if hex_truncated else ""),
            "```",
        ]
        return "\n".join(lines)

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


# Register on import
register(HoneytrapParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = HoneytrapParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — empty payload ───────────────────────────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Honeytrap",
        "src_ip": "203.0.113.5",
        "src_port": 54321,
        "dst_port": 4444,
        "proto": "tcp",
        "t-pot_hostname": "node1",
        "payload_printable": "",
        "payload_hex": "",
        "geoip": {
            "country_iso_code": "RU",
            "country_name": "Russia",
            "asn": 12345,
            "organization": "ExampleNet",
        },
    }

    # ── Case 2: substantive — HTTP-ish payload on a random port ────────
    substantive_doc = {
        "@timestamp": now.isoformat(),
        "type": "Honeytrap",
        "src_ip": "198.51.100.42",
        "src_port": 33333,
        "dst_port": 8081,
        "proto": "tcp",
        "t-pot_hostname": "node1",
        "payload_printable": "GET / HTTP/1.0\r\nHost: example.com\r\n",
        "payload_hex": "474554202f20485454502f312e300d0a486f73743a206578616d706c652e636f6d0d0a",
        "geoip": {
            "country_iso_code": "CN",
            "country_name": "China",
            "city_name": "Shanghai",
            "asn": 4134,
            "organization": "ChinaNet",
        },
        "attack_connection": {"dst_port": 8081, "protocol": "tcp"},
    }

    # parse + correlate both
    drive_event = parser.parse(driveby_doc)
    subs_event = parser.parse(substantive_doc)
    assert drive_event and subs_event, "parse failed"

    drive_sessions = parser.correlate([drive_event])
    subs_sessions = parser.correlate([subs_event])
    assert len(drive_sessions) == 1 and len(subs_sessions) == 1

    drive_session = drive_sessions[0]
    subs_session = subs_sessions[0]

    drive_has = parser.has_substance(drive_session)
    subs_has = parser.has_substance(subs_session)
    print(f"drive-by has_substance:   {drive_has}  (expected False)")
    print(f"substantive has_substance: {subs_has}  (expected True)")
    assert drive_has is False
    assert subs_has is True

    # Need a Config to build STIX
    os.environ.setdefault("TPOT_HOST", "test")
    os.environ.setdefault("OPENCTI_ADMIN_TOKEN", "00000000-0000-0000-0000-000000000000")
    os.environ.setdefault("TPOT2CTI_CONNECTOR_ID", "00000000-0000-0000-0000-000000000001")
    from tpot2cti.config import load_config

    cfg = load_config()

    # Drive-by: orchestrator would call builder.build_driveby_session()
    builder1 = STIXBuilder(cfg)
    drive_objs = builder1.build_driveby_session(drive_session)
    drive_counts: dict[str, int] = {}
    for o in drive_objs:
        drive_counts[o["type"]] = drive_counts.get(o["type"], 0) + 1
    print(f"\ndrive-by STIX objects ({len(drive_objs)}):")
    for t, n in sorted(drive_counts.items(), key=lambda x: -x[1]):
        print(f"  {t:25s} {n}")

    # Substantive: orchestrator would call parser.build()
    builder2 = STIXBuilder(cfg)
    subs_objs = parser.build(subs_session, builder2)
    subs_counts: dict[str, int] = {}
    for o in subs_objs:
        subs_counts[o["type"]] = subs_counts.get(o["type"], 0) + 1
    print(f"\nsubstantive STIX objects ({len(subs_objs)}):")
    for t, n in sorted(subs_counts.items(), key=lambda x: -x[1]):
        print(f"  {t:25s} {n}")

    # Sanity: the substantive bundle must include a Note
    assert any(o["type"] == "note" for o in subs_objs), "substantive bundle missing Note"
    # And the drive-by bundle must NOT include a Note
    assert not any(o["type"] == "note" for o in drive_objs), "drive-by bundle should have no Note"

    print("\nSmoke test passed.")
