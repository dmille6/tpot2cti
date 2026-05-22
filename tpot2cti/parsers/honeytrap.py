"""Honeytrap parser — TCP/UDP catchall honeypot.

Honeytrap is T-Pot's default-route catchall: anything that hits a
port no other honeypot is listening on lands here.  Most of what we
see is one-packet probes from internet background radiation — a SYN,
a banner grab, an empty UDP packet — but occasionally an attacker
actually sends an exploit payload to a non-honeypotted port and that
payload is worth preserving.

Per PoC LESSONS §32, this parser stays pure (model-only):
parse() + has_substance() only.  The per-protocol STIX shape lives in
``STIXBuilder.build_honeytrap_probe``.

Per V1_SPEC.md §5.4:

  T-Pot doc fields used:
    src_ip, dst_port, proto, payload_hex, payload_printable,
    attack_connection (metadata)

  Event correlation: each TCP connection or UDP datagram is one event.
  We use the default one-event-per-session correlator.

  STIX emitted (by the builder):
    - IPv4-Addr (via builder.build_attacker_context)
    - Sighting (probe of port N) with payload summary in description

  Substance filter: empty-payload probes get a minimal Sighting only.
  Sessions with > 8 bytes of printable payload get the full graph with
  a Sighting description that preserves the captured bytes.
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

#: Threshold (in printable-payload bytes) above which a Honeytrap session
#: is treated as "substantive" and gets the full STIX graph including a
#: Sighting with payload preview in its description.  Per V1_SPEC §5.4.
SUBSTANCE_PAYLOAD_THRESHOLD = 8


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

        # T-Pot Honeytrap docs use `dest_port` / `dest_ip` (live ES sample
        # 2026-05-22), NOT `dst_port` / `dst_ip`. Earlier parser code
        # missed this and Sighting descriptions showed `tcp/?` for every
        # Honeytrap probe. Accept both spellings + the nested
        # `attack_connection.*` shape for cross-version safety.
        dst_port = self._safe_int(
            doc.get("dest_port")
            or doc.get("dst_port")
            or ac.get("dest_port")
            or ac.get("dst_port")
        )
        dst_ip = (
            doc.get("dest_ip")
            or doc.get("dst_ip")
            or ac.get("dest_ip")
            or ac.get("dst_ip")
        )
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
            dst_ip=dst_ip,
            protocol=proto,
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # Payload bytes — store both representations in meta so the
        # builder can preserve them verbatim in the Sighting description.
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
        Sighting, no payload preview.
        """
        if not session.events:
            return False
        payload = session.events[0].meta.get("payload_printable") or ""
        return len(payload) > SUBSTANCE_PAYLOAD_THRESHOLD

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

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

    # Need a Config to build STIX. Per refactor, the orchestrator dispatches
    # substantive Honeytrap sessions to builder.build_honeytrap_probe(s).
    from tpot2cti.parsers.base import _smoketest_env
    _smoketest_env()
    from tpot2cti.config import load_config
    from tpot2cti.stix.builder import STIXBuilder

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

    # Substantive: orchestrator would call builder.build_honeytrap_probe()
    builder2 = STIXBuilder(cfg)
    subs_objs = builder2.build_honeytrap_probe(subs_session)
    subs_counts: dict[str, int] = {}
    for o in subs_objs:
        subs_counts[o["type"]] = subs_counts.get(o["type"], 0) + 1
    print(f"\nsubstantive STIX objects ({len(subs_objs)}):")
    for t, n in sorted(subs_counts.items(), key=lambda x: -x[1]):
        print(f"  {t:25s} {n}")

    # Per LESSONS_LEARNED §7.1 (post-refactor): Honeytrap no longer emits
    # a per-probe Note. The per-probe summary now lives on the Sighting's
    # `description` field. Verify both ends of the contract.
    assert not any(o["type"] == "note" for o in subs_objs), (
        "Honeytrap should NOT emit Notes anymore — summary goes in "
        "Sighting.description per LESSONS_LEARNED §7.1"
    )
    sightings = [o for o in subs_objs if o["type"] == "sighting"]
    assert sightings, "substantive bundle missing Sighting"
    assert sightings[0].get("description"), \
        "Sighting must carry a per-probe description string"
    assert "Honeytrap probe" in sightings[0]["description"], \
        f"unexpected sighting description: {sightings[0]['description']!r}"
    # Drive-by bundle still has no Note (unchanged from before)
    assert not any(o["type"] == "note" for o in drive_objs), \
        "drive-by bundle should have no Note"

    print("\nSmoke test passed.")
