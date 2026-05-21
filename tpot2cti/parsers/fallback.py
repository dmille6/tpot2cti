"""Fallback parser — handles any T-Pot honeypot type without a dedicated parser.

Per V1_SPEC.md §5.24 (Fallback parser):

    For any `type` value not covered above. Ensures **zero data gaps**.

    T-Pot doc fields used:
      src_ip (if present), dst_port (if present), t-pot_hostname (sensor),
      @timestamp, type (recorded in the Note)

    STIX emitted:
      IPv4-Addr (if src_ip present), Sighting, Note containing the raw
      type field + the doc's _source JSON (truncated).

    The fallback parser also emits a `WARNING` log line on every
    unrecognized type so operators see "T-Pot has a new honeypot type
    `<type>` — consider opening an issue for a dedicated parser."

Design notes:

* The registry's ``get_parser()`` falls back to this parser whenever a
  doc's ``type`` field has no dedicated handler, by looking up the
  sentinel key ``FALLBACK_KEY`` (``"__fallback__"``).  This parser's
  ``type_name`` is set to that sentinel.

* ``has_substance()`` is always ``True``.  Even an empty Note giving
  operators visibility into "we saw a doc of unknown type" is more
  useful than silently dropping the event.  The Note's content lets a
  maintainer prioritize adding a dedicated parser when the type proves
  high-value.

* The WARNING log is rate-limited via a module-level set so an
  unrecognized type only logs once per process, not once per event.

* ``src_ip`` is optional here.  When missing we still emit a Note (no
  IPv4-Addr / Sighting), so the unknown event is visible in OpenCTI
  even without an attacker observable to attach to.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from tpot2cti.parsers import FALLBACK_KEY, register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent
from tpot2cti.stix.builder import STIXBuilder
from tpot2cti.stix_ids import generate_ipv4_id, generate_sensor_id

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Truncation cap for the raw doc JSON embedded in the Note body.
#: 4 KB is plenty for an operator to recognize the structure of an
#: unknown honeypot's event without blowing past the per-Note size cap
#: in STIXBuilder (MAX_NOTE_BODY_BYTES = 64 KB).
MAX_RAW_DOC_BYTES = 4 * 1024

#: Placeholder src_ip used when the doc has none.  ``ParsedEvent.src_ip``
#: is a required ``str``; this empty value flows through the builder
#: cleanly because ``build_ipv4()`` rejects strings that don't match
#: its IPv4 regex.
_MISSING_IP = ""

#: One-shot warning tracker — keyed by the unknown ``type`` value.
_warned_types: set[str] = set()


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class FallbackParser(BaseParser):
    """Catch-all parser for unrecognized T-Pot honeypot ``type`` values.

    Registered under the sentinel :data:`FALLBACK_KEY` so that the
    registry's ``get_parser()`` returns it whenever no dedicated parser
    matches a doc's ``type`` field.  Inherits the default one-event-per-
    session correlator from :class:`BaseParser` — fine for unknown
    protocols where we have no idea what (if any) session semantics apply.
    """

    type_name = FALLBACK_KEY

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Parse any T-Pot doc into a generic :class:`ParsedEvent`.

        The doc's ``type`` field is captured in ``event.event_type`` and
        the full ``_source`` is stashed in ``event.raw_doc`` so the
        downstream Note can quote it.  Missing ``src_ip`` is tolerated:
        the event still parses, and the build path will skip the
        IPv4-Addr / Sighting and emit only the Note.

        Returns ``None`` only when ``@timestamp`` is missing /
        unparseable — without a timestamp we can't even build a
        sensible Sighting or Note id, so the doc is skipped.
        """
        unknown_type = str(doc.get("type") or "unknown")

        # Rate-limited warning: log once per process per unknown type.
        if unknown_type not in _warned_types:
            logger.warning(
                f"T-Pot has a new honeypot type {unknown_type!r} — "
                f"consider opening an issue at "
                f"https://github.com/dmille6/tpot2cti/issues for a "
                f"dedicated parser."
            )
            _warned_types.add(unknown_type)

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug(
                f"fallback parser skipping doc with no parseable "
                f"@timestamp (type={unknown_type!r}, _id={doc.get('_id')!r})"
            )
            return None

        src_ip = doc.get("src_ip")
        src_ip_str = str(src_ip) if src_ip else _MISSING_IP

        event = ParsedEvent(
            src_ip=src_ip_str,
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type=unknown_type,
            dst_port=self._safe_int(doc.get("dst_port")),
            raw_doc=dict(doc),
        )

        # If logstash happened to enrich with geoip, take it — costs us
        # nothing and lets the attacker context build correctly when
        # src_ip is present.
        self._populate_geoip(doc, event)

        return event

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — always True
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Always substantive.

        Per V1_SPEC §5.24, the fallback exists specifically to guarantee
        zero data gaps.  Every event of an unknown type contributes
        *something* (at minimum a Note) so operators can see what their
        T-Pot is capturing even before a dedicated parser exists.
        """
        return True

    # ──────────────────────────────────────────────────────────────────
    # build() — produces STIX objects for one fallback session
    # ──────────────────────────────────────────────────────────────────

    def build(self, session: AttackSession, builder: STIXBuilder) -> list[dict]:
        """Build STIX for one unknown-type session.

        Always emits a Note describing the unknown event.  Additionally
        emits IPv4-Addr / IP-Indicator / Sighting / sensor context when
        ``src_ip`` is present.  When ``src_ip`` is missing the Note
        stands alone — better a free-floating Note than no record at all.
        """
        out: list[dict] = []
        if not session.events:
            return out

        first = session.events[0]
        unknown_type = first.event_type

        # Sensor identity is foundation — emit even when there's no IP
        # so the Note can hang off the sensor.
        out.extend(builder.build_sensor_context(session.sensor_hostname))

        ipv4_id: Optional[str] = None
        ip_ind_id: Optional[str] = None

        if first.src_ip:
            # Attacker context (IPv4 + GeoIP + AS + located-at / belongs-to)
            attacker_objs = builder.build_attacker_context(first)
            out.extend(attacker_objs)
            if attacker_objs:
                ipv4_id = generate_ipv4_id(first.src_ip)

            # IP Indicator + based-on → IPv4
            ip_ind = builder.build_ip_indicator(first.src_ip)
            if ip_ind:
                out.append(ip_ind)
                ip_ind_id = ip_ind["id"]
                if ipv4_id:
                    if rel := builder.build_relationship(
                        ip_ind["id"], "based-on", ipv4_id,
                        description=f"IP indicator for {first.src_ip}",
                    ):
                        out.append(rel)

                # Sighting on the IP Indicator — the per-event summary
                # (unknown_type + dst_port) now lives in the Sighting's
                # `description` field. Per LESSONS_LEARNED §7.1 we do NOT
                # emit a separate Note per event for high-volume / low-
                # signal protocols. If a maintainer wants per-event
                # forensics, the raw doc is preserved on T-Pot's ES.
                sighting = builder.build_sighting(
                    ip_ind["id"], session.sensor_hostname, session,
                    count=session.event_count,
                    description=self._render_sighting_description(first, unknown_type),
                )
                if sighting:
                    out.append(sighting)
        else:
            # Edge case: unknown-type event has no src_ip.  Without an IP
            # there is no Sighting to attach a description to — emit a
            # single free-floating Note so the event isn't silently lost.
            # This is the ONE remaining Note-emission path in the fallback
            # parser (LESSONS_LEARNED §7.1 carve-out: per-event Notes for
            # the IP-bearing common case are dropped; the rare no-IP case
            # keeps a Note as the only signal we can surface).
            body = self._render_no_ip_note_body(first, unknown_type)
            note = builder.build_session_note(
                session,
                body_md=body,
                abstract=f"Unrecognized T-Pot event: {unknown_type} (no src_ip)",
                object_refs=[generate_sensor_id(session.sensor_hostname)],
            )
            if note:
                out.append(note)

        return out

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _render_sighting_description(event: ParsedEvent, unknown_type: str) -> str:
        """One-line Sighting.description for unknown T-Pot types.

        Replaces the per-event Note we used to emit. Per LESSONS_LEARNED
        §7.1 we keep low-signal-per-event protocols out of the Notes
        tab. The analyst sees the unknown type in the Sighting context
        and the maintainer's WARNING log triggers the "add a dedicated
        parser" workflow per V1_SPEC §5.24.
        """
        proto = (event.protocol or "?").lower()
        dst = event.dst_port if event.dst_port is not None else "?"
        return (
            f"Unrecognized T-Pot type {unknown_type!r} — "
            f"{proto}/{dst} (consider opening an issue for a dedicated parser)"
        )

    @staticmethod
    def _render_no_ip_note_body(event: ParsedEvent, unknown_type: str) -> str:
        """Markdown body for the rare no-src_ip free-floating Note.

        Called only when an unknown-type event lacks a src_ip — without
        an IP there is no Sighting on which to hang a description, so
        a Note is the only place to surface the event in OpenCTI.
        """
        try:
            raw_pretty = json.dumps(
                event.raw_doc, indent=2, sort_keys=True, default=str,
            )
        except (TypeError, ValueError):
            raw_pretty = repr(event.raw_doc)

        if len(raw_pretty.encode("utf-8")) > MAX_RAW_DOC_BYTES:
            raw_pretty = raw_pretty[:MAX_RAW_DOC_BYTES] + "\n... [truncated]"

        src_ip_disp = event.src_ip or "missing"
        dst_port_disp = str(event.dst_port) if event.dst_port is not None else "missing"
        ts_disp = event.timestamp.isoformat()

        return (
            f"## Unrecognized T-Pot event type: {unknown_type}\n\n"
            f"Captured on sensor: {event.sensor_hostname}\n"
            f"Timestamp: {ts_disp}\n"
            f"Source IP: {src_ip_disp}\n"
            f"Destination port: {dst_port_disp}\n\n"
            f"### Raw event document (truncated)\n"
            f"```json\n{raw_pretty}\n```\n"
        )

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


# Register on import.  The sentinel key makes ``get_parser()`` return
# this instance whenever no dedicated parser matches.
register(FallbackParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = FallbackParser()

    now = datetime.now(timezone.utc)

    # --- Case 1: brand-new honeypot type with src_ip ----------------------
    doc1 = {
        "@timestamp": now.isoformat(),
        "src_ip": "1.2.3.4",
        "dst_port": 4242,
        "t-pot_hostname": "node1",
        "type": "BrandNewHoneypot",
        "weird_field": "some payload",
        "geoip": {
            "country_iso_code": "RU",
            "country_name": "Russia",
            "city_name": "Moscow",
            "asn": 12345,
            "organization": "ExampleNet",
        },
    }

    e1 = parser.parse(doc1)
    assert e1 is not None, "case 1: parse should not return None"
    assert e1.src_ip == "1.2.3.4", "case 1: src_ip captured"
    assert e1.event_type == "BrandNewHoneypot", "case 1: type captured"
    assert e1.dst_port == 4242, "case 1: dst_port captured"
    print(f"case 1: parsed event src_ip={e1.src_ip} type={e1.event_type}")

    sessions1 = parser.correlate([e1])
    assert len(sessions1) == 1, "case 1: one event → one session"
    s1 = sessions1[0]
    assert parser.has_substance(s1), "case 1: fallback always substantive"

    # --- Case 2: same type again — WARNING must NOT re-fire ---------------
    doc2 = {
        "@timestamp": now.isoformat(),
        "src_ip": "5.6.7.8",
        "dst_port": 4242,
        "t-pot_hostname": "node1",
        "type": "BrandNewHoneypot",     # same type as case 1
    }
    warned_before = set(_warned_types)
    e2 = parser.parse(doc2)
    assert e2 is not None, "case 2: parse should not return None"
    assert _warned_types == warned_before, (
        f"case 2: WARNING should fire ONCE per type, but _warned_types changed: "
        f"{warned_before} → {_warned_types}"
    )
    print(f"case 2: _warned_types unchanged ({sorted(_warned_types)})")

    # --- Case 3: different unknown type, NO src_ip ------------------------
    doc3 = {
        "@timestamp": now.isoformat(),
        "t-pot_hostname": "node2",
        "type": "WeirdProtocol",
        "blob": {"foo": "bar"},
    }
    e3 = parser.parse(doc3)
    assert e3 is not None, "case 3: parse should not return None even without src_ip"
    assert e3.src_ip == "", "case 3: missing src_ip → empty string sentinel"
    assert "WeirdProtocol" in _warned_types, "case 3: new type triggers warning"
    print(f"case 3: parsed no-src_ip event type={e3.event_type}")

    # --- Build STIX for all three cases -----------------------------------
    os.environ.setdefault("TPOT_HOST", "test")
    os.environ.setdefault("OPENCTI_ADMIN_TOKEN", "00000000-0000-0000-0000-000000000000")
    os.environ.setdefault("TPOT2CTI_CONNECTOR_ID", "00000000-0000-0000-0000-000000000001")
    from tpot2cti.config import load_config

    cfg = load_config()
    builder = STIXBuilder(cfg)

    # Case 1: full graph (Note + IPv4 + Indicator + Sighting + sensor + geoip)
    objs1 = parser.build(s1, builder)
    types1 = {o["type"] for o in objs1}
    print(f"\ncase 1 built {len(objs1)} STIX objects: {sorted(types1)}")
    assert "ipv4-addr" in types1, "case 1: IPv4-Addr expected when src_ip present"
    assert "indicator" in types1, "case 1: IP Indicator expected"
    assert "sighting" in types1, "case 1: Sighting expected"
    # Post-refactor (LESSONS_LEARNED §7.1): no Note when src_ip present —
    # the per-event summary lives in the Sighting.description instead.
    assert "note" not in types1, (
        "case 1: Note should NOT be emitted when src_ip present "
        "(summary goes in Sighting.description)"
    )
    sighting1 = next(o for o in objs1 if o["type"] == "sighting")
    assert sighting1.get("description"), "case 1: Sighting missing description"
    assert "BrandNewHoneypot" in sighting1["description"], \
        f"case 1: sighting description should name the unknown type, got {sighting1['description']!r}"

    # Case 3: no src_ip — Note IS emitted as the only surface (Sighting
    # can't exist without an IP indicator).
    s3 = parser.correlate([e3])[0]
    objs3 = parser.build(s3, STIXBuilder(cfg))
    types3 = {o["type"] for o in objs3}
    print(f"case 3 built {len(objs3)} STIX objects: {sorted(types3)}")
    assert "ipv4-addr" not in types3, "case 3: no IPv4-Addr without src_ip"
    assert "sighting" not in types3, "case 3: no Sighting without src_ip"
    assert "note" in types3, "case 3: free-floating Note expected without src_ip"

    note3 = next(o for o in objs3 if o["type"] == "note")
    assert "Source IP: missing" in note3["content"]
    assert "Destination port: missing" in note3["content"]

    print("\nSmoke test passed.")
