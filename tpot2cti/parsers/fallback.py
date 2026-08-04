"""Fallback parser — handles any T-Pot honeypot type without a dedicated parser.

See docs/parsers/fallback.md for protocol/ES-field/STIX/substance notes.
"""

from __future__ import annotations

import logging
from typing import Optional

from tpot2cti.parsers import FALLBACK_KEY, register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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
            dst_port=self._safe_int((doc.get("dest_port") or doc.get("dst_port"))),
            raw_doc=dict(doc),
        )

        # If logstash happened to enrich with geoip, take it — costs us
        # nothing and lets the attacker context build correctly when
        # src_ip is present.
        self._populate_geoip(doc, event)

        return event
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


# Register on import.  The sentinel key makes ``get_parser()`` return
# this instance whenever no dedicated parser matches.
register(FallbackParser())
