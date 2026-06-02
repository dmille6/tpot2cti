"""ADBhoney parser — Android Debug Bridge honeypot (port 5555).

See docs/parsers/adbhoney.md for protocol/ES-field/STIX/substance notes.
"""

from __future__ import annotations

import logging
import re
from typing import Iterable, Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Hex-only regex used to validate ``data_sha256`` before pushing it
#: into ``session.malware_hashes``.  We don't enforce length here (the
#: field name tells us it's sha256) — we just want to reject obvious
#: garbage like "n/a" or quote-wrapped values.
_HEX_RE = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)

#: ADBhoney device-info fields we preserve in meta when present.  These
#: are not "substance" signals (they don't gate has_substance), but
#: they're handy for the Note body and downstream analytics.
_DEVICE_INFO_FIELDS: tuple[str, ...] = (
    "device_serial",
    "device_model",
    "device_id",
    "system_property",
    "shell_id",
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class AdbhoneyParser(BaseParser):
    """Parser for T-Pot's ADBhoney Android Debug Bridge honeypot."""

    type_name = "Adbhoney"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert an ADBhoney ES doc into a normalized :class:`ParsedEvent`.

        Pulls the attacker-issued ``command`` (if any), the captured
        binary's ``data_sha256`` (if a file was uploaded), and any
        device-info fields the attacker leaked while interacting with
        the fake ADB shell.

        Returns ``None`` (logged at DEBUG) when the doc has no
        ``src_ip`` or no parseable ``@timestamp`` — without those we
        cannot build a sensible Sighting.
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("adbhoney: skipping doc with no src_ip")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug(
                f"adbhoney: skipping doc with unparseable @timestamp "
                f"(_id={doc.get('_id')!r})"
            )
            return None

        # ADBhoney is single-port: 5555.  T-Pot may still populate
        # dst_port, so we respect it but default to 5555 in meta.
        dst_port = self._safe_int((doc.get("dest_port") or doc.get("dst_port"))) or 5555

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="Adbhoney",
            session_id=doc.get("session") or doc.get("session_id"),
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=dst_port,
            dst_ip=(doc.get("dest_ip") or doc.get("dst_ip")),
            protocol="adb",
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── Command issued through the fake ADB shell ──────────────────
        if cmd := doc.get("command"):
            event.meta["command"] = str(cmd)

        # ── Uploaded data — captured as a sha256 reference ─────────────
        if (data_sha256 := doc.get("data_sha256")):
            h = str(data_sha256).strip().lower()
            if _HEX_RE.match(h):
                event.meta["data_sha256"] = h
            else:
                logger.debug(
                    f"adbhoney: ignoring non-hex data_sha256={data_sha256!r} "
                    f"on src_ip={src_ip}"
                )

        # ── Device-info fields (anything the attacker poked at) ────────
        for fld in _DEVICE_INFO_FIELDS:
            if (v := doc.get(fld)) not in (None, "", [], {}):
                event.meta[fld] = v

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — one event per session + promote hashes / commands
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events: Iterable[ParsedEvent]) -> list[AttackSession]:
        """Wrap each event in a one-event :class:`AttackSession` and
        promote ``data_sha256`` to ``session.malware_hashes`` /
        ``command`` to ``session.commands`` so the orchestrator and
        STIX builder read uniformly-populated session fields.
        """
        sessions: list[AttackSession] = []
        for event in events:
            session = AttackSession.from_event(event)
            self._aggregate_session(session, [event])
            sessions.append(session)
        return sessions

    @staticmethod
    def _aggregate_session(
        session: AttackSession, events: list[ParsedEvent],
    ) -> None:
        """Promote per-event ADBhoney fields to session aggregates."""
        for e in events:
            meta = e.meta

            if (h := meta.get("data_sha256")):
                if h not in session.malware_hashes:
                    session.malware_hashes.append(h)

            if (cmd := meta.get("command")):
                if cmd not in session.commands:
                    session.commands.append(cmd)

            # Mirror device-info onto session.meta for the Note builder.
            for fld in _DEVICE_INFO_FIELDS:
                if fld in meta:
                    session.meta.setdefault(fld, meta[fld])

            # Also mirror the primary keys so the STIX builder doesn't
            # need to reach into events[0].meta.
            for k in ("command", "data_sha256"):
                if k in meta:
                    session.meta.setdefault(k, meta[k])

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — always True for ADBhoney
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Always True.

        Port 5555 ADB on the open internet is inherently malicious —
        there is no legitimate reason for a connection to land on the
        honeypot — so every ADBhoney session warrants the full SDO
        graph.  This is the deliberate exception to LESSONS §2's
        "drive-by probes get only a Sighting" rule.

        We override (rather than inherit BaseParser.has_substance's
        default-True) so the deviation from the general substance-
        filter convention is explicit at the parser level.
        """
        return True

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
register(AdbhoneyParser())
