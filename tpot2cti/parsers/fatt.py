"""FATT parser — passive TLS/SSH fingerprint observations.

FATT (Fingerprint All The Things) is T-Pot's passive fingerprinting
collector — it watches the traffic that hits other honeypots and
emits a separate document per observed JA3 / JA3S / HASSH / HASSHServer
fingerprint.  Because it is purely an observer, FATT doesn't have its
own sessions: it produces a burst of near-identical fingerprint events
for the same attacker IP as their TLS/SSH handshakes complete.  We
correlate those bursts into a single AttackSession using the time-
window correlator (default 300s, mirroring the V0 importer per
docs/LESSONS_LEARNED_FROM_V0.md §6).

Per V1_SPEC.md §5.20:

  T-Pot doc fields used:
    src_ip, dst_ip, dst_port,
    fatt.ja3, fatt.ja3s, fatt.hassh, fatt.hasshServer,
    fatt.tlsClient, fatt.tlsServer

  Event correlation:
    `correlate_by_window` with a 300s gap — FATT fires once per
    handshake observed, but a single attacker often produces multiple
    handshakes (retries, multi-port scans, parallel connects) in
    quick succession.  Grouping them into one AttackSession lets the
    downstream STIX builder emit one Cryptographic-Key per unique
    fingerprint per attacker, not one per redundant emission.

  Substance filter:
    Substantive iff ANY fingerprint field (ja3, ja3s, hassh,
    hasshServer) is non-empty on at least one event in the session.
    A FATT doc with all four fingerprint fields blank carries no
    information beyond what the upstream honeypot already gives us,
    so it routes to the drive-by Sighting path.

  Aggregator policy:
    We keep the FIRST non-empty value seen across the window for
    each of ja3 / ja3s / hassh / hasshServer.  FATT often re-emits
    the same fingerprint repeatedly (one doc per connection in the
    burst); the first observation is sufficient and additional ones
    would be duplicates.  The corresponding session fields
    (`session.ja3`, `session.ja3s`, `session.hassh`) are populated
    directly; `hasshServer` and the human-readable `tlsClient` /
    `tlsServer` strings live on `session.meta`.

  STIX emitted (by the orchestrator from session state):
    - IPv4-Addr (via builder.build_attacker_context)
    - Cryptographic-Key per unique fingerprint (JA3, JA3S, HASSH,
      HASSHServer) — see docs/LESSONS_LEARNED_FROM_V0.md §8.4 for
      the correct STIX type slug ("cryptographic-key", NOT
      "x-opencti-cryptographic-key")
    - Sighting on the IP Indicator
"""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent
from tpot2cti.session import correlate_by_window

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Window (seconds) within which FATT events from the same attacker are
#: grouped into a single AttackSession.  Matches the V0 importer's
#: `max_gap_seconds: 300` (LESSONS §6) and the project-wide default in
#: `correlate_by_window`.
FATT_WINDOW_SECONDS = 300


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class FattParser(BaseParser):
    """Parser for T-Pot's FATT passive fingerprinting collector."""

    type_name = "Fatt"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert one FATT ES doc into a ParsedEvent.

        FATT nests its fingerprint output under a `fatt` sub-object in
        the canonical T-Pot mapping, but some older installs flatten
        the fields to the top level.  We look in both places so the
        parser is robust across T-Pot versions.

        Returns None for docs missing src_ip or @timestamp (per
        V1_SPEC §7 — caller logs at DEBUG, skips the doc, continues).
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("fatt: doc missing src_ip; skipping")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("fatt: doc missing/unparseable @timestamp; skipping")
            return None

        # Fingerprints may be nested under `fatt` or flattened to top
        # level depending on T-Pot version.  Prefer nested.
        fatt = doc.get("fatt") or {}
        if not isinstance(fatt, dict):
            fatt = {}

        ja3 = self._first_str(fatt.get("ja3"), doc.get("ja3"))
        ja3s = self._first_str(fatt.get("ja3s"), doc.get("ja3s"))
        hassh = self._first_str(fatt.get("hassh"), doc.get("hassh"))
        hassh_server = self._first_str(
            fatt.get("hasshServer"), doc.get("hasshServer")
        )
        tls_client = self._first_str(fatt.get("tlsClient"), doc.get("tlsClient"))
        tls_server = self._first_str(fatt.get("tlsServer"), doc.get("tlsServer"))

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="Fatt",
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int(doc.get("dst_port") or doc.get("dest_port")),
            dst_ip=doc.get("dst_ip") or doc.get("dest_ip"),
            protocol=self._derive_protocol(ja3 or ja3s, hassh or hassh_server),
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # Stash all four fingerprint fields plus the tlsClient / tlsServer
        # human-readable strings in meta so the aggregator (and any
        # downstream consumer) can introspect without reaching into the
        # raw_doc.
        if ja3:
            event.meta["ja3"] = ja3
        if ja3s:
            event.meta["ja3s"] = ja3s
        if hassh:
            event.meta["hassh"] = hassh
        if hassh_server:
            event.meta["hasshServer"] = hassh_server
        if tls_client:
            event.meta["tlsClient"] = tls_client
        if tls_server:
            event.meta["tlsServer"] = tls_server

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — group FATT bursts via the window correlator
    # ──────────────────────────────────────────────────────────────────

    def correlate(self, events: Iterable[ParsedEvent]) -> list[AttackSession]:
        """Group events from the same `(src_ip, sensor)` within a
        FATT_WINDOW_SECONDS gap into a single AttackSession.

        See `tpot2cti.session.correlator.correlate_by_window` for the
        burst-extension semantics (the window resets each time a new
        event lands within the gap).
        """
        return correlate_by_window(
            events,
            window_seconds=FATT_WINDOW_SECONDS,
            aggregator=self._aggregate_session,
        )

    def _aggregate_session(
        self, session: AttackSession, events: list[ParsedEvent]
    ) -> None:
        """Populate session fingerprint fields from per-event meta.

        FATT re-emits the same fingerprint each time a handshake
        completes, so we keep the FIRST non-empty observation for each
        of ja3 / ja3s / hassh / hasshServer.  Per-event order is
        ascending by timestamp (correlator guarantee).
        """
        for e in events:
            meta = e.meta
            if not session.ja3 and (v := meta.get("ja3")):
                session.ja3 = str(v)
            if not session.ja3s and (v := meta.get("ja3s")):
                session.ja3s = str(v)
            if not session.hassh and (v := meta.get("hassh")):
                session.hassh = str(v)
            if "hasshServer" not in session.meta and (v := meta.get("hasshServer")):
                session.meta["hasshServer"] = str(v)
            if "tlsClient" not in session.meta and (v := meta.get("tlsClient")):
                session.meta["tlsClient"] = str(v)
            if "tlsServer" not in session.meta and (v := meta.get("tlsServer")):
                session.meta["tlsServer"] = str(v)

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — at least one non-empty fingerprint
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """A FATT session is substantive iff we captured at least one
        of the four fingerprint values (JA3, JA3S, HASSH, HASSHServer).

        FATT docs with all four blank carry no information beyond what
        the underlying honeypot already provided — they route to the
        one-Sighting drive-by code path per V1_SPEC §5.20 +
        docs/LESSONS_LEARNED_FROM_V0.md §2.
        """
        return bool(
            session.ja3
            or session.ja3s
            or session.hassh
            or session.meta.get("hasshServer")
        )

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _first_str(*candidates) -> Optional[str]:
        """Return the first non-empty stringified candidate, else None."""
        for c in candidates:
            if c not in (None, "", [], {}):
                return str(c)
        return None

    @staticmethod
    def _derive_protocol(
        has_tls_fp: Optional[str], has_ssh_fp: Optional[str]
    ) -> Optional[str]:
        """Best-effort protocol label from which fingerprint family
        fired.  JA3/JA3S → tls; HASSH/HASSHServer → ssh.  Both or
        neither → None (let the dst_port speak for itself)."""
        if has_tls_fp and not has_ssh_fp:
            return "tls"
        if has_ssh_fp and not has_tls_fp:
            return "ssh"
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
register(FattParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timedelta, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = FattParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — all fingerprint fields empty ───────────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Fatt",
        "src_ip": "203.0.113.30",
        "src_port": 55555,
        "dst_port": 443,
        "t-pot_hostname": "node1",
        "fatt": {},
        "geoip": {"country_iso_code": "US", "asn": 64500},
    }

    # ── Case 2: substantive — three FATT events for the same attacker,
    #    bursting within the 300s window.  First two carry JA3+JA3S
    #    (TLS handshake), third carries HASSH (SSH handshake on another
    #    port from the same attacker).  Verify FIRST non-empty wins.
    base = {
        "type": "Fatt",
        "src_ip": "198.51.100.50",
        "src_port": 41111,
        "t-pot_hostname": "node1",
        "geoip": {"country_iso_code": "CN", "asn": 4134},
    }
    docs = [
        {**base,
         "@timestamp": now.isoformat(),
         "dst_port": 443,
         "fatt": {
             "ja3": "771,4865-4866-4867,0-23-65281",
             "ja3s": "771,4865",
             "tlsClient": "Chrome/120",
         }},
        {**base,
         "@timestamp": (now + timedelta(seconds=30)).isoformat(),
         "dst_port": 443,
         # Different ja3 — but the aggregator MUST keep the first.
         "fatt": {
             "ja3": "771,SHOULD-NOT-OVERRIDE",
             "ja3s": "771,SHOULD-NOT-OVERRIDE",
         }},
        {**base,
         "@timestamp": (now + timedelta(seconds=60)).isoformat(),
         "dst_port": 22,
         "fatt": {
             "hassh": "0a1b2c3d4e5f6789abcdef",
             "hasshServer": "deadbeefcafef00d",
         }},
    ]

    # parse all
    drive_ev = parser.parse(driveby_doc)
    burst_evs = [parser.parse(d) for d in docs]
    assert drive_ev is not None
    assert all(e is not None for e in burst_evs)

    # correlate
    drive_sessions = parser.correlate([drive_ev])
    burst_sessions = parser.correlate(burst_evs)
    assert len(drive_sessions) == 1, f"got {len(drive_sessions)}"
    assert len(burst_sessions) == 1, (
        f"FATT burst should fold into 1 session, got {len(burst_sessions)}"
    )

    drive_s = drive_sessions[0]
    burst_s = burst_sessions[0]

    # has_substance assertions
    assert parser.has_substance(drive_s) is False, "empty-fp must be drive-by"
    assert parser.has_substance(burst_s) is True, "burst with fp must be substantive"

    # FIRST non-empty wins for each fp field
    assert burst_s.ja3 == "771,4865-4866-4867,0-23-65281", (
        f"ja3 first-wins broken: got {burst_s.ja3!r}"
    )
    assert burst_s.ja3s == "771,4865", f"ja3s first-wins broken: got {burst_s.ja3s!r}"
    assert burst_s.hassh == "0a1b2c3d4e5f6789abcdef"
    assert burst_s.meta.get("hasshServer") == "deadbeefcafef00d"
    assert burst_s.meta.get("tlsClient") == "Chrome/120"

    print("OK")
