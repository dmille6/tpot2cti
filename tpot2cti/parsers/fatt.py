"""FATT parser — passive TLS/SSH fingerprint observations.

See docs/parsers/fatt.md for protocol/ES-field/STIX/substance notes.
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

        # Per 2026-05-22 field-name audit vs real ES exports:
        # T-Pot ships FATT fingerprints under per-protocol containers,
        # NOT a single `fatt` dict and NOT flat top-level.  Real shape:
        #
        #   fatt_ssh:  {hassh, hasshServer, hasshAlgorithms,
        #               hasshServerAlgorithms, client, server, ...}      (~51%)
        #   fatt_tls:  {ja3, ja3s, ja3Algorithms, serverName, ...}        (~38%)
        #   fatt_http: {userAgent, requestURI, requestMethod,
        #               clientHeaderHash, serverHeaderHash, ...}          (~12%)
        #
        # The legacy nested `fatt` and flat top-level reads remain as
        # fallbacks for older T-Pot installs (no real data triggers them
        # at audit time, but they're cheap insurance).
        fatt_ssh = doc.get("fatt_ssh") or {}
        fatt_tls = doc.get("fatt_tls") or {}
        fatt_http = doc.get("fatt_http") or {}
        if not isinstance(fatt_ssh, dict):
            fatt_ssh = {}
        if not isinstance(fatt_tls, dict):
            fatt_tls = {}
        if not isinstance(fatt_http, dict):
            fatt_http = {}
        # Legacy single-container shape (kept for cross-version safety)
        fatt = doc.get("fatt") or {}
        if not isinstance(fatt, dict):
            fatt = {}

        ja3 = self._first_str(
            fatt_tls.get("ja3"), fatt.get("ja3"), doc.get("ja3"),
        )
        ja3s = self._first_str(
            fatt_tls.get("ja3s"), fatt.get("ja3s"), doc.get("ja3s"),
        )
        hassh = self._first_str(
            fatt_ssh.get("hassh"), fatt.get("hassh"), doc.get("hassh"),
        )
        hassh_server = self._first_str(
            fatt_ssh.get("hasshServer"), fatt.get("hasshServer"),
            doc.get("hasshServer"),
        )
        # The human-readable client/server banner strings live alongside
        # the hash. SSH path: fatt_ssh.{client, server}; TLS path:
        # fatt_tls.serverName (server only — TLS has no client banner).
        tls_client = self._first_str(
            fatt_ssh.get("client"), fatt.get("tlsClient"), doc.get("tlsClient"),
        )
        tls_server = self._first_str(
            fatt_ssh.get("server"), fatt_tls.get("serverName"),
            fatt.get("tlsServer"), doc.get("tlsServer"),
        )
        # HTTP fingerprint surface (audit-#1 finding — was completely
        # absent before): userAgent + clientHeaderHash give us per-tool
        # identification on HTTP attackers FATT observed via mirror.
        http_user_agent = self._first_str(fatt_http.get("userAgent"))
        http_client_hash = self._first_str(fatt_http.get("clientHeaderHash"))

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
        if http_user_agent:
            event.meta["http_user_agent"] = http_user_agent
        if http_client_hash:
            event.meta["http_client_hash"] = http_client_hash

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
