"""Dionaea parser — binary-catching honeypot (SMB / FTP / HTTP / MS-SQL / MySQL).

Dionaea's whole reason for existing is to *catch the binary*: it accepts a
file drop over one of its emulated services and writes the bytes to disk
under a sha256-derived path.  T-Pot emits one ES document per
connection — and for connections that actually drop a payload the doc
carries the hashes (sha256 / md5 / sha1), the size, and (when the
attacker fetched the binary from somewhere) the download_url.

Per V1_SPEC.md §5.3:

  T-Pot doc fields used:
    src_ip, dst_port, protocol,
    sha256, md5, sha1, size_bytes,
    download_url (if applicable),
    connection_protocol (smbd, ftpd, etc.)

  STIX emitted (later, by the orchestrator):
    IPv4-Addr, StixFile (with all available hashes),
    URL (if download_url present), Indicator(file), Sighting.

  Relationships: same as Cowrie file paths.

  Event correlation: each binary drop / connection is its own event.
  We inherit BaseParser.correlate() (one-event-per-session) — there's
  no Dionaea-wide session id to group on, and each captured connection
  is independently interesting.

Substance filter (per docs/LESSONS_LEARNED_FROM_V0.md §2):

  Dionaea is loud — port-scanners and SMB worms slam port 445 all day
  and most of those connections drop NO bytes at all.  The single signal
  that separates noise from substance is whether we actually *captured a
  binary* (or at least learned of a URL to fetch one from).  We treat a
  session as substantive iff any of:

    - sha256 is present
    - md5 is present
    - sha1 is present
    - download_url is present

  Everything else is a drive-by handshake and gets the minimal Sighting.

The hashes we extract are pushed to ``session.malware_hashes`` as
lowercase hex strings; the download_url goes to ``session.urls``; the
download_url's hostname goes to ``session.domains`` (when it parses as
a hostname rather than a bare IPv4 literal).
"""

from __future__ import annotations

import logging
import re
from typing import Iterable, Optional
from urllib.parse import urlparse

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Hex-only regex used to validate hash candidates before pushing them
#: to ``session.malware_hashes`` / ``meta.all_hashes``.  Length is *not*
#: enforced here — the field key ("sha256" vs "md5") tells us how long
#: each hash is expected to be; we just want to reject obvious garbage
#: (whitespace, "n/a", quote-wrapped values that crept in via logstash).
_HEX_RE = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)

#: Bare-IPv4 sniffer used to decide whether to push a download_url's host
#: to ``session.domains``.  We only push hostnames; IPv4 literals would
#: duplicate the IPv4-Addr observable the attacker already maps to.
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class DionaeaParser(BaseParser):
    """Parser for T-Pot's Dionaea binary-catching honeypot."""

    type_name = "Dionaea"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        """Convert a Dionaea ES doc into a normalized :class:`ParsedEvent`.

        Returns ``None`` (and logs at DEBUG) for malformed docs that
        either have no ``src_ip`` or no parseable ``@timestamp`` — we
        cannot emit a sensible Sighting / IPv4-Addr without those.

        All Dionaea-specific fields (hashes, download_url, size,
        connection_protocol) live under ``event.meta`` so the substance
        filter can see them and the STIX builder can quote them verbatim.
        """
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("dionaea: skipping doc with no src_ip")
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug(
                f"dionaea: skipping doc with unparseable @timestamp "
                f"(_id={doc.get('_id')!r})"
            )
            return None

        # T-Pot's Dionaea docs carry the application protocol (smbd /
        # ftpd / httpd / mysqld / etc.) under `connection.protocol` —
        # strictly more informative than the L4 transport.
        # Per 2026-05-22 field-name audit vs real ES exports: real data
        # always uses `connection.protocol` (nested); the flat
        # `connection_protocol` and `protocol` spellings never appear.
        # Legacy flat reads kept as fallback for older T-Pot versions.
        conn = doc.get("connection") if isinstance(doc.get("connection"), dict) else {}
        connection_protocol = (
            conn.get("protocol")
            or doc.get("connection_protocol")
            or doc.get("protocol")
            or None
        )
        protocol_str = str(connection_protocol).lower() if connection_protocol else None

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="Dionaea",
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int((doc.get("dest_port") or doc.get("dst_port"))),
            dst_ip=(doc.get("dest_ip") or doc.get("dst_ip")),
            protocol=protocol_str,
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── Hashes ─────────────────────────────────────────────────────
        # Dionaea's canonical ELK shape (per the dionaea.download.complete
        # event) puts sha256/md5/sha1 at the top level of the doc.  Per
        # 2026-05-22 audit #14 we also defensively read the nested
        # ``connection.payload.*_hash`` / ``proxy_connection.payload.*_hash``
        # paths used by some T-Pot versions when Dionaea emits via the
        # connection-level payload event instead of the dedicated download
        # event.  Hex-validated + lowercased before stashing so the
        # downstream STIX File / Indicator builders never see garbage.
        conn = doc.get("connection") or {}
        proxy = doc.get("proxy_connection") or {}
        conn_payload = conn.get("payload") if isinstance(conn, dict) else None
        proxy_payload = proxy.get("payload") if isinstance(proxy, dict) else None
        conn_payload = conn_payload if isinstance(conn_payload, dict) else {}
        proxy_payload = proxy_payload if isinstance(proxy_payload, dict) else {}

        all_hashes: dict[str, str] = {}
        for algo in ("sha256", "md5", "sha1"):
            raw = (
                doc.get(algo)
                or conn_payload.get(f"{algo}_hash")
                or proxy_payload.get(f"{algo}_hash")
            )
            if not raw:
                continue
            h = str(raw).strip().lower()
            if not _HEX_RE.match(h):
                logger.debug(
                    f"dionaea: ignoring non-hex {algo}={raw!r} on "
                    f"src_ip={src_ip}"
                )
                continue
            all_hashes[algo] = h
        if all_hashes:
            event.meta["all_hashes"] = all_hashes
            # Primary hash for ``session.malware_hashes`` — prefer
            # sha256, then sha1, then md5.  has_substance() and the
            # downstream File builder both key off this.
            for preferred in ("sha256", "sha1", "md5"):
                if preferred in all_hashes:
                    event.meta["primary_hash"] = all_hashes[preferred]
                    event.meta["primary_hash_algo"] = preferred
                    break

        # ── Download URL ───────────────────────────────────────────────
        # Some Dionaea drops happen via a wget/curl-style fetch the
        # attacker triggered through the emulated service; the URL is
        # captured under ``download_url`` (or occasionally ``url``).
        if dl_url := (doc.get("download_url") or doc.get("url")):
            event.meta["download_url"] = str(dl_url)

        # ── Misc fields preserved for the Note / File builder ──────────
        if (size_bytes := self._safe_int(doc.get("size_bytes"))) is not None:
            event.meta["size_bytes"] = size_bytes
        if connection_protocol:
            event.meta["connection_protocol"] = str(connection_protocol)

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — one event per session (default behavior)
    # ──────────────────────────────────────────────────────────────────
    #
    # We override only to attach session.malware_hashes / urls / domains
    # from the lone event's meta, so downstream has_substance() and the
    # STIX builder see a uniformly-populated session.

    def correlate(self, events: Iterable[ParsedEvent]) -> list[AttackSession]:
        """Wrap each event in a one-event :class:`AttackSession` and
        promote per-event Dionaea metadata to the session aggregates.

        Dionaea has no protocol session id — each captured connection /
        binary drop is its own event and own session — but we still
        want ``session.malware_hashes``, ``session.urls`` and
        ``session.domains`` populated so :meth:`has_substance` and the
        STIX builder don't need to reach into ``events[0].meta``.
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
        """Promote per-event Dionaea fields to session aggregates."""
        for e in events:
            meta = e.meta

            # Push the primary hash to malware_hashes (lowercase hex).
            if (primary := meta.get("primary_hash")):
                if primary not in session.malware_hashes:
                    session.malware_hashes.append(primary)

            # Push the download_url to session.urls; derive a domain.
            if (url := meta.get("download_url")):
                if url not in session.urls:
                    session.urls.append(url)
                try:
                    host = urlparse(url).hostname
                except Exception as ex:
                    logger.debug(
                        f"dionaea: failed to urlparse {url!r}: {ex}"
                    )
                    host = None
                # Only push real hostnames, not bare IPv4 literals
                # (those are already attacker / dst observables).
                if host and not _IPV4_RE.match(host):
                    if host not in session.domains:
                        session.domains.append(host)

            # Mirror the full hash map onto session.meta so the STIX
            # builder can attach md5 / sha1 to the File SCO when sha256
            # is present.
            if (all_hashes := meta.get("all_hashes")):
                existing = session.meta.setdefault("all_hashes", {})
                for algo, h in all_hashes.items():
                    existing.setdefault(algo, h)

            # Connection protocol + size bytes — handy for the Note.
            if cp := meta.get("connection_protocol"):
                session.meta.setdefault("connection_protocol", cp)
            if (sz := meta.get("size_bytes")) is not None:
                session.meta.setdefault("size_bytes", sz)

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — the LESSONS §2 substance filter
    # ──────────────────────────────────────────────────────────────────

    def has_substance(self, session: AttackSession) -> bool:
        """Per V1_SPEC §5.3 / LESSONS §2: a Dionaea session is
        substantive iff we actually captured *content* — either a
        binary (any of sha256 / md5 / sha1) or a download URL pointing
        at one.  Bare connect-and-drop probes (the dominant signal on
        port 445) get the drive-by treatment.
        """
        if session.malware_hashes:
            return True
        if session.urls:
            return True
        # Defensive: also check meta.all_hashes directly in case the
        # aggregator path was skipped for some reason.
        all_hashes = session.meta.get("all_hashes") or {}
        if isinstance(all_hashes, dict) and any(all_hashes.values()):
            return True
        return False

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
register(DionaeaParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = DionaeaParser()
    now = datetime.now(timezone.utc)

    # ── Case 1: drive-by — SMB connection, no binary captured ──────────
    driveby_doc = {
        "@timestamp": now.isoformat(),
        "type": "Dionaea",
        "src_ip": "203.0.113.7",
        "src_port": 41001,
        "dst_port": 445,
        "connection_protocol": "smbd",
        "t-pot_hostname": "node1",
        "geoip": {
            "country_iso_code": "CN",
            "country_name": "China",
            "asn": 4134,
            "organization": "ChinaNet",
        },
    }

    # ── Case 2: substantive — binary captured, hashes + URL present ────
    substantive_doc = {
        "@timestamp": now.isoformat(),
        "type": "Dionaea",
        "src_ip": "198.51.100.99",
        "src_port": 33222,
        "dst_port": 445,
        "connection_protocol": "smbd",
        "t-pot_hostname": "node1",
        "sha256": "AABBCCDDEEFF" + "00" * 26,    # 64 hex chars
        "md5": "11223344556677889900aabbccddeeff",
        "sha1": "0123456789abcdef0123456789abcdef01234567",
        "size_bytes": 142336,
        "download_url": "http://malware.example.com/payload.exe",
        "geoip": {
            "country_iso_code": "RU",
            "country_name": "Russia",
            "asn": 12345,
            "organization": "ExampleNet",
        },
    }

    drive_event = parser.parse(driveby_doc)
    subs_event = parser.parse(substantive_doc)
    assert drive_event and subs_event, "parse failed"

    drive_session = parser.correlate([drive_event])[0]
    subs_session = parser.correlate([subs_event])[0]

    drive_has = parser.has_substance(drive_session)
    subs_has = parser.has_substance(subs_session)
    print(f"drive-by    has_substance: {drive_has}  (expected False)")
    print(f"substantive has_substance: {subs_has}  (expected True)")
    assert drive_has is False, "drive-by Dionaea must be non-substantive"
    assert subs_has is True, "Dionaea drop with hash+URL must be substantive"

    # The substantive session must carry the primary hash, URL, and
    # derived domain in the session aggregates the orchestrator reads.
    assert subs_session.malware_hashes, "primary hash should be promoted"
    assert subs_session.urls == ["http://malware.example.com/payload.exe"]
    assert subs_session.domains == ["malware.example.com"]
    assert subs_session.meta.get("all_hashes", {}).get("md5"), "md5 in meta.all_hashes"
    assert subs_session.meta.get("connection_protocol") == "smbd"
    assert subs_session.meta.get("size_bytes") == 142336

    print("OK")
