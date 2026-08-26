"""RDPHoneypot parser — RDP/3389 with NLA, NTLM challenge-response capture.

Ported 2026-08-26 from the v1 importer's parsers/rdphoneypot.py, with three
corrections found by checking the port against live ES rather than trusting the
original (the same discipline that caught Heralding's `proto` vs `protocol`).

WHY THIS EXISTS
---------------
`RDPHoneypot` had no parser here, so every event fell through to the fallback
and became a bare IPv4 observable. Core logs the tell on startup:
"T-Pot has a new honeypot type 'RDPHoneypot'". Over 24h that discarded 25,352
events, of which 6,492 were `rdphoneypot.login` carrying a full NetNTLMv2
challenge-response.

THE PASSWORD FIELD IS ALWAYS EMPTY, AND THAT IS NOT A BUG
---------------------------------------------------------
NLA never transmits a cleartext password — the client proves knowledge via an
NTLM challenge-response. Every doc has `password: ""`, so a naive "distinct
passwords" metric scores this honeypot 1 and makes it look worthless. It is
not: the NTLMv2 response IS the credential and is offline-crackable. Score this
honeypot on distinct usernames and NTLM captures, never on event volume — it is
flood-shaped (top few IPs dominate).

CORRECTIONS vs THE v1 PARSER
----------------------------
1. Session id is `session`, not `session_id`.
2. `cookie` / `mstshash` are read by v1 but do not exist on this type:
   0 occurrences in 25,352 docs over 24h. Dropped.
3. v1 extracts only `nt_response`. The `message` field also carries a
   ready-to-crack **hashcat mode 5600** line, which v1 never captured:
       username::domain:challenge:HMAC:blob
   That is the single most useful artifact this honeypot produces.

⚠ THE NTLM BLOB CONTAINS OUR OWN SENSOR IP
-------------------------------------------
The NTLMv2 blob carries AV pairs, and AV pair type 9 (SPN) is the target the
client thought it was authenticating to — i.e. OUR honeypot:

    AV type 9  ->  TERMSRV/76.165.200.155

Measured: 39 of 200 sampled blobs (19.5%) over 7 days. This matters because it
defeats every redaction pass on the platform. `TPOT_HONEYPOT_IPS` redaction is
string replacement over text; the address here is UTF-16LE *inside a hex
string* (`00370036002e00310036...`), so it matches nothing and ships out intact.

It cannot simply be scrubbed: the NTLMv2 response is an HMAC computed OVER the
blob, so altering the blob destroys crackability. Redacting and keeping the
value are mutually exclusive.

So this parser does not decide — it MARKS. Blobs whose SPN names operator
infrastructure get `rdp:ntlm-operator-spn`, and the hashcat line is exposed in
`meta` rather than in any field that flows into a published description or
Note. Publication policy is the operator's call; what matters is that the
choice is now visible instead of silent.
"""

from __future__ import annotations

import logging
import re
import struct
from typing import Iterable, Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent
from tpot2cti.session import correlate_by_session_id

logger = logging.getLogger(__name__)


# Localised builtin-administrator names. Presence is a targeting signal: it
# says which locale the attacker's tooling expects, which bare "admin" does
# not. Explicit rather than regex-guessed so it stays auditable.
_LOCALISED_ADMIN = frozenset({
    "administrator", "administrateur", "administrador", "administratör",
    "amministratore", "rendszergazda", "beheerder", "järjestelmänvalvoja",
    "administrator1", "admin", "администратор",
})

_MAX_USERNAME_LEN = 64

# "... username: 'admin', hashcat: 'admin::WORKGROUP:<chal>:<hmac>:<blob>'."
_HASHCAT_RE = re.compile(r"hashcat:\s*'([^']+)'")
_HOSTNAME_RE = re.compile(r"hostname:\s*'([^']*)'")
_SESSION_RE = re.compile(r"\[session:\s*([0-9a-f]+)\]")

# NTLMv2 AV-pair id for the target SPN.
_AV_TARGET_NAME = 9
# Offset past the NTLMv2 blob header (respType/hiRespType/reserved/timestamp/
# client-challenge/reserved) to the first AV pair.
_AV_LIST_OFFSET = 28


def _plausible_username(u: str) -> bool:
    """True if `u` looks like a username a human or tool would actually send.

    RDPHoneypot mis-decodes some NTLM blobs into the username field. On the v1
    platform, over 7 days of the top 3,000 distinct usernames, 2,197 were
    non-ASCII/binary and 706 were Python bytes-reprs — 96.7% of DISTINCT values
    but only 1.3% of events. Publishing them would mint ~2,900 junk user
    accounts a week. Reject for CREDENTIAL purposes; the event and the NTLM
    capture remain valid regardless of whether the username decoded.
    """
    if not u or u.startswith(("b'", 'b"')) or len(u) > _MAX_USERNAME_LEN:
        return False
    return all(32 <= ord(c) < 127 for c in u)


def ntlm_target_spn(nt_response: str) -> Optional[str]:
    """Return the SPN (AV pair type 9) from an NTLMv2 blob, if present.

    This is how we detect that a blob names our own infrastructure. Parsing is
    deliberately defensive: the field is attacker-influenced, so a malformed
    blob must yield None rather than raise.
    """
    if not nt_response:
        return None
    try:
        raw = bytes.fromhex(nt_response)
    except (ValueError, TypeError):
        return None
    i = _AV_LIST_OFFSET
    while i + 4 <= len(raw):
        try:
            av_id, av_len = struct.unpack_from("<HH", raw, i)
        except struct.error:
            return None
        i += 4
        if av_id == 0:                      # MsvAvEOL
            return None
        value, i = raw[i:i + av_len], i + av_len
        if av_id == _AV_TARGET_NAME:
            try:
                return value.decode("utf-16le").rstrip("\x00")
            except UnicodeDecodeError:
                return None
    return None


class RDPHoneypotParser(BaseParser):
    """Parser for RDPHoneypot (RDP/3389, NLA + NetNTLMv2 capture)."""

    type_name = "RDPHoneypot"

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        src_ip = doc.get("src_ip")
        if not src_ip:
            logger.debug("rdphoneypot: skipping doc with no src_ip")
            return None
        ts = self._parse_timestamp(doc)
        if ts is None:
            logger.debug("rdphoneypot: skipping doc with unparseable @timestamp")
            return None

        message = doc.get("message") or ""
        eventid = (doc.get("eventid") or "").lower()

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or "unknown"
            ),
            event_type="RDPHoneypot",
            # Verified against live ES: the field is `session`, NOT `session_id`
            # (25,352/25,352 docs over 24h). `session_id` is checked second only
            # so a future T-Pot rename does not silently drop correlation.
            session_id=doc.get("session") or doc.get("session_id")
                       or self._session_from_message(message),
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int(doc.get("dest_port") or doc.get("dst_port")) or 3389,
            dst_ip=(doc.get("dest_ip") or doc.get("dst_ip")),
            protocol="rdp",          # never present as a field on this type
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        username = (doc.get("username") or "").strip()
        nt_response = (doc.get("nt_response") or "").strip()
        is_login = eventid.endswith("login") or bool(nt_response) or bool(username)

        if not is_login:
            event.meta["rdp_phase"] = (
                "close" if eventid.endswith("closed") else "connect")
            if (dur := doc.get("duration")) is not None:
                event.meta["session_duration"] = dur
            return event

        username_ok = _plausible_username(username)
        # `domain` is near-always "" or "." here; `derived_domain` carries the
        # real value (WORKGROUP, or an AD domain when the client is joined).
        domain = (doc.get("domain") or "").strip()
        derived = (doc.get("derived_domain") or "").strip()

        event.meta["rdp_phase"] = "login"
        event.meta["auth_method"] = (doc.get("auth_method") or "unknown").strip()
        event.meta["username_decoded"] = username_ok
        # Both halves present ⇒ the aggregator records a credential attempt.
        # Password is "" by protocol design under NLA, never a missing value.
        event.meta["username"] = username if username_ok else ""
        event.meta["password"] = ""
        if derived and derived != ".":
            event.meta["target_domain"] = derived
        elif domain and domain != ".":
            event.meta["target_domain"] = domain

        if nt_response:
            event.meta["ntlm_nt_response"] = nt_response
            # The ready-to-crack artifact (hashcat -m 5600). v1 never captured
            # this; it is the reason this honeypot is worth parsing at all.
            if (m := _HASHCAT_RE.search(message)):
                event.meta["ntlm_hashcat"] = m.group(1)
            if (spn := ntlm_target_spn(nt_response)):
                event.meta["ntlm_spn"] = spn

        if (client := _HOSTNAME_RE.search(message)) and client.group(1).strip():
            event.meta["client_hostname"] = client.group(1).strip()
        return event

    # ------------------------------------------------------------------ #

    def correlate(self, events: Iterable[ParsedEvent]) -> list[AttackSession]:
        return correlate_by_session_id(events, aggregator=self._aggregate_session)

    def _aggregate_session(self, session: AttackSession,
                           events: list[ParsedEvent]) -> None:
        seen: set[tuple[str, str]] = set()
        ntlm: list[dict] = []
        for e in events:
            meta = e.meta
            uname, pwd = meta.get("username"), meta.get("password")
            if uname is not None and pwd is not None:
                pair = (str(uname), str(pwd))
                if pair not in seen:
                    seen.add(pair)
                    session.credentials_tried.append(pair)
            if meta.get("ntlm_nt_response"):
                ntlm.append({
                    "nt_response": meta["ntlm_nt_response"],
                    "hashcat": meta.get("ntlm_hashcat", ""),
                    "spn": meta.get("ntlm_spn", ""),
                    "username": meta.get("username", ""),
                    "domain": meta.get("target_domain", ""),
                    "auth_method": meta.get("auth_method", "unknown"),
                })
            if e.dst_port is not None:
                session.dst_ports.add(e.dst_port)
            if proto := (e.protocol or meta.get("protocol")):
                session.protocols.add(str(proto))

        if ntlm:
            # Kept in session.meta, NOT in any field that flows into a published
            # description or Note — see the module docstring: ~20% of these
            # blobs name our own sensor in their SPN, and the value cannot be
            # redacted without destroying crackability.
            session.meta["ntlm_captures"] = ntlm
            session.meta["ntlm_capture_count"] = len(ntlm)

    def labels_for_session(self, session: AttackSession) -> list[str]:
        """Extra labels beyond the base [honeypot, rdphoneypot, remote-desktop].

        Called by the builder where supported; harmless if it is not, since the
        substance also lives in session.meta.
        """
        labels: list[str] = []
        captures = session.meta.get("ntlm_captures") or []
        if not captures:
            labels.append("rdp:connection-only")
            return labels
        labels += ["rdp:login-attempt", "rdp:ntlm-captured", "credentials:harvested"]
        if any(c.get("hashcat") for c in captures):
            labels.append("rdp:ntlm-crackable")
        if any(_operator_spn(c.get("spn", "")) for c in captures):
            # Marks material that must not be published verbatim.
            labels.append("rdp:ntlm-operator-spn")
        methods = {c.get("auth_method", "").lower() for c in captures if c.get("auth_method")}
        labels += [f"rdp:auth-{m}" for m in sorted(methods) if m and m != "unknown"]
        for uname, _ in session.credentials_tried:
            if uname and uname.lower() in _LOCALISED_ADMIN:
                labels.append("rdp:builtin-admin-target")
                break
        if any(not c.get("username") for c in captures):
            labels.append("rdp:username-undecodable")
        if any(c.get("domain") for c in captures):
            labels.append("rdp:domain-specified")
        return sorted(set(labels))

    @staticmethod
    def _session_from_message(message: str) -> Optional[str]:
        m = _SESSION_RE.search(message or "")
        return m.group(1) if m else None

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


def _operator_spn(spn: str) -> bool:
    """True if an SPN names our own infrastructure.

    Derived from TPOT_HONEYPOT_IPS / TPOT2CTI_SENSOR_HOSTNAMES at call time
    rather than hard-coded — a hand-maintained copy of a guard list drifts, and
    that is exactly how a sensor ends up published as an indicator.
    """
    if not spn:
        return False
    try:
        from tpot2cti.config import from_env
        cfg = from_env()
        needles = set(getattr(cfg, "honeypot_ips", None) or [])
        needles |= set(getattr(cfg, "sensor_hostnames", None) or [])
    except Exception:                       # noqa: BLE001 — never block parsing
        needles = set()
    if not needles:
        import os
        needles = {x.strip() for x in
                   (os.environ.get("TPOT_HONEYPOT_IPS", "") + "," +
                    os.environ.get("TPOT2CTI_SENSOR_HOSTNAMES", "")).split(",")
                   if x.strip()}
    low = spn.lower()
    return any(n and n.lower() in low for n in needles)


# Register on import
register(RDPHoneypotParser())
