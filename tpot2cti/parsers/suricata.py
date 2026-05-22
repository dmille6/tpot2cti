"""Suricata parser — network IDS alerts.

Suricata is T-Pot's network IDS — it inspects every packet against a
big rule corpus (ET Open + community rules) and emits an alert
document for each rule that fires.  Unlike Cowrie, there is no
multi-event "session" to correlate: each alert is the discrete unit
of substance.  We map one ES doc → one ParsedEvent → one AttackSession,
and every session is substantive (the alert itself is the signal).

Per the V0 parser-vs-builder separation rule, this parser stays pure (model-only):
parse() + correlate() + has_substance() only.  The per-protocol STIX
shape — AttackPattern selection, Vulnerability emission, Domain-Name
resolves-to relationships — lives in
``STIXBuilder.build_suricata_alert``.

Per V1_SPEC.md §5.2:

  T-Pot doc fields used:
    src_ip, dest_ip, src_port, dest_port, proto,
    alert.signature, alert.signature_id, alert.category, alert.severity,
    alert.metadata.mitre_*, flow_id, hostname, http.*, tls.*

  Event correlation:
    each alert is a discrete event — we do NOT group by flow_id.
    Multiple alerts on the same flow each become their own Sighting.

  STIX emitted per alert (by the builder):
    IPv4-Addr, Location, AutonomousSystem (via build_attacker_context)
    Indicator (IP-based), Sighting,
    Domain-Name (if TLS SNI or HTTP host present),
    URL (if http.url present),
    AttackPattern (from alert.metadata.mitre_technique_id),
    Vulnerability (if a CVE id appears in the signature name).
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from tpot2cti.parsers import register
from tpot2cti.parsers.base import AttackSession, BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# CVE ids inside Suricata signature names ("ET EXPLOIT ... CVE-2021-44228 ...")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# ATT&CK technique id format: T1190, T1059.001, etc.
_MITRE_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class SuricataParser(BaseParser):
    """Parser for T-Pot's Suricata IDS alerts."""

    type_name = "Suricata"

    # ──────────────────────────────────────────────────────────────────
    # parse() — one ES doc → one ParsedEvent
    # ──────────────────────────────────────────────────────────────────

    def parse(self, doc: dict) -> Optional[ParsedEvent]:
        # Skip non-alert Suricata docs (flow, stats, dns metadata, etc.).
        # Per V1_SPEC §5.2 we only process alert documents in v1.0.
        alert = doc.get("alert")
        if not isinstance(alert, dict):
            return None

        src_ip = doc.get("src_ip")
        if not src_ip:
            return None

        ts = self._parse_timestamp(doc)
        if ts is None:
            return None

        event = ParsedEvent(
            src_ip=str(src_ip),
            timestamp=ts,
            sensor_hostname=str(
                doc.get("t-pot_hostname")
                or (doc.get("host") or {}).get("name")
                or doc.get("hostname")
                or "unknown"
            ),
            event_type="Suricata",
            session_id=self._session_id_for(doc),
            src_port=self._safe_int(doc.get("src_port")),
            dst_port=self._safe_int(doc.get("dest_port") or doc.get("dst_port")),
            dst_ip=doc.get("dest_ip") or doc.get("dst_ip"),
            protocol=self._derive_protocol(doc),
            raw_doc=doc,
        )
        self._populate_geoip(doc, event)

        # ── Alert metadata into meta ───────────────────────────────────
        signature = alert.get("signature") or ""
        event.meta["signature"] = str(signature)
        if (sid := alert.get("signature_id")) is not None:
            event.meta["signature_id"] = self._safe_int(sid) or sid
        if cat := alert.get("category"):
            event.meta["category"] = str(cat)
        if (sev := alert.get("severity")) is not None:
            event.meta["severity"] = self._safe_int(sev) or sev

        # ── MITRE ATT&CK techniques from rule metadata ────────────────
        techniques = self._extract_mitre_techniques(alert)
        if techniques:
            event.meta["mitre_techniques"] = techniques

        # ── CVEs mentioned in the signature name ──────────────────────
        cves = sorted({m.upper() for m in _CVE_RE.findall(signature)})
        if cves:
            event.meta["cves"] = cves

        # ── App-layer context — TLS / HTTP / SSH / SIP / RFB / fileinfo ─
        # Per 2026-05-22 field-name audit vs real ES exports: every one
        # of these surfaces appears at 100% within its event-type slice
        # and was previously dropped on the floor by the parser. We now
        # stash them in meta so the downstream Sighting / Note can
        # render useful context (and downstream builders / pivot menus
        # can build off them).
        tls = doc.get("tls") or {}
        if isinstance(tls, dict):
            if sni := tls.get("sni"):
                event.meta["tls_sni"] = str(sni).lower()
            # JA3/JA3S/JA4 fingerprints — 100% of TLS events.  These are
            # the SAME shape as FATT's TLS output, just observed by
            # Suricata on the wire instead of by FATT's pcap mirror.
            for fp_key in ("ja3", "ja3s", "ja4"):
                if v := tls.get(fp_key):
                    if isinstance(v, dict):
                        v = v.get("hash") or v.get("fingerprint") or ""
                    if v:
                        event.meta[f"tls_{fp_key}"] = str(v).lower()
            # subject / issuerdn — let downstream Note name the cert.
            if subj := tls.get("subject"):
                event.meta["tls_subject"] = str(subj)

        http = doc.get("http") or {}
        if isinstance(http, dict):
            if host := (http.get("hostname") or http.get("http_host")):
                event.meta["http_host"] = str(host).lower()
            if url := http.get("url"):
                event.meta["http_url"] = str(url)
            if ua := (http.get("http_user_agent") or http.get("user_agent")):
                event.meta["http_user_agent"] = str(ua)
            if method := http.get("http_method"):
                event.meta["http_method"] = str(method).upper()
            if status := http.get("status"):
                try:
                    event.meta["http_status"] = int(status)
                except (TypeError, ValueError):
                    pass

        # SSH client/server banners — fingerprint surface for non-Cowrie
        # SSH attackers (e.g. those hitting a sensor's actual sshd).
        ssh = doc.get("ssh") or {}
        if isinstance(ssh, dict):
            ssh_client = ssh.get("client") if isinstance(ssh.get("client"), dict) else {}
            ssh_server = ssh.get("server") if isinstance(ssh.get("server"), dict) else {}
            if ver := (ssh_client.get("software_version")
                       or ssh_client.get("proto_version")):
                event.meta["ssh_client_version"] = str(ver)
            if ver := (ssh_server.get("software_version")
                       or ssh_server.get("proto_version")):
                event.meta["ssh_server_version"] = str(ver)

        # fileinfo — Suricata extracted a file during the alert. Hash +
        # filename let us emit a File observable downstream when the
        # signature implicates malware delivery.
        fi = doc.get("fileinfo") or {}
        if isinstance(fi, dict):
            for algo in ("sha256", "sha1", "md5"):
                if h := fi.get(algo):
                    event.meta[f"file_{algo}"] = str(h).lower()
            if name := fi.get("filename"):
                event.meta["file_name"] = str(name)
            if size := fi.get("size"):
                try:
                    event.meta["file_size"] = int(size)
                except (TypeError, ValueError):
                    pass

        # RFB (VNC) — 100% of rfb events carry the protocol version +
        # auth method; useful for the "VNC bruteforce" attacker profile.
        rfb = doc.get("rfb") or {}
        if isinstance(rfb, dict):
            if ver := rfb.get("server_protocol_version"):
                event.meta["rfb_version"] = str(ver)
            if auth := rfb.get("authentication"):
                event.meta["rfb_auth"] = str(auth) if not isinstance(auth, dict) else (
                    auth.get("security_type") or ""
                )

        # SIP — Suricata catches SIP probes that don't reach SentryPeer
        # (e.g. on ports SentryPeer isn't listening on). Mirror the
        # SentryPeer parser's surface so downstream Note rendering is
        # consistent across the two sources.
        sip = doc.get("sip") or {}
        if isinstance(sip, dict):
            if m := sip.get("method"):
                event.meta["sip_method"] = str(m).upper()
            if u := sip.get("uri"):
                event.meta["sip_uri"] = str(u)
            if v := sip.get("version"):
                event.meta["sip_version"] = str(v)

        if flow_id := doc.get("flow_id"):
            event.meta["flow_id"] = flow_id

        return event

    # ──────────────────────────────────────────────────────────────────
    # correlate() — default one-event-per-session is correct here
    # ──────────────────────────────────────────────────────────────────
    # We inherit BaseParser.correlate, which calls AttackSession.from_event
    # for each event.  Per V1_SPEC §5.2 we explicitly do NOT group by
    # flow_id — each alert is its own Sighting.

    # ──────────────────────────────────────────────────────────────────
    # has_substance() — default True
    # ──────────────────────────────────────────────────────────────────
    # All Suricata alerts are substantive: the rule firing IS the signal.
    # We inherit BaseParser.has_substance which returns True.

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _session_id_for(doc: dict) -> str:
        """Construct a deterministic synthetic session id for one alert.

        Suricata has no session concept across alerts; we still want a
        stable id so AttackSession.from_event() can build a unique
        session_id.  flow_id + signature_id + timestamp is deterministic
        and unique enough to avoid collisions between alerts.
        """
        flow = doc.get("flow_id") or "noflow"
        alert = doc.get("alert") or {}
        sid = alert.get("signature_id") or "nosid"
        ts = doc.get("@timestamp") or "nots"
        return f"suricata:{flow}:{sid}:{ts}"

    @staticmethod
    def _derive_protocol(doc: dict) -> Optional[str]:
        """Pick the most informative protocol label.

        Prefer app-layer (tls/http/dns) when present; otherwise fall back
        to the transport in `proto` ("TCP" → "tcp").  Returns None when
        nothing useful is available.
        """
        if doc.get("tls"):
            return "tls"
        if doc.get("http"):
            return "http"
        if doc.get("dns"):
            return "dns"
        proto = doc.get("proto") or doc.get("app_proto")
        if proto:
            return str(proto).lower()
        return None

    @staticmethod
    def _extract_mitre_techniques(alert: dict) -> list[str]:
        """Pull ATT&CK technique ids from alert.metadata.

        Suricata rules can carry metadata as either a single string or a
        list of strings under `metadata.mitre_technique_id`.  We accept
        both, normalize to uppercase, and validate each id matches the
        TXXXX or TXXXX.NNN shape before returning.
        """
        meta = alert.get("metadata") or {}
        if not isinstance(meta, dict):
            return []
        raw = meta.get("mitre_technique_id")
        if raw is None:
            return []
        values = raw if isinstance(raw, list) else [raw]
        out: list[str] = []
        for v in values:
            if not isinstance(v, str):
                continue
            tid = v.strip().upper()
            if _MITRE_TID_RE.match(tid) and tid not in out:
                out.append(tid)
        return out

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


# Register on import
register(SuricataParser())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = SuricataParser()

    now = datetime.now(timezone.utc)
    doc = {
        "@timestamp": now.isoformat(),
        "type": "Suricata",
        "src_ip": "5.6.7.8",
        "src_port": 41234,
        "dest_ip": "10.0.0.2",
        "dest_port": 443,
        "proto": "TCP",
        "flow_id": 1234567890,
        "t-pot_hostname": "node1",
        "geoip": {
            "country_iso_code": "RU", "country_name": "Russia",
            "city_name": "Moscow", "asn": 12389, "organization": "Rostelecom",
        },
        "alert": {
            "signature": "ET EXPLOIT Apache log4j CVE-2021-44228 RCE Attempt",
            "signature_id": 2034647,
            "category": "Web Application Attack",
            "severity": 1,
            "metadata": {
                "mitre_technique_id": "T1190",
                "mitre_tactic_id": "TA0001",
            },
        },
        "tls": {"sni": "victim.example.com"},
        "http": {"hostname": "victim.example.com", "url": "/api/v1/login"},
    }

    # 1. parse
    event = parser.parse(doc)
    assert event is not None, "parse() returned None"
    print(f"parsed event: src_ip={event.src_ip} sig_id={event.meta.get('signature_id')}")
    print(f"  mitre_techniques: {event.meta.get('mitre_techniques')}")
    print(f"  cves:             {event.meta.get('cves')}")
    print(f"  tls_sni:          {event.meta.get('tls_sni')}")

    # 2. correlate
    sessions = parser.correlate([event])
    assert len(sessions) == 1, f"expected 1 session, got {len(sessions)}"
    session = sessions[0]
    print(f"correlated into {len(sessions)} session(s); session_id={session.session_id}")

    # 3. has_substance — default True
    assert parser.has_substance(session) is True
    print(f"  has_substance:    {parser.has_substance(session)}")

    # 4. build STIX via the builder (parser no longer owns build()).
    import os
    from tpot2cti.parsers.base import _smoketest_env
    _smoketest_env()
    from tpot2cti.config import load_config
    from tpot2cti.stix.builder import STIXBuilder

    cfg = load_config()
    builder = STIXBuilder(cfg)
    objects = builder.build_suricata_alert(session)
    print(f"\nbuilt {len(objects)} STIX objects:")
    by_type: dict[str, int] = {}
    for o in objects:
        by_type[o["type"]] = by_type.get(o["type"], 0) + 1
    for t, n in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"  {t:25s} {n}")

    # 5. Verify Vulnerability for CVE-2021-44228 and AttackPattern for T1190
    cve_names = {o.get("name") for o in objects if o["type"] == "vulnerability"}
    ap_ext_ids = {
        ref.get("external_id")
        for o in objects if o["type"] == "attack-pattern"
        for ref in (o.get("external_references") or [])
    }
    assert "CVE-2021-44228" in cve_names, f"missing CVE-2021-44228; got {cve_names}"
    assert "T1190" in ap_ext_ids, f"missing T1190 AttackPattern; got {ap_ext_ids}"
    print("\nVerified: CVE-2021-44228 Vulnerability + T1190 AttackPattern present.")

    # Also assert a Domain-Name was emitted from the TLS SNI
    domains = {o.get("value") for o in objects if o["type"] == "domain-name"}
    assert "victim.example.com" in domains, f"missing SNI domain; got {domains}"
    print(f"Verified: Domain-Name for TLS SNI present: {domains}")

    print("\nSmoke test passed.")
