"""tpot2cti — STIX 2.1 object builder.

See docs/stix/builder.md for design notes.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlsplit

from tpot2cti.config import Config
from tpot2cti.parsers.base import AttackSession, ParsedEvent
from tpot2cti import attack_mapping
from tpot2cti import port_intel
from tpot2cti.stix.rendering import (
    render_cowrie_session_note_body,
    render_cowrie_sighting_description,
    render_fallback_no_ip_note_body,
    render_fallback_sighting_description,
    render_honeytrap_sighting_description,
)
from tpot2cti.stix.external_refs import (
    for_autonomous_system as _refs_for_as,
    for_domain as _refs_for_domain,
    for_file_sha256 as _refs_for_file,
    for_ipv4 as _refs_for_ipv4,
    for_ipv6 as _refs_for_ipv6,
    for_url as _refs_for_url,
)
from tpot2cti.stix_ids import (
    generate_attack_pattern_id,
    generate_autonomous_system_id,
    generate_campaign_id,
    generate_city_location_id,
    generate_country_location_id,
    generate_credential_note_id,
    generate_cryptographic_key_id,
    generate_domain_id,
    generate_file_id,
    generate_file_indicator_id,
    generate_identity_id,
    generate_infrastructure_id_for_sensor,
    attacker_ip_indicator_id,
    attacker_ip_observable_id,
    canonical_ip,
    generate_ip_indicator_id,
    generate_ipv4_id,
    generate_ipv6_id,
    generate_malware_id,
    generate_marking_definition_id,
    generate_process_id,
    sdo_id,
    generate_relationship_id,
    generate_sensor_id,
    generate_session_note_id,
    generate_sighting_id,
    generate_url_id,
    generate_vulnerability_id,
    sensor_infra_name,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Note bodies are capped per LESSONS §13 to keep bundles under
# OpenCTI's ~1 MB worker limit.  64 KB is generous for any reasonable
# session summary.
MAX_NOTE_BODY_BYTES = 64 * 1024
#: Max distinct URL observables emitted per web session (a scanner can
#: hit hundreds of paths; cap so one session can't balloon the bundle).
_MAX_WEB_URLS = 25

#: Stand-in for the source of an event whose src_ip could not be trusted
#: (see build_unattributed_payload_objects). It is a human-readable LABEL
#: that flows into generated descriptions — never an address, and never
#: passed to an id generator.
_UNATTRIBUTED_SRC = "an unattributed source (spoofed X-Forwarded-For)"

#: Cap on raw/decoded payload text embedded in a salvage Note.
_UNATTRIBUTED_RAW_CAP = 4 * 1024

# Process command_line cap (matches PoC convention)
MAX_COMMANDS_PER_PROCESS = 50

# Ephemeral temp-file paths in scp malware-drop probes; normalized to dedupe noise.
_TMPFILE_RE = re.compile(r"(/tmp|/var/tmp|/dev/shm|/run/shm)/[A-Za-z0-9._-]{5,}")

# Attacker-IP validation/canonicalization + deterministic ids live in
# tpot2cti.stix_ids: `canonical_ip`, `attacker_ip_observable_id`,
# `attacker_ip_indicator_id`. Every attacker-IP id in this file goes
# through those so the id always matches the emitted object (v4 or v6, any
# notation) — minting an id from a raw string is what caused dangling refs.
# `_IPV4_RE` remains only for the referenced-C2-literal path (build_referenced_ipv4).
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Download URLs (wget/curl/tftp droppers) embedded in command transcripts.
_CMD_URL_RE = re.compile(r"\b(?:https?|ftp|tftp)://[^\s<>|;,)\\]+", re.IGNORECASE)

# ── Recon-noise classifier (2026-06-19) ─────────────────────────────────────
# Commodity fingerprinting (esp. the GPU-miner uname/lscpu/lspci/nvidia-smi
# suite) dominates LLM-SSH command volume and mints thousands of zero-value
# Process SDOs per cycle. build_process drops a session whose commands are ALL
# pure recon, so only "meaty" attacks (download/exec, persistence, cred/cloud
# theft) reach OpenCTI. Conservative: ONE offensive token anywhere in any
# command keeps the whole session. Raw events always remain in ES/Kibana.
_IPECHO_RE = re.compile(
    r"(ipinfo\.io|ifconfig\.me|ifconfig\.co|icanhazip|ipify\.org|ipecho\.net|"
    r"checkip|ip\.sb|myip|whatismyip|wtfismyip|trackip|showip|api\.ip)",
    re.IGNORECASE,
)
_FETCH_LEAD_RE = re.compile(
    r"^(sudo\s+)?(/\S+/|\./)?(curl|wget|fetch|lwp-download|get)\b", re.IGNORECASE
)
_MEATY_RE = re.compile(
    r"(\|\s*(sh|bash|ash|zsh|python3?|perl|php|ruby|node)\b|\b(sh|bash)\s+-c\b|"
    r"\beval\b|\bexec\b|\bchmod\b|\bchattr\b|\bbase64\b|\bxxd\b|\\x[0-9a-fA-F]{2}|"
    r"\bwget\b|\bcurl\b|\btftp\b|\bftpget\b|\blwp-download\b|\bscp\b|\bsftp\b|\brsync\b|"
    r"\bnc\b|\bncat\b|\bsocat\b|\bcrontab\b|authorized_keys|/\.ssh|id_rsa|id_ed25519|"
    r"\bsystemctl\b|rc\.local|init\.d|\buseradd\b|\badduser\b|\busermod\b|\bchpasswd\b|"
    r"/etc/shadow|/tmp/|/dev/shm|/var/tmp|\.sh\b|\.bin\b|\.elf\b|\bnohup\b|\bsetsid\b|"
    r"\bdisown\b|xmrig|minerd|cpuminer|kinsing|kdevtmpfs|\.env\b|\.aws\b|\.azure\b|"
    r"\.kube\b|credentials|169\.254\.169\.254|metadata/identity|\bkubectl\b|\bgcloud\b|"
    r"\.git/config|\bdd\b|\biptables\b|\bufw\b|\bmysql\b|\bredis\b|\bpasswd\b|\bmkfifo\b)",
    re.IGNORECASE,
)
_RECON_LEAD_RE = re.compile(
    r"^(sudo\s+)?(/\S+/|\./)?("
    r"uname|lscpu|lsmem|lsblk|lspci|nproc|nvidia-smi|uptime|free|whoami|id|hostname|"
    r"hostnamectl|pwd|who|w|last|users|groups|ls|dir|cd|exit|logout|history|clear|"
    r"reset|which|command|type|getconf|lsb_release|tty|set|env|printenv|locale|date|"
    r"cal|top|htop|vmstat|iostat|ps|df|du|arch|getprop|"
    r"cat\s+/proc/\S+|cat\s+/sys/\S+|"
    r"cat\s+/etc/(os-release|issue|lsb-release|hostname|machine-id|debian_version|redhat-release|centos-release)"
    r")(\s|$|\|)",
    re.IGNORECASE,
)


#: Vendor labels that are behaviour/category words, not malware families.
#: Matched EXACTLY (not as substrings) so real names that merely contain one
#: of these tokens — e.g. "abtrojan" — still pass.
_GENERIC_MALWARE_FAMILIES: frozenset[str] = frozenset({
    "trojan", "malware", "generic", "gen", "gen2", "agent", "linux", "elf",
    "backdoor", "dropper", "downloader", "riskware", "suspicious", "unknown",
    "packed", "shell", "ddos", "siggen", "virus", "worm", "exploit", "hacktool",
    "coinminer", "miner", "flooder", "script", "trojandownloader",
    "possible", "bash", "python", "perl", "application", "program", "tool",
    "variant", "heuristic", "behaveslike", "attribute", "encoded", "obfuscated",
    "botnet", "bot", "rootkit", "adware", "spyware", "ransom", "ransomware",
})

#: `gen2`, `gen3`, … are vendor generation counters, not families.
_GEN_COUNTER_RE = re.compile(r"^gen\d*$")

#: Stems that prefix a vendor's catch-all label (e.g. "genericrxhz"). Matched
#: as a PREFIX, unlike the exact-match set above.
_GENERIC_FAMILY_PREFIXES: tuple[str, ...] = (
    "generic", "heur", "trojan", "malware", "suspicious", "unwanted", "risk",
)

#: Vendor auto-generated detection ids interleave letters and digits
#: (`r002c0dbc25`, `r06ec0djq25`, `usblf226`). A live dry run showed that a
#: "3+ consecutive digits" rule was too weak — `r06ec0djq25` has no such run
#: and slipped through. Real families in this corpus (mirai, gafgyt,
#: multiverze, xmriggo, malxmr, bashdlod, miraia) carry NO digits at all, so
#: two or more digits anywhere is a reliable reject.
_MAX_FAMILY_DIGITS = 2


def normalize_malware_family(raw: Optional[str]) -> Optional[str]:
    """Normalise a vendor family label, or return ``None`` if unusable.

    Rejects, in order: empty/short tokens, generic behaviour words, and
    auto-generated vendor detection ids. ``None`` means "do not emit a Malware
    SDO" — the sample still gets its File observable and labels.

    Emitting a Malware SDO named ``r002c0dbc25`` or ``shell`` would pollute the
    graph and, once exported, misattribute infrastructure. See
    ``docs/ENRICHMENT.md`` §7.
    """
    if not raw:
        return None
    fam = str(raw).strip().lower()
    # Vendor labels arrive as "trojan.shell/malkey" or "trojan.r002c0dk825";
    # the family is the most specific trailing token.
    for sep in (".", "/", ":", "\\"):
        if sep in fam:
            fam = fam.rsplit(sep, 1)[-1]
    fam = fam.strip()
    if len(fam) < 4:
        return None
    if fam in _GENERIC_MALWARE_FAMILIES:
        return None
    if sum(c.isdigit() for c in fam) >= _MAX_FAMILY_DIGITS:
        return None
    if fam.startswith(_GENERIC_FAMILY_PREFIXES):
        return None
    if _GEN_COUNTER_RE.match(fam):
        return None
    if not fam.replace("-", "").replace("_", "").isalnum():
        return None
    return fam


def _is_recon_command(cmd: str) -> bool:
    """True if a single command is pure recon (no offensive action)."""
    c = (cmd or "").strip()
    if not c:
        return True  # blank / keepalive — ignorable
    if _FETCH_LEAD_RE.match(c):
        # download verb: recon only when probing an IP-echo service
        return bool(_IPECHO_RE.search(c))
    if _MEATY_RE.search(c):
        return False
    return bool(_RECON_LEAD_RE.match(c))


def _session_is_recon_only(commands) -> bool:
    """True if EVERY command in the session is pure recon (>=1 present)."""
    saw = False
    for c in commands:
        if (c or "").strip():
            saw = True
            if not _is_recon_command(c):
                return False
    return saw

#: Conservative domain-name validator. Requires >=2 dot-separated labels and
#: an alphabetic TLD, which rejects the malformations OpenCTI bounces with
#: "Observable is not correctly formatted": IP literals (numeric TLD), values
#: with a port (':'), path ('/'), or whitespace, and bare single labels. Used
#: by build_domain so a junk TLS-SNI / HTTP-Host never reaches OpenCTI as a
#: malformed domain-name SCO (which would also dangle any resolves-to edge).
#: The trailing label accepts either a pure-alphabetic TLD or an A-label
#: (`xn--…`). Without the second alternative NO punycode TLD can ever match,
#: which silently made all 151 `xn--` entries shipped in `iana_tlds.txt`
#: unreachable dead weight — `shop.xn--p1ai` (.рф) was rejected as malformed.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$"
)

#: The IANA root zone, shipped in-repo. The regex above ends in `[a-z]{2,63}`,
#: so ANY alphabetic trailing label passes as a TLD — which is how
#: `azenv.nethttp` (protocol residue concatenated onto a real domain),
#: `huangxcdh.html` (a filename) and `718.xuelian.lpost` became Domain-Name
#: observables in a threat-intelligence graph. Shape is not existence.
_TLD_FILE = Path(__file__).resolve().parent.parent / "data" / "iana_tlds.txt"


def _load_tlds() -> frozenset[str]:
    """Load the shipped TLD list. Missing file is FATAL, not a silent bypass.

    A validator that quietly stops validating when its data is absent is worse
    than no validator: it reports the same clean result either way.
    """
    try:
        text = _TLD_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(
            f"IANA TLD list missing at {_TLD_FILE}: {exc}. Refusing to run with "
            f"domain validation silently disabled."
        ) from exc
    tlds = frozenset(
        line.strip().lower() for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    )
    if len(tlds) < 1000:
        raise RuntimeError(
            f"IANA TLD list at {_TLD_FILE} parsed to only {len(tlds)} entries; "
            f"expected >1000. Refusing to run with a truncated allowlist."
        )
    return tlds


#: RFC 2606 / RFC 6761 reserved names. Valid TLDs by standard, deliberately
#: absent from IANA's delegated root because they are permanently reserved for
#: documentation and testing. Accepted so the project's own fixtures and
#: sanitised corpora — which are required to use them — keep working. They are
#: non-resolvable by definition, so accepting them costs nothing in production;
#: rejecting them would break the convention every sanitised fixture relies on.
#: `onion` is here for the same reason and by the same rule: RFC 7686 reserves
#: it as a special-use name, so it is absent from the IANA root BY DESIGN and
#: will never appear there. Rejecting it would silently discard Tor C2 and
#: leak-site addresses, which are genuine high-value IoCs.
_RESERVED_TLDS = frozenset({"example", "test", "invalid", "localhost", "onion"})

IANA_TLDS = _load_tlds() | _RESERVED_TLDS

#: Schemes a URL observable may carry. Measured against the live corpus:
#: https 6,879, http 1,720, ftp 1 — and 2,468 values with no scheme at all,
#: which are bare request paths ("/admin.php") naming no host, which no
#: consumer can block, hunt or attribute.
#:
#: The JNDI providers are here deliberately. A Log4Shell payload's whole value
#: is the C2 endpoint it points at (`ldap://c2.example/Exploit`), recovered by
#: tpot2cti/log4shell.py from deliberately obfuscated input — that is among the
#: highest-quality intelligence this pipeline produces, and an http-only
#: allowlist would have silently discarded all of it.
_JNDI_SCHEMES = frozenset({
    "ldap", "ldaps", "rmi", "dns", "iiop", "nis", "corba", "nds",
})
#: `tftp` is NOT optional: `_CMD_URL_RE` (line 107) is written to extract
#: `(?:https?|ftp|tftp)://` out of command transcripts — its own comment says
#: "wget/curl/tftp droppers". Omitting it here means the extractor mints a
#: tftp dropper URL and this validator silently discards it, on the one path
#: (a URL inside a real shell-command transcript) that produces this
#: pipeline's highest-confidence intel. The two sets must stay in step.
_URL_SCHEMES = frozenset({"http", "https", "ftp", "tftp"}) | _JNDI_SCHEMES


def valid_domain(value: str) -> Optional[str]:
    """Return the canonical FQDN, or None if it is not a real domain name.

    Shape AND existence: the label after the final dot must be a TLD that
    actually exists in the IANA root zone.
    """
    if not value:
        return None
    fqdn = str(value).strip().lower().rstrip(".")
    if not fqdn or _IPV4_RE.match(fqdn) or not _DOMAIN_RE.match(fqdn):
        return None
    if fqdn.rsplit(".", 1)[-1] not in IANA_TLDS:
        return None
    return fqdn


#: Rendering budget for `session.protocol_requests`. Mirrors
#: `stix/rendering.py`'s Cowrie transcript budget, and for the same reason:
#: bound the bundle without ever dropping evidence silently.
_MAX_PROTOCOL_REQUESTS_RENDERED = 200
_MAX_PROTOCOL_REQUEST_BYTES = 8000


def _render_protocol_requests(requests: list[str]) -> str:
    """Render received protocol requests as ONE fenced block, with an
    explicit marker for anything omitted.

    The first cut fenced each element separately and hard-capped at 5:

        "\\n\\n".join(f"```\\n{r.strip()[:2000]}\\n```" for r in requests[:5])

    That was sized for ConPot, whose elements are multi-KB HTTP blobs. It is
    wrong for Mailoney, whose elements are four-character SMTP verbs: a
    ten-verb session rendered EHLO/MAIL/RCPT/RCPT/RCPT and silently dropped
    DATA, VRFY and RSET — the entire substance — while the Note's abstract
    advertised ten. Worse, the parser deliberately does not dedup because a
    repeated `RCPT TO` is itself a signal, so repeated verbs are exactly what
    exhausted the five-slot budget. Twenty lines of fence chrome around
    sixteen characters of content, and the analyst is never told.

    Silent truncation is the defect class this whole change set is about, so
    the cap is now generous, byte-bounded, and always announced.
    """
    kept = [r.strip() for r in requests[:_MAX_PROTOCOL_REQUESTS_RENDERED] if r.strip()]
    if not kept:
        return ""
    omitted = len([r for r in requests if r.strip()]) - len(kept)

    lines: list[str] = []
    total = 0
    for req in kept:
        total += len(req.encode("utf-8")) + 1
        if total > _MAX_PROTOCOL_REQUEST_BYTES:
            lines.append("... [truncated for size]")
            omitted += len(kept) - len(lines) + 1
            break
        lines.append(req)

    block = "```\n" + "\n".join(lines) + "\n```"
    if omitted > 0:
        block += f"\n_({omitted} additional request(s) omitted)_"
    return block


def valid_url(value: str) -> Optional[str]:
    """Return the URL unchanged if it is an absolute, host-bearing URL.

    `build_url` previously accepted anything non-empty, which is how 2,468 bare
    request paths and at least one User-Agent string became URL observables. A
    URL that names no host is not an indicator — nobody can block it, hunt it,
    or attribute it.
    """
    if not value:
        return None
    raw = str(value).strip()
    if not raw or any(c.isspace() for c in raw) or any(ord(c) < 32 for c in raw):
        return None
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in _URL_SCHEMES or not parts.netloc:
        return None

    if scheme in _JNDI_SCHEMES and "${" in parts.netloc:
        # A JNDI URL is EVIDENCE, not an IoC, and its host is frequently not a
        # resolvable name on purpose: exfil payloads embed an unresolved Log4j
        # template inside the hostname
        # (`ldap://x-${sys:java.version}.<c2-domain>/`) so the victim leaks its
        # Java version over DNS. Demanding a valid host here would discard the
        # payload verbatim — the only record of what was actually attempted.
        # The resolvable C2 zone is extracted separately by log4shell.py and
        # published as the Domain-Name observable, which IS the IoC.
        #
        # The `${` test is what keeps this an exemption rather than a hole.
        # Keyed on the scheme alone it was a general bypass of host validation
        # for any attacker-controlled string that happened to carry a JNDI
        # scheme — `ldap://ANYTHING-AT-ALL` was accepted verbatim. Only an
        # UNRESOLVED TEMPLATE justifies skipping the check, because only a
        # template is un-validatable by construction. A JNDI URL with an
        # ordinary host (`ldap://c2.malicious.example/Exploit`) is still a
        # perfectly good IoC and falls through to normal validation below.
        return raw

    # urlsplit does NOT validate the port until `.port` is touched, so
    # `http://evil.example:65536/a` and `:bad` sail through otherwise. This
    # MUST come after the JNDI exemption: a template in the hostname
    # (`ldap://x-${sys:java.version}.c2.example/a`) contains a colon, so
    # urlsplit reads everything after it as a port and raises — which would
    # discard the exfil payload this function exists to preserve.
    try:
        parts.port
    except ValueError:
        return None

    host = (parts.hostname or "").strip().lower()
    if not host:
        return None
    # For ordinary URLs the host must clear the same bar as a standalone
    # Domain-Name observable, or be an IP literal.
    if valid_domain(host) is None and canonical_ip(host) is None:
        return None
    return raw


# ---------------------------------------------------------------------------
# Suricata MITRE technique allowlist
# ---------------------------------------------------------------------------
# A conservative, expandable catalogue of MITRE technique ids we recognize.
# Anything outside this set is logged at DEBUG and skipped rather than
# emitted as a noisy / unverified AttackPattern in build_suricata_alert.
# Extend as we observe new ids in the wild.
# Single source of truth lives in tpot2cti.attack_mapping.TECHNIQUES (shared
# with the behaviour-driven session mapper). Aliased here for the Suricata
# rule-id → name lookup below.
_KNOWN_MITRE_TECHNIQUES: dict[str, str] = attack_mapping.TECHNIQUES


# ---------------------------------------------------------------------------
# Parser-aware enrichment vocabulary (port of PoC's `source_labels` pattern
# from tsec-tpot-connectors/tsec-tpot-hp-connector/src/stix/
# observables.py + indicators.py).
#
# Every observable/indicator emitted on behalf of a session gets:
#   - 'honeypot' (always)
#   - the parser's slug (e.g. 'cowrie', 'suricata')
#   - a protocol-family slug (e.g. 'ssh-telnet', 'network-ids')
#
# Analyst impact: Indicator/Observable "Labels" column in OpenCTI shows
# WHICH honeypot caught this attacker, enabling filter-by-source queries
# without needing custom dashboards.
# ---------------------------------------------------------------------------

#: Maps each parser's type_name (== event_type on AttackSession) to a
#: tuple of (parser_slug, protocol_family_slug). Add a row whenever a
#: new parser is added; missing entries fall back to the parser name
#: lowercased.
_PARSER_LABEL_VOCAB: dict[str, tuple[str, str]] = {
    "Cowrie":        ("cowrie",        "ssh-telnet"),
    "Suricata":      ("suricata",      "network-ids"),
    "Honeytrap":     ("honeytrap",     "tcp-catchall"),
    "Dionaea":       ("dionaea",       "malware-capture"),
    "Heralding":     ("heralding",     "credential-capture"),
    "Mailoney":      ("mailoney",      "smtp"),
    "ConPot":        ("conpot",        "ics-scada"),
    "Dicompot":      ("dicompot",      "dicom-medical"),
    "Medpot":        ("medpot",        "hl7-medical"),
    "ElasticPot":    ("elasticpot",    "elasticsearch"),
    "Redishoneypot": ("redishoneypot", "redis"),
    "Ciscoasa":      ("ciscoasa",      "cisco-asa"),
    "Adbhoney":      ("adbhoney",      "android-adb"),
    "Ipphoney":      ("ipphoney",      "ipp-printer"),
    "Miniprint":     ("miniprint",     "printer"),
    "Tanner":        ("tanner",        "web-app"),
    "Wordpot":       ("wordpot",       "wordpress"),
    "Sentrypeer":    ("sentrypeer",    "sip-voip"),
    "Fatt":          ("fatt",          "tls-fingerprint"),
    "NGINX":         ("nginx",         "web"),
    "Honeyaml":      ("honeyaml",      "iac-config"),
    "Router":        ("router",        "telnet"),
    "H0neytr4p":     ("h0neytr4p",     "web-app"),
    "Beelzebub":     ("beelzebub",     "ssh-llm"),
    "Galah":         ("galah",         "web-llm"),
    # Galah internal-type aliases — see galah.py for the reason these
    # exist. Same labels as "Galah" because event.event_type is set to
    # "Galah" inside parse(); these entries only exist to satisfy the
    # parser-registry parity check.
    "contentGenerationError": ("galah", "web-llm"),
    "emptyLLMResponse":       ("galah", "web-llm"),
    "failedResponse":         ("galah", "web-llm"),
    "invalidJSONResponse":    ("galah", "web-llm"),
    "successfulResponse":     ("galah", "web-llm"),
    "cacheHit":               ("galah", "web-llm"),
    "__fallback__":  ("fallback",      "unknown-type"),
}


def parser_labels_for(event_type: Optional[str], sensor_hostname: Optional[str] = None) -> list[str]:
    """Return base labels [`honeypot`, <parser>, <protocol_family>] for a
    given parser type_name. Unknown parsers fall back to the type name
    lowercased so we never have an unlabelled object."""
    extra = [f"sensor:{sensor_hostname}"] if sensor_hostname else []
    if not event_type:
        return ["honeypot"] + extra
    pair = _PARSER_LABEL_VOCAB.get(event_type)
    if pair is None:
        return ["honeypot", event_type.lower()] + extra
    return ["honeypot", pair[0], pair[1]] + extra


#: Indicator name templates. {ip} and {n} are substituted; {n} is the
#: session count for IP indicators. Missing entries fall back to a
#: generic template.
_INDICATOR_NAME_TEMPLATES: dict[str, str] = {
    # Coverage MUST match _PARSER_LABEL_VOCAB. The 2026-05-22 spot-check
    # found 40 "fallback" indicators that were actually CiscoASA / FATT /
    # SentryPeer / IppHoney / Honeyaml / Dicompot / Miniprint emissions
    # falling through to the generic "Honeypot Attacker" name because
    # they had no template here. Keep this dict in sync with vocab.
    "Cowrie":        "Cowrie SSH/Telnet Attack - {ip} ({n} session{s})",
    "Suricata":      "Suricata Alert - {ip} ({n} alert{s})",
    "Honeytrap":     "Honeytrap Probe - {ip} ({n} probe{s})",
    "Dionaea":       "Dionaea Malware Drop - {ip} ({n} drop{s})",
    "Heralding":     "Heralding Credential Attack - {ip} ({n} session{s})",
    "Mailoney":      "Mailoney SMTP Abuse - {ip} ({n} session{s})",
    "ConPot":        "ConPot ICS Probe - {ip} ({n} probe{s})",
    "Dicompot":      "Dicompot DICOM Probe - {ip} ({n} probe{s})",
    "Medpot":        "Medpot HL7 Probe - {ip} ({n} probe{s})",
    "ElasticPot":    "ElasticPot ES API Abuse - {ip} ({n} session{s})",
    "Redishoneypot": "RedisHoneypot Probe - {ip} ({n} session{s})",
    "Ciscoasa":      "CiscoASA Probe - {ip} ({n} probe{s})",
    "Adbhoney":      "ADBhoney Android Debug Bridge Abuse - {ip} ({n} session{s})",
    "Ipphoney":      "IppHoney Printer Probe - {ip} ({n} probe{s})",
    "Miniprint":     "Miniprint Printer Probe - {ip} ({n} probe{s})",
    "Tanner":        "Tanner Web Attack - {ip} ({n} session{s})",
    "Wordpot":       "Wordpot WordPress Probe - {ip} ({n} probe{s})",
    "Sentrypeer":    "SentryPeer SIP/VoIP Abuse - {ip} ({n} session{s})",
    "Fatt":          "FATT Fingerprint Observation - {ip} ({n} burst{s})",
    "NGINX":         "NGINX Web Probe - {ip} ({n} session{s})",
    "Honeyaml":      "Honeyaml IaC Config Probe - {ip} ({n} probe{s})",
    "Router":        "Router Telnet Abuse - {ip} ({n} session{s})",
    "H0neytr4p":     "H0neytr4p Web Probe - {ip} ({n} probe{s})",
    "Beelzebub":     "Beelzebub LLM SSH Session - {ip} ({n} session{s})",
    "Galah":         "Galah LLM Web Probe - {ip} ({n} probe{s})",
    # Galah internal-type aliases — see galah.py.
    "contentGenerationError": "Galah LLM Web Probe - {ip} ({n} probe{s})",
    "emptyLLMResponse":       "Galah LLM Web Probe - {ip} ({n} probe{s})",
    "failedResponse":         "Galah LLM Web Probe - {ip} ({n} probe{s})",
    "invalidJSONResponse":    "Galah LLM Web Probe - {ip} ({n} probe{s})",
    "successfulResponse":     "Galah LLM Web Probe - {ip} ({n} probe{s})",
    "cacheHit":               "Galah LLM Web Probe - {ip} ({n} probe{s})",
    "__fallback__":  "Honeypot Activity (unknown type) - {ip} ({n} event{s})",
}


def _format_indicator_name(event_type: Optional[str], ip: str, n: int) -> str:
    tmpl = _INDICATOR_NAME_TEMPLATES.get(
        event_type or "",
        "Honeypot Attacker - {ip} ({n} event{s})"
    )
    return tmpl.format(ip=ip, n=n, s="s" if n != 1 else "")


# ---------------------------------------------------------------------------
# Scoring (lightweight; PoC's tsec_scoring.py is enrichment-owned, we own it
# directly since we don't ship enrichment connectors).
# ---------------------------------------------------------------------------

#: Default baseline score for a freshly-observed honeypot attacker IP.
#: PoC convention; tuned to leave headroom for enrichment to push up or
#: pull down. We don't have enrichment so this is the actual score
#: analysts see — picked at the middle of the 0-100 range to read as
#: "we know they probed but no enrichment confirms classification."
BASELINE_INDICATOR_SCORE = 50


def _signal_score(session: Optional[AttackSession]) -> int:
    """Compute a STIX score for an IP indicator from the session's
    substance signals. Mirrors PoC `tsec_scoring.LABEL_WEIGHTS` for the
    honeypot-side signals only (we have no enrichment labels).

    Returns a score in [10, 100]. Substantive sessions score higher than
    drive-bys. Single-shot probes from unknown IPs land at the baseline.
    """
    if session is None:
        return BASELINE_INDICATOR_SCORE
    score = BASELINE_INDICATOR_SCORE
    if session.auth_success:
        score += 30
    if session.commands:
        score += 25
    if session.malware_hashes:
        score += 35
    if session.credentials_tried:
        # +5 per attempt up to a cap (mirrors PoC's auth:failed weight
        # applied per-attempt with a small ceiling so a single brute-force
        # session can't max the score on its own).
        score += min(15, len(session.credentials_tried) * 5)
    # Cap to [10, 100].
    return max(10, min(100, score))


def _ip_score(session: Optional["AttackSession"]) -> int:
    """Observable score for an attacker IP: the substance-signal score
    (_signal_score) plus a threat-intel reputation boost and a broad-scan
    boost. Any honeypot interaction is inherently malicious, so even a bare
    probe sits at the baseline; known-bad + hands-on activity approaches 100."""
    if session is None:
        return BASELINE_INDICATOR_SCORE
    score = _signal_score(session)
    rep = ""
    if session.events:
        rep = str(session.events[0].raw_doc.get("ip_rep") or "").lower()
    if "known attacker" in rep:
        score += 25
    elif "bad reputation" in rep:
        score += 12
    # NOTE (2026-08-04): "mass scanner" / "scanner" / "bot" / "crawler" / "tor"
    # deliberately do NOT raise the score, and neither does broad port fan-out
    # (formerly +5 for >=5 dst_ports). Those describe COMMODITY MASS-SCANNING —
    # precisely the population the ENRICH ring exists to suppress
    # (docs/ENRICHMENT.md §1) — so boosting them here fights every downstream
    # sharing gate and inflates exactly what must not be published.
    #
    # Suppression is expressed as LABELS, never as a lower score: the
    # publisher's cross-cycle merge keeps max(score) (see
    # publisher.py::_dedup / state.object_max_state), so a score can only ever
    # ratchet UP and can never be walked back once inflated.
    return max(10, min(100, score))


def _humanize_span(delta) -> str:
    secs = int(delta.total_seconds())
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m"
    if secs < 86400:
        return f"{secs // 3600}h{(secs % 3600) // 60:02d}m"
    return f"{secs // 86400}d{(secs % 86400) // 3600:02d}h"


def _describe_ip(ip: str, session: "AttackSession") -> str:
    """Analyst-facing narrative: who/where, reputation, what was hit, how
    much, observed behavior, concrete samples, and the activity window."""
    ev0 = session.events[0] if session.events else None
    geo_bits = []
    if ev0 is not None:
        loc = ev0.src_country_name or ev0.src_country_code
        if loc:
            geo_bits.append(loc)
        if ev0.src_as_org:
            geo_bits.append(ev0.src_as_org + (f" (AS{ev0.src_asn})" if ev0.src_asn else ""))
        elif ev0.src_asn:
            geo_bits.append(f"AS{ev0.src_asn}")
    geo = f" from {', '.join(geo_bits)}" if geo_bits else ""
    rep = ""
    if ev0 is not None and ev0.raw_doc.get("ip_rep"):
        rep = str(ev0.raw_doc.get("ip_rep")).strip()
    svc = "/".join(sorted(session.protocols)) if session.protocols else ""
    ports = sorted(session.dst_ports)
    port_str = ""
    if ports:
        shown = ", ".join(str(p) for p in ports[:8])
        port_str = f" targeting port(s) {shown}" + ("…" if len(ports) > 8 else "")

    d = f"Attacker {ip}{geo} engaged T-Pot sensor '{session.sensor_hostname}'"
    if rep and rep.lower() not in ("", "-", "unknown"):
        d += f" (threat-intel reputation: {rep})"
    d += f". {session.event_count} event(s) against the {session.event_type} honeypot"
    if svc:
        d += f" [{svc}]"
    d += port_str + "."

    beh = []
    if session.auth_success:
        beh.append("authenticated into the service")
    if session.commands:
        beh.append(f"ran {len(session.commands)} shell command(s)")
    if session.credentials_tried:
        beh.append(f"attempted {len(session.credentials_tried)} login(s)")
    if session.malware_hashes:
        beh.append(f"staged/dropped {len(session.malware_hashes)} file(s)")
    if session.urls:
        beh.append(f"referenced {len(session.urls)} URL(s)")
    if session.ja3 or session.hassh:
        beh.append("left a TLS/SSH client fingerprint")
    if beh:
        d += " Behavior: " + ", ".join(beh) + "."

    if session.successful_credential:
        u = session.successful_credential[0]
        d += f" Successful login as '{u}'."
    if session.commands:
        sample = " ; ".join(c.strip() for c in session.commands[:3] if c.strip())
        if sample:
            d += f" e.g. {sample[:220]}" + ("…" if len(session.commands) > 3 else "")

    if session.last_seen > session.first_seen:
        d += (f" Activity window {session.first_seen.isoformat()} → "
              f"{session.last_seen.isoformat()} ({_humanize_span(session.last_seen - session.first_seen)}).")
    else:
        d += f" Seen {session.first_seen.isoformat()}."
    return d



#: How long an Indicator stays "valid_from" → "valid_until" before
#: OpenCTI considers it stale. 60 days matches the PoC default; can be
#: overridden via config when we wire a knob.
DEFAULT_INDICATOR_VALIDITY_DAYS = 60


# ---------------------------------------------------------------------------
# STIXBuilder
# ---------------------------------------------------------------------------

class STIXBuilder:
    """Build STIX 2.1 objects for a single cycle's bundle.

    Per V1_SPEC.md §4 — every emitted object is stamped with
    `created_by_ref`, `object_marking_refs`, and a sensible `confidence`.
    Per-bundle dedup caches prevent emitting the same foundation
    object twice within one bundle (OpenCTI deduplicates server-side
    via standard_id anyway; this just trims bundle size).
    """

    def __init__(self, config: Config, sensor_dicts: Optional[list[dict]] = None):
        """Construct a per-bundle builder.

        `sensor_dicts` is the list of sensor configs (currently unused for
        v1.0 — sensor Identity is derived from the event's hostname — but
        plumbed for future use when multi-sensor metadata enrichment
        lands).
        """
        self.config = config
        self.sensor_dicts = sensor_dicts or []
        self._now_iso = datetime.now(timezone.utc).isoformat()

        #: Values refused by validation this bundle. Counted, not silent: a
        #: validator that quietly drops things is indistinguishable from an
        #: extractor that never found any, and this codebase has shipped that
        #: confusion more than once.
        self.rejected_urls = 0
        self.rejected_domains = 0

        # Stable IDs for the operator + TLP marking — referenced everywhere
        self.operator_identity_id = generate_identity_id(
            config.operator.org_name, "organization"
        )
        self.tlp_marking_id = generate_marking_definition_id(config.operator.default_tlp)

        # Per-bundle dedup caches
        self._emitted_ids: set[str] = set()

    # ──────────────────────────────────────────────────────────────────
    # Object stamping (created_by_ref + markings + confidence + timestamps)
    # ──────────────────────────────────────────────────────────────────

    def _stamp(self, obj: dict, *, add_confidence: bool = True) -> dict:
        """Add the common provenance/marking/timestamp fields.

        Idempotent — safe to call on an object that already has these
        fields (we don't overwrite existing values).
        """
        obj.setdefault("spec_version", "2.1")
        obj.setdefault("created", self._now_iso)
        obj.setdefault("modified", self._now_iso)
        obj.setdefault("created_by_ref", self.operator_identity_id)
        obj.setdefault("object_marking_refs", [self.tlp_marking_id])
        if add_confidence:
            obj.setdefault("confidence", self.config.operator.default_confidence)
        return obj

    def _dedup(self, obj: dict) -> Optional[dict]:
        """Return obj if its id hasn't been emitted in this bundle, else None.

        Foundation objects (operator identity, TLP marking) are emitted
        once per bundle; per-session entities (IPv4-Addr, Process, etc.)
        also dedupe naturally because deterministic IDs collapse them.
        """
        oid = obj.get("id")
        if not oid:
            return obj  # let the publisher's validator complain later
        if oid in self._emitted_ids:
            return None
        self._emitted_ids.add(oid)
        return obj

    # ──────────────────────────────────────────────────────────────────
    # Foundation objects
    # ──────────────────────────────────────────────────────────────────

    def build_operator_identity(self) -> dict:
        obj = {
            "type": "identity",
            "id": self.operator_identity_id,
            "name": self.config.operator.org_name,
            "identity_class": "organization",
            "description": "tpot2cti operator — emits all objects in this bundle.",
        }
        return self._stamp(obj, add_confidence=False)

    def build_tlp_marking(self) -> dict:
        """STIX 2.1 standard TLP marking-definition.

        We use the deterministic id from stix_ids.generate_marking_definition_id
        which maps to STIX's published TLP marking IDs (those are the canonical
        statics the rest of the threat-intel ecosystem references).
        """
        tlp = self.config.operator.default_tlp
        obj = {
            "type": "marking-definition",
            "id": self.tlp_marking_id,
            "definition_type": "tlp",
            "definition": {"tlp": tlp.lower().replace("+strict", "")},
            "name": f"TLP:{tlp}",
        }
        # Marking definitions don't carry created_by_ref or object_marking_refs
        # per STIX 2.1 — strip them after _stamp() would have added them.
        # Cleaner: just don't call _stamp.
        obj.setdefault("spec_version", "2.1")
        obj.setdefault("created", self._now_iso)
        return obj

    def build_sensor_identity(self, sensor_hostname: str) -> Optional[dict]:
        if not sensor_hostname:
            return None
        sid = generate_sensor_id(sensor_hostname)
        obj = {
            "type": "identity",
            "id": sid,
            "name": sensor_hostname,
            "identity_class": "system",
            "description": f"T-Pot sensor: {sensor_hostname}",
        }
        return self._dedup(self._stamp(obj, add_confidence=False))

    def build_country_location(
        self,
        country_code: str,
        country_name: Optional[str] = None,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        """Country-level Location SDO.

        Per 2026-05-22 audit #6: accepts an optional ``session`` like the
        other observable-style builders so the Location page in OpenCTI
        gets a context description + parser-derived labels + the actual
        first-seen timestamp.  Geographic browse views in particular
        benefit — a bare ``"RO"`` is far less useful than ``"RO — sourcing
        Cowrie SSH attacks via node2"``.
        """
        if not country_code:
            return None
        cc = country_code.upper()
        obj = {
            "type": "location",
            "id": generate_country_location_id(cc),
            "country": cc,
            "name": country_name or cc,
        }
        if session is not None:
            cname = country_name or cc
            obj["x_opencti_description"] = (
                f"Country observed sourcing honeypot attacks: {cname} ({cc}). "
                f"Recent activity: {session.src_ip} via {session.event_type} "
                f"on sensor {session.sensor_hostname!r}."
            )
            obj["x_opencti_labels"] = sorted(set(
                parser_labels_for(session.event_type, session.sensor_hostname) + ["attacker-country"]
            ))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        return self._dedup(self._stamp(obj, add_confidence=False))

    def build_city_location(
        self,
        country_code: str,
        city: str,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        """City-level Location SDO.

        See :meth:`build_country_location` for the ``session`` rationale —
        same shape, scoped to the (country, city) pair.
        """
        if not (country_code and city):
            return None
        cc = country_code.upper()
        obj = {
            "type": "location",
            "id": generate_city_location_id(cc, city),
            "city": city,
            "country": cc,
            "name": f"{city}, {cc}",
        }
        if session is not None:
            obj["x_opencti_description"] = (
                f"City observed sourcing honeypot attacks: {city}, {cc}. "
                f"Recent activity: {session.src_ip} via {session.event_type} "
                f"on sensor {session.sensor_hostname!r}."
            )
            obj["x_opencti_labels"] = sorted(set(
                parser_labels_for(session.event_type, session.sensor_hostname) + ["attacker-city"]
            ))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        return self._dedup(self._stamp(obj, add_confidence=False))

    def build_autonomous_system(
        self,
        asn: int,
        organization: Optional[str] = None,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        if asn is None:
            return None
        obj = {
            "type": "autonomous-system",
            "id": generate_autonomous_system_id(asn),
            "number": int(asn),
        }
        if organization:
            obj["name"] = organization
        if session is not None:
            obj["x_opencti_description"] = (
                f"AS{int(asn)}"
                + (f" — {organization}" if organization else "")
                + f". Observed sourcing honeypot attacks from "
                + f"{session.src_ip} via {session.event_type}."
            )
            obj["x_opencti_labels"] = sorted(set(
                parser_labels_for(session.event_type, session.sensor_hostname) + ["attacker-as"]
            ))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        refs = _refs_for_as(int(asn))
        if refs:
            obj["external_references"] = refs
        return self._dedup(self._stamp(obj, add_confidence=False))

    def build_attack_pattern(
        self,
        name: str,
        mitre_id: Optional[str] = None,
        *,
        session: Optional[AttackSession] = None,
    ) -> dict:
        """AttackPattern SDO (optionally tied to a MITRE ATT&CK technique).

        Per 2026-05-22 audit #6: accepts an optional ``session`` so the
        pattern carries an evidence description + parser labels, mirroring
        the enrichment shape we already apply to Indicator / AS / IP.
        Without ``session`` the bare SDO is still emitted (drive-by path,
        unit tests).
        """
        obj = {
            "type": "attack-pattern",
            "id": generate_attack_pattern_id(name),
            "name": name,
        }
        if mitre_id:
            # x_mitre_id is OpenCTI's merge key for attack-patterns: setting it
            # makes our honeypot-observed pattern resolve INTO the canonical
            # ATT&CK technique node from the bundled MITRE connector, so the
            # native Navigator/matrix reflects honeypot activity.
            obj["x_mitre_id"] = mitre_id
            obj["external_references"] = [{
                "source_name": "mitre-attack",
                "external_id": mitre_id,
                "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
            }]
        if session is not None:
            mitre_str = f" (MITRE {mitre_id})" if mitre_id else ""
            obj["description"] = (
                f"Attack pattern {name!r}{mitre_str} observed in honeypot "
                f"telemetry: {session.src_ip} via {session.event_type} on "
                f"sensor {session.sensor_hostname!r}."
            )
            # AttackPattern is an SDO so it gets canonical objectLabel
            # via labels= rather than x_opencti_labels (the latter is for SCOs).
            obj["labels"] = sorted(set(
                parser_labels_for(session.event_type, session.sensor_hostname) + ["attack-pattern"]
            ))
        # NOTE: return the dedup result directly (None on an already-emitted
        # id) — like every sibling build_* method. The former ` or obj`
        # fallback re-emitted the full SDO on every duplicate, and because
        # build_session_attack_patterns() runs for EVERY session, the ~30
        # unique techniques were re-minted once per substantive session:
        # a busy catch-up window produced ~947k duplicate attack-pattern
        # dicts, ballooning memory and overflowing SQLite's bind-variable
        # limit in the publisher's pre-dedup state lookup (2026-07-19 →
        # 08-04 ingestion outage). All five callers already guard with
        # `if ap:` / `if not ap: continue`, so None is the correct contract.
        return self._dedup(self._stamp(obj, add_confidence=False))

    def build_session_attack_patterns(self, session: AttackSession) -> list[dict]:
        """Behaviour-driven ATT&CK techniques for any session.

        Maps the session's normalised substance signals (creds, auth,
        commands, malware, planted keys, port sweeps) to ATT&CK techniques
        via :func:`tpot2cti.attack_mapping.techniques_for_session`, emits one
        AttackPattern per technique (x_mitre_id → merges with the canonical
        MITRE node) and an ``indicator --indicates--> attack-pattern`` edge
        anchored on the attacker's IP indicator.

        Called centrally by the orchestrator for EVERY session, so all 32
        parsers contribute to the matrix — not just Suricata/web. Overlaps
        with a builder's own AttackPatterns (e.g. web T1190) collapse via
        deterministic ids. Returns ``[]`` when no behaviour evidences a
        technique (the common bare-probe case).
        """
        if not session.src_ip:
            return []
        techniques = attack_mapping.techniques_for_session(session)
        if not techniques:
            return []
        out: list[dict] = []
        ip_ind_id = attacker_ip_indicator_id(session.src_ip)
        for mitre_id, name in techniques:
            ap = self.build_attack_pattern(name, mitre_id=mitre_id, session=session)
            if not ap:
                continue
            out.append(ap)
            if rel := self.build_relationship(
                ip_ind_id, "indicates", ap["id"],
                description=(
                    f"{session.event_type} behaviour on sensor "
                    f"{session.sensor_hostname!r} maps to {name} ({mitre_id})"
                ),
            ):
                out.append(rel)
        return out

    # ──────────────────────────────────────────────────────────────────
    # Malware SDO (family attribution)
    # ──────────────────────────────────────────────────────────────────

    def build_malware(
        self,
        family: str,
        *,
        sample_sha256: Optional[str] = None,
        detection_ratio: Optional[str] = None,
        source: str = "virustotal",
        description: Optional[str] = None,
    ) -> Optional[dict]:
        """Malware SDO for a *confirmed, named* family.

        Returns ``None`` unless the family survives
        :func:`normalize_malware_family` — callers MUST also apply their own
        detection-count gate before calling. Emitting a Malware SDO for a
        generic or auto-generated vendor label is worse than emitting nothing:
        it pollutes the graph and, once exported, misattributes someone else's
        infrastructure. (The predecessor platform had an abuse.ch key banned
        for exactly this class of mistake.)
        """
        fam = normalize_malware_family(family)
        if not fam:
            return None
        obj = {
            "type": "malware",
            "id": generate_malware_id(fam),
            "name": fam,
            "is_family": True,
            "labels": sorted({f"source:{source}", "malware-family"}),
        }
        # Callers that did NOT capture a sample must say so: the default
        # wording asserts first-party capture, and attaching it to a
        # list-derived attribution would be a false provenance claim on the
        # highest-confidence object this codebase emits.
        bits = [description or
                f"Malware family {fam!r} attributed from honeypot-captured sample(s)."]
        if sample_sha256:
            bits.append(f"First attributed via sha256:{sample_sha256[:16]}….")
        if detection_ratio:
            bits.append(f"Multi-engine detection at attribution time: {detection_ratio}.")
        obj["description"] = " ".join(bits)
        return self._dedup(self._stamp(obj))

    # ──────────────────────────────────────────────────────────────────
    # SCOs (observables)
    # ──────────────────────────────────────────────────────────────────

    def build_ipv4(
        self,
        ip: str,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        """Build the IPv4-Addr observable for an attacker IP.

        When `session` is provided we attach OpenCTI's `x_opencti_*`
        extensions so the IP page in the UI carries:
          - a human description naming the parser + sensor + counts
          - source labels (honeypot, <parser>, <protocol>)
          - the actual honeypot event timestamp (not the connector run)
          - a pivot menu (AbuseIPDB / VT / Shodan / Censys / GreyNoise)

        Without session, we still emit a minimal observable so the
        publisher's drive-by path (and any unit tests) keep working.
        """
        fam = canonical_ip(ip)
        if fam is None or fam[0] != "ipv4":
            return None
        return self._build_ip_observable("ipv4-addr", fam[1], session)

    def build_ipv6(
        self,
        ip: str,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        """Build the IPv6-Addr observable for an attacker IP.

        Same enrichment shape as :meth:`build_ipv4` (description, score,
        labels, pivot menu), but for IPv6. The address is canonicalized
        (compressed, lowercase) so its id is stable across notations.
        """
        fam = canonical_ip(ip)
        if fam is None or fam[0] != "ipv6":
            return None
        return self._build_ip_observable("ipv6-addr", fam[1], session)

    def build_ip_observable(
        self,
        ip: str,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        """Version-aware attacker-IP observable: IPv4 or IPv6 (else None)."""
        fam = canonical_ip(ip)
        if fam is None:
            return None
        kind, canon = fam
        return self._build_ip_observable(
            "ipv6-addr" if kind == "ipv6" else "ipv4-addr", canon, session
        )

    def _build_ip_observable(
        self, stix_type: str, ip: str, session: Optional[AttackSession]
    ) -> Optional[dict]:
        """Shared body for build_ipv4 / build_ipv6 (ip is already validated
        and, for IPv6, canonical)."""
        is_v6 = stix_type == "ipv6-addr"
        obj = {
            "type": stix_type,
            "id": generate_ipv6_id(ip) if is_v6 else generate_ipv4_id(ip),
            "value": ip,
        }
        # OpenCTI extensions — populated when we have session context.
        if session is not None:
            obj["x_opencti_description"] = _describe_ip(ip, session)
            obj["x_opencti_score"] = _ip_score(session)
            obj["x_opencti_labels"] = sorted(
                set(parser_labels_for(session.event_type, session.sensor_hostname))
            )
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        # Pivot menu — adds external_references; OpenCTI renders these as
        # buttons on the IP detail page.
        refs = _refs_for_ipv6(ip) if is_v6 else _refs_for_ipv4(ip)
        if refs:
            obj["external_references"] = refs
        return self._dedup(self._stamp(obj))

    def build_file(
        self,
        sha256: str,
        *,
        name: Optional[str] = None,
        size: Optional[int] = None,
        session: Optional[AttackSession] = None,
        labels: Optional[list[str]] = None,
        description: Optional[str] = None,
    ) -> Optional[dict]:
        """File SCO keyed on SHA-256.

        ``labels`` / ``description`` let a non-session caller (e.g.
        ``tpot2cti.ingest.malware``) attach context without inventing a fake
        AttackSession. They are additive: OpenCTI unions labels on upsert, so
        a File that CORE already created from honeypot logs keeps its existing
        labels and attacker relationships.
        """
        if not sha256:
            return None
        sha256_lc = sha256.lower()
        obj = {
            "type": "file",
            "id": generate_file_id(sha256),
            "hashes": {"SHA-256": sha256_lc},
        }
        if name:
            obj["name"] = name
        if size is not None:
            obj["size"] = int(size)
        if session is not None:
            obj["x_opencti_description"] = (
                f"File sha256:{sha256_lc[:16]}… dropped by attacker "
                f"{session.src_ip} via {session.event_type} on sensor "
                f"{session.sensor_hostname!r}. First seen "
                f"{session.first_seen.isoformat()}."
            )
            obj["x_opencti_labels"] = sorted(set(
                parser_labels_for(session.event_type, session.sensor_hostname) + ["malware-sample"]
            ))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        if labels:
            obj["x_opencti_labels"] = sorted(set(
                list(obj.get("x_opencti_labels") or []) + list(labels)
            ))
        if description and not obj.get("x_opencti_description"):
            obj["x_opencti_description"] = description
        refs = _refs_for_file(sha256_lc)
        if refs:
            obj["external_references"] = refs
        return self._dedup(self._stamp(obj))

    def build_url(
        self,
        url: str,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        url = valid_url(url)
        if url is None:
            # Was `if not url: return None` — no validation whatsoever, which
            # is how 2,468 bare request paths ("/admin.php") and a User-Agent
            # string became URL observables. A URL naming no host cannot be
            # blocked, hunted or attributed by any consumer.
            self.rejected_urls += 1
            return None
        obj = {
            "type": "url",
            "id": generate_url_id(url),
            "value": url,
        }
        if session is not None:
            obj["x_opencti_description"] = (
                f"URL referenced by attacker {session.src_ip} via "
                f"{session.event_type} on sensor "
                f"{session.sensor_hostname!r}."
            )
            obj["x_opencti_labels"] = sorted(set(
                parser_labels_for(session.event_type, session.sensor_hostname) + ["attacker-referenced"]
            ))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        refs = _refs_for_url(url)
        if refs:
            obj["external_references"] = refs
        return self._dedup(self._stamp(obj))

    def build_domain(
        self,
        fqdn: str,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        if not fqdn:
            return None
        # Reject malformed values (IP literals, ports, paths, bare labels)
        # before OpenCTI bounces them as "Observable is not correctly
        # formatted" — which also dangles any resolves-to edge to them.
        # valid_domain additionally requires a REAL TLD: shape alone let
        # `huangxcdh.html` and `azenv.nethttp` through for months.
        fqdn_lc = valid_domain(fqdn)
        if fqdn_lc is None:
            logger.debug(f"build_domain: skipping malformed domain {fqdn!r}")
            self.rejected_domains += 1
            return None
        obj = {
            "type": "domain-name",
            "id": generate_domain_id(fqdn),
            "value": fqdn_lc,
        }
        if session is not None:
            obj["x_opencti_description"] = (
                f"Domain {fqdn_lc} referenced by attacker {session.src_ip} "
                f"via {session.event_type} on sensor "
                f"{session.sensor_hostname!r}."
            )
            obj["x_opencti_labels"] = sorted(set(
                parser_labels_for(session.event_type, session.sensor_hostname) + ["attacker-referenced"]
            ))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        refs = _refs_for_domain(fqdn_lc)
        if refs:
            obj["external_references"] = refs
        return self._dedup(self._stamp(obj))

    def build_referenced_ipv4(
        self, ip: str, *, session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        """A plain IPv4-Addr observable for a host *referenced by* an attacker
        (e.g. a malware payload / C2 endpoint in a wget/curl command) -- distinct
        from build_ipv4, which describes the attacker themselves."""
        if not ip or not _IPV4_RE.match(ip):
            return None
        obj = {"type": "ipv4-addr", "id": generate_ipv4_id(ip), "value": ip}
        if session is not None:
            obj["x_opencti_description"] = (
                f"Endpoint referenced by attacker {session.src_ip} via "
                f"{session.event_type} (malware payload / C2 host)."
            )
            obj["x_opencti_labels"] = ["attacker-referenced", "malware-c2"]
            obj["x_opencti_score"] = 75
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        return self._dedup(self._stamp(obj))

    def build_process(self, session: AttackSession, commands: list[str]) -> Optional[dict]:
        """Process SDO carrying the attacker's command transcript.

        Enriched per the same pattern as build_ipv4 / build_url / etc.
        (port of PoC's observable enrichment): x_opencti_description
        names the attacker + sensor + parser context, x_opencti_labels
        carries the parser-source tags, x_opencti_created_at is the
        actual session timestamp so OpenCTI's "Original Creation Date"
        column reflects when the attack ran (not when the connector
        ingested it). Per the live cycle 16 review — a bare Process
        with just command_line and TLP marking is hard to use; the
        analyst can't tell which sensor/parser the commands came from.
        """
        if not commands:
            return None
        # Drop pure-recon sessions (miner fingerprint flood etc.) from
        # OpenCTI; raw events stay in ES/Kibana. A single meaty command
        # keeps the full transcript. See _session_is_recon_only.
        if self.config.cycle.drop_recon_process and _session_is_recon_only(commands):
            return None
        # Cap commands to MAX_COMMANDS_PER_PROCESS for bundle-size sanity
        capped = commands[:MAX_COMMANDS_PER_PROCESS]
        # Normalize ephemeral temp-file paths (e.g. automated scp malware-drop
        # probes: scp -qt "/tmp/<random>") so near-identical sessions do not
        # each spawn a unique Process observable.
        capped = [_TMPFILE_RE.sub(r"\1/<tmpfile>", c) for c in capped]
        truncated_marker = (
            f"\n... and {len(commands) - MAX_COMMANDS_PER_PROCESS} more"
            if len(commands) > MAX_COMMANDS_PER_PROCESS else ""
        )
        cmd_line = "\n".join(capped) + truncated_marker
        # Pure scp-to-tempfile noise collapses to one content-addressed Process
        # (keeps the TTP signal as a single observable with many sightings).
        _stripped = [c.strip() for c in capped if c.strip()]
        _is_scp_noise = bool(_stripped) and all(
            c.startswith("scp ") and "/<tmpfile>" in c for c in _stripped
        )
        _proc_id = (
            sdo_id("process", "process", session.sensor_hostname, cmd_line)
            if _is_scp_noise
            else generate_process_id(session.sensor_hostname, session.session_id)
        )
        obj = {
            "type": "process",
            "id": _proc_id,
            "command_line": cmd_line,
            "x_opencti_description": (
                f"Command sequence executed by attacker {session.src_ip} "
                f"in a {session.event_type} session on sensor "
                f"{session.sensor_hostname!r} "
                f"({len(commands)} command(s), "
                f"first seen {session.first_seen.isoformat()})."
            ),
            "x_opencti_labels": sorted(set(
                parser_labels_for(session.event_type, session.sensor_hostname) + ["command-transcript"]
            )),
            "x_opencti_created_at": session.first_seen.isoformat(),
        }
        return self._dedup(self._stamp(obj))

    def build_cryptographic_key(
        self,
        value: str,
        *,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        """Cryptographic-Key SCO (HASSH / SSH client fingerprint / etc.).

        Type spelling is critical: `cryptographic-key` per STIX 2.1 and
        LESSONS §8.4. The custom `x-opencti-cryptographic-key` typo gets
        silently dropped by OpenCTI's worker — never use it.

        When `session` is provided, attaches OpenCTI x_opencti_*
        extensions so the HASSH page shows analyst-useful context (which
        attacker IP it came from, which sensor, what SSH client banner).
        Plugged in 2026-05-22 after spot-check showed Cryptographic-Key
        as 100% missing description+labels — same gap Process had until
        commit f66da5c.
        """
        if not value:
            return None
        obj = {
            "type": "cryptographic-key",   # correct type per LESSONS §8.4
            "id": generate_cryptographic_key_id(value),
            "value": value,
        }
        if session is not None:
            ssh_ver = (session.ssh_version or "unknown SSH client").strip() or "unknown SSH client"
            obj["x_opencti_description"] = (
                f"HASSH SSH-client fingerprint {value[:16]}… observed from "
                f"attacker {session.src_ip} via {session.event_type} on "
                f"sensor {session.sensor_hostname!r}. Banner: {ssh_ver}. "
                f"Same fingerprint across different IPs implies same SSH "
                f"client / tool — useful for campaign correlation."
            )
            obj["x_opencti_labels"] = sorted(set(
                parser_labels_for(session.event_type, session.sensor_hostname) + ["ssh-fingerprint", "hassh"]
            ))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        return self._dedup(self._stamp(obj))

    def build_attacker_ssh_key(
        self,
        key_info: dict,
        *,
        session: Optional[AttackSession] = None,
        context: str = "planted",
    ) -> Optional[dict]:
        """Cryptographic-Key SCO for an attacker SSH public key.

        `context` is "planted" (written to authorized_keys for persistence)
        or "authenticated" (the key they logged in WITH). Both mint the SAME
        id for the same key material — that shared id is the pivot, joining
        "who holds this private key" to "where they installed the public
        half" — but they are different claims, so the description and labels
        differ. Nothing here may assert the union of both.

        Distinct from :meth:`build_cryptographic_key` (which models a
        HASSH SSH-client hash) — this one represents the public key
        material the attacker dropped into the victim's
        ``~/.ssh/authorized_keys``.  The observable value is the SHA256
        fingerprint of the key blob (matching OpenSSH ``ssh-keygen
        -lf`` semantics minus the ``SHA256:`` prefix and base64
        encoding); the full key + type + comment go in the description
        so operators can copy/paste it into a hunt.

        Every attacker IP that planted the SAME key produces the SAME
        UUID5 here, so OpenCTI dedups them onto one SCO.  Each IP's
        Cowrie session adds a ``related-to`` edge to that one SCO —
        and clicking the SCO in OpenCTI's UI walks those edges back to
        the entire campaign footprint.  This is the operator-pivot
        we couldn't get from HASSH alone (HASSH groups by client
        tool; a planted key groups by C&C identity).
        """
        if not isinstance(key_info, dict):
            return None
        fingerprint = key_info.get("fingerprint")
        key_blob = key_info.get("key")
        key_type = key_info.get("type") or "ssh-rsa"
        comment = key_info.get("comment") or ""
        if not fingerprint or not key_blob:
            return None

        # Compose a copy-paste-ready authorized_keys line for the desc.
        full_line = f"{key_type} {key_blob}"
        if comment:
            full_line += f" {comment}"

        obj = {
            "type": "cryptographic-key",
            "id": generate_cryptographic_key_id(fingerprint),
            # The visible "value" is the SHA256 fingerprint — short,
            # uniquely identifying, copy-pasteable. Operators wanting
            # the full key material read the description.
            "value": f"SHA256:{fingerprint}",
        }
        comment_disp = comment or "∅ (no comment)"
        desc_lines = [
            # Deliberately does NOT say "planted". The same SCO id is minted
            # for a key the attacker AUTHENTICATED with and one they wrote to
            # authorized_keys — that shared id is the point, it joins the two
            # halves of the same actor. But the SCO cannot assert which
            # happened, because it may be both. The per-edge relationship
            # descriptions carry the specific claim; this line must stay true
            # of every path that reaches it.
            (f"Attacker-planted SSH public key (campaign IoC)."
             if context == "planted"
             else f"Attacker SSH public key used to AUTHENTICATE (campaign "
                  f"IoC) — they hold the private half."),
            f"",
            f"Key type:      {key_type}",
            f"SHA256 fp:     {fingerprint}",
            f"Comment:       {comment_disp}",
            f"",
            f"authorized_keys line (verbatim):",
            f"    {full_line}",
            f"",
            f"Every attacker IP that AUTHENTICATED WITH or PLANTED this "
            f"key links to this SCO via `related-to` — the per-edge "
            f"description says which. Click 'Related entities' to see the "
            f"campaign footprint.",
        ]
        if session is not None:
            desc_lines.insert(
                1,
                f"First observed: {session.first_seen.isoformat()} from "
                f"{session.src_ip} via Cowrie on "
                f"sensor {session.sensor_hostname!r}.",
            )
        obj["x_opencti_description"] = "\n".join(desc_lines)

        # A label is an assertion too — only the planted path may claim it.
        labels = ["ssh-key", "campaign-ioc", key_type]
        labels.append("planted-key" if context == "planted" else "auth-key")
        if comment:
            # Comment is often a botnet tag ("mdrfckr" for Outlaw,
            # "JenX" for that family, etc.) — make it a label for
            # quick filtering.
            tag = re.sub(r'[^A-Za-z0-9._-]', '', comment.lower())[:32]
            if tag:
                labels.append(f"comment:{tag}")
        if session is not None:
            labels.extend(parser_labels_for(session.event_type, session.sensor_hostname))
            obj["x_opencti_created_at"] = session.first_seen.isoformat()
        obj["x_opencti_labels"] = sorted(set(labels))
        # Confidence/score: a planted-key SCO is one of the highest-
        # signal IoCs we emit. Score it at 85 so it stands out vs the
        # routine SCO-50 baseline.
        obj["x_opencti_score"] = 85
        return self._dedup(self._stamp(obj))

    # ──────────────────────────────────────────────────────────────────
    # SDOs (indicators, notes, vulnerabilities)
    # ──────────────────────────────────────────────────────────────────

    def build_ip_indicator(
        self,
        ip: str,
        *,
        session: Optional[AttackSession] = None,
        session_count: int = 1,
    ) -> Optional[dict]:
        """Build a STIX Indicator for an attacker IP.

        Per the PoC pattern (
        tsec-tpot-connectors/tsec-tpot-hp-connector/src/stix/indicators.py
        ): rich `name` template, multi-paragraph `description` with
        session/event counts + date range + severity context, source
        labels, computed score, valid_until from validity_days.

        When `session` is None, falls back to a minimal indicator —
        keeps backward compat with the few smoke tests that build
        bare indicators.

        Handles both IPv4 and IPv6 attacker addresses.
        """
        fam = canonical_ip(ip)
        if fam is None:
            return None
        is_v6 = fam[0] == "ipv6"
        ip = fam[1]  # canonical form

        event_type = session.event_type if session else None
        n = session_count if session_count is not None else (
            session.event_count if session else 1
        )

        # Score + valid_from/valid_until
        score = _signal_score(session)
        first_seen = session.first_seen if session else datetime.now(timezone.utc)
        last_seen = session.last_seen if session else datetime.now(timezone.utc)
        valid_until = last_seen + timedelta(days=DEFAULT_INDICATOR_VALIDITY_DAYS)

        # Description — multi-paragraph context (PoC pattern). Skip when no
        # session info available (smoke tests + edge cases).
        description: Optional[str] = None
        if session is not None:
            start_date = session.first_seen.strftime("%Y-%m-%d %H:%M")
            end_date = session.last_seen.strftime("%Y-%m-%d %H:%M")
            bits: list[str] = [
                f"Malicious IP {ip} observed via {event_type} on sensor "
                f"{session.sensor_hostname!r} in {n} correlated session"
                f"{'s' if n != 1 else ''} ({session.event_count} total "
                f"event{'s' if session.event_count != 1 else ''}). "
                f"Activity between {start_date} and {end_date} UTC."
            ]
            # Substance-signal hints — what made this session score high.
            sig_bits: list[str] = []
            if session.auth_success:
                sig_bits.append("successful authentication")
            if session.commands:
                sig_bits.append(f"{len(session.commands)} command(s) executed")
            if session.malware_hashes:
                sig_bits.append(
                    f"{len(session.malware_hashes)} file(s) dropped"
                )
            if session.credentials_tried:
                sig_bits.append(
                    f"{len(session.credentials_tried)} credential attempt(s)"
                )
            if sig_bits:
                bits.append("Substance signals: " + ", ".join(sig_bits) + ".")
            # Severity blurb tuned to the score band.
            if score >= 80:
                bits.append(
                    "High threat score: sophisticated attack patterns "
                    "(successful auth, command execution, or malware "
                    "delivery). Consider sharing as actor IoC."
                )
            elif score >= 60:
                bits.append(
                    "Medium threat score: active attack attempts with "
                    "multiple authentication tries or reconnaissance "
                    "activity."
                )
            else:
                bits.append(
                    "Baseline-or-low score: drive-by probe behavior. "
                    "Useful for noise/scanner correlation, not actor "
                    "attribution."
                )
            description = " ".join(bits)

        obj = {
            "type": "indicator",
            "id": generate_ip_indicator_id(ip),
            "name": _format_indicator_name(event_type, ip, n),
            "pattern_type": "stix",
            "pattern": f"[ipv6-addr:value = '{ip}']" if is_v6
                       else f"[ipv4-addr:value = '{ip}']",
            "valid_from": first_seen.isoformat(),
            "valid_until": valid_until.isoformat(),
            "indicator_types": ["malicious-activity"],
            "labels": sorted(set(parser_labels_for(event_type))),
            # OpenCTI custom properties (the dashboard widgets read these).
            "x_opencti_score": score,
            "x_opencti_main_observable_type": "IPv6-Addr" if is_v6 else "IPv4-Addr",
        }
        if description:
            obj["description"] = description
        # Pivot menu on the indicator too — duplicates the SCO's refs but
        # an analyst on the indicator page wants the same one-click options.
        refs = _refs_for_ipv6(ip) if is_v6 else _refs_for_ipv4(ip)
        if refs:
            obj["external_references"] = refs
        return self._dedup(self._stamp(obj))

    def build_file_indicator(
        self,
        sha256: str,
        *,
        name: Optional[str] = None,
        session: Optional[AttackSession] = None,
    ) -> Optional[dict]:
        if not sha256:
            return None
        sha_lc = sha256.lower()
        n = session.event_count if session else 1
        score = _signal_score(session)
        first_seen = session.first_seen if session else datetime.now(timezone.utc)
        last_seen = session.last_seen if session else datetime.now(timezone.utc)
        valid_until = last_seen + timedelta(days=DEFAULT_INDICATOR_VALIDITY_DAYS)

        description: Optional[str] = None
        if session is not None:
            description = (
                f"File sha256:{sha_lc} dropped/downloaded by attacker "
                f"{session.src_ip} via {session.event_type} on sensor "
                f"{session.sensor_hostname!r}. First seen "
                f"{session.first_seen.strftime('%Y-%m-%d %H:%M')} UTC. "
                f"Honeypot sample — bytes available via the malware-vault "
                f"sidecar if enabled."
            )

        obj = {
            "type": "indicator",
            "id": generate_file_indicator_id(sha256),
            "name": name or f"Honeypot file SHA256 {sha_lc[:16]}…",
            "pattern_type": "stix",
            "pattern": f"[file:hashes.'SHA-256' = '{sha_lc}']",
            "valid_from": first_seen.isoformat(),
            "valid_until": valid_until.isoformat(),
            "indicator_types": ["malicious-activity"],
            "labels": sorted(set(
                parser_labels_for(session.event_type if session else None)
                + ["malware-sample"]
            )),
            "x_opencti_score": score,
            "x_opencti_main_observable_type": "StixFile",
        }
        if description:
            obj["description"] = description
        refs = _refs_for_file(sha_lc)
        if refs:
            obj["external_references"] = refs
        return self._dedup(self._stamp(obj))

    def build_session_note(
        self,
        session: AttackSession,
        body_md: str,
        abstract: Optional[str] = None,
        object_refs: Optional[list[str]] = None,
    ) -> Optional[dict]:
        """Per-session Note SDO.

        WARNING: per LESSONS §7.1 we do NOT emit a per-IP per-cycle
        Activity Report.  Use this only for genuinely-per-session content
        (a Cowrie command transcript, a Honeytrap payload hexdump that's
        worth preserving).  For aggregated content prefer a rolling per-IP
        Note (e.g. `build_ip_credential_note()`) or skip the Note entirely
        and let the per-event Sighting carry the signal.
        """
        if not body_md:
            return None
        # Cap to MAX_NOTE_BODY_BYTES
        if len(body_md.encode("utf-8")) > MAX_NOTE_BODY_BYTES:
            body_md = body_md[:MAX_NOTE_BODY_BYTES] + "\n... [truncated]"
        obj = {
            "type": "note",
            "id": generate_session_note_id(session.sensor_hostname, session.session_id),
            "abstract": abstract or f"Session {session.session_id[:16]}… from {session.src_ip}",
            "content": body_md,
            "object_refs": object_refs or [],
        }
        return self._dedup(self._stamp(obj))

    def build_ip_credential_note(
        self,
        ip: str,
        credentials: list[dict],
        *,
        max_rows: int = 200,
    ) -> Optional[dict]:
        """One rolling Note per attacker IP summarising credential attempts.

        `credentials` is the per-IP summary from the credential store
        (each: username, password, attempts, succeeded, service, port). A
        bruteforce of tens of thousands of pairs becomes ONE Note here — the
        bulk lives in the store, not OpenCTI. Idempotent id → OpenCTI upserts
        the same Note as the attacker's activity grows. Attached to the IP
        observable via object_refs.

        Rows are capped (`max_rows`, accepted creds always shown first) so a
        spray with a huge unique-pair count can't blow the Note body.
        """
        if not ip or not credentials:
            return None
        sco_id = attacker_ip_observable_id(ip)
        if sco_id is None:  # malformed IP — nothing valid to attach the Note to
            return None
        # Accepted logins first, then by attempt volume.
        rows = sorted(
            credentials,
            key=lambda r: (not r.get("succeeded"), -int(r.get("attempts", 0))),
        )
        n_total = len(rows)
        n_success = sum(1 for r in rows if r.get("succeeded"))
        shown = rows[:max_rows]

        def _cell(v: str) -> str:
            # Escape pipes/newlines so the markdown table stays intact.
            return str(v).replace("|", "\\|").replace("\n", " ")[:128] or "∅"

        lines = [
            f"# Credential attempts from {ip}",
            "",
            f"- **Unique pairs:** {n_total}"
            + (f" (showing top {max_rows})" if n_total > max_rows else ""),
            f"- **Accepted logins:** {n_success}",
            "",
            "| Username | Password | Attempts | Service:Port | Accepted |",
            "|---|---|---:|---|:---:|",
        ]
        for r in shown:
            lines.append(
                f"| {_cell(r.get('username'))} | {_cell(r.get('password'))} "
                f"| {int(r.get('attempts', 0))} "
                f"| {_cell(r.get('service'))}:{r.get('port')} "
                f"| {'✅' if r.get('succeeded') else ''} |"
            )
        body_md = "\n".join(lines)
        if len(body_md.encode("utf-8")) > MAX_NOTE_BODY_BYTES:
            body_md = body_md[:MAX_NOTE_BODY_BYTES] + "\n... [truncated]"

        abstract = (
            f"Credentials from {ip}: {n_total} unique pair(s), "
            f"{n_success} accepted."
        )
        obj = {
            "type": "note",
            "id": generate_credential_note_id(ip),
            "abstract": abstract,
            "content": body_md,
            "object_refs": [sco_id],
        }
        return self._dedup(self._stamp(obj))

    def build_vulnerability(self, cve_id: str, *, description: Optional[str] = None) -> Optional[dict]:
        if not cve_id:
            return None
        obj = {
            "type": "vulnerability",
            "id": generate_vulnerability_id(cve_id),
            "name": cve_id,
            "external_references": [{
                "source_name": "cve",
                "external_id": cve_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }],
        }
        if description:
            obj["description"] = description
        return self._dedup(self._stamp(obj))

    def build_campaign(
        self,
        *,
        artifact_key: str,
        name: str,
        description: Optional[str] = None,
        objective: Optional[str] = None,
        first_seen: Optional[str] = None,
        last_seen: Optional[str] = None,
        labels: Optional[list[str]] = None,
    ) -> dict:
        """STIX 2.1 Campaign SDO for a shared-IoC attacker grouping.

        Keyed deterministically off ``artifact_key`` (e.g.
        ``"malware:<sha256>"``) so every cycle that observes another IP
        sharing the artifact attributes to the SAME node — OpenCTI then
        accumulates the whole coordinated set under one Campaign. See
        tpot2cti/campaigns.py for membership logic.
        """
        obj = {
            "type": "campaign",
            "id": generate_campaign_id(artifact_key),
            "name": name,
        }
        if description:
            obj["description"] = description
        if objective:
            obj["objective"] = objective
        if first_seen:
            obj["first_seen"] = first_seen
        if last_seen:
            obj["last_seen"] = last_seen
        if labels:
            obj["labels"] = sorted(set(labels))
        return self._dedup(self._stamp(obj))

    # ──────────────────────────────────────────────────────────────────
    # Relationships and Sightings
    # ──────────────────────────────────────────────────────────────────

    def build_relationship(
        self,
        src_id: str,
        relationship_type: str,
        dst_id: str,
        *,
        description: Optional[str] = None,
    ) -> Optional[dict]:
        if not (src_id and dst_id and relationship_type) or src_id == dst_id:
            return None
        obj = {
            "type": "relationship",
            "id": generate_relationship_id(src_id, dst_id, relationship_type),
            "relationship_type": relationship_type,
            "source_ref": src_id,
            "target_ref": dst_id,
        }
        if description:
            obj["description"] = description
        return self._dedup(self._stamp(obj))

    def build_sighting(
        self,
        target_ref: str,
        sensor_hostname: str,
        session: AttackSession,
        *,
        count: int = 1,
        description: Optional[str] = None,
        id_discriminator: str = "",
    ) -> Optional[dict]:
        """Sighting SDO — per V1_SPEC §4 'sighting target=Indicator,
        where=sensor Identity'.

        ``target_ref`` is the STIX id this Sighting refers to.  In
        STIX 2.1 the spec says ``sighting_of_ref`` SHOULD be an SDO
        (typically an Indicator), but the field accepts any SDO/SCO id.
        We exploit that to emit *two* Sightings per session (see
        :meth:`build_dual_sighting`): one on the IP Indicator and one
        directly on the IPv4-Addr observable, so OpenCTI's "Sightings"
        tab populates on both pages.  The optional ``id_discriminator``
        threads through to :func:`generate_sighting_id` so the two
        Sightings get distinct deterministic IDs.

        Per LESSONS §7.1: putting per-session activity summaries
        in the Sighting `description` is the preferred place for
        low-signal-per-event protocols (Honeytrap probe payload, Fallback
        unknown-type blurb). Beats spewing 50k+ Notes/day that nobody
        reads. Cowrie/SSH sessions still get their own Notes — those
        are the genuinely-per-session content the lesson called out
        as the carve-out.
        """
        if not (target_ref and sensor_hostname):
            return None
        sensor_id = generate_sensor_id(sensor_hostname)
        obj = {
            "type": "sighting",
            "id": generate_sighting_id(
                sensor_hostname, session.session_id, id_discriminator,
            ),
            "sighting_of_ref": target_ref,
            "where_sighted_refs": [sensor_id],
            "first_seen": session.first_seen.isoformat(),
            "last_seen": session.last_seen.isoformat(),
            "count": count,
        }
        if description:
            obj["description"] = description
        return self._dedup(self._stamp(obj))

    def build_dual_sighting(
        self,
        indicator_id: str,
        ipv4_id: Optional[str],
        sensor_hostname: str,
        session: AttackSession,
        *,
        count: int = 1,
        description: Optional[str] = None,
    ) -> list[dict]:
        """Emit Sightings on BOTH the IP Indicator and the IPv4-Addr.

        STIX 2.1 §4.13 says ``sighting_of_ref`` SHOULD be an SDO; OpenCTI's
        Observable→Sightings tab only walks Sightings whose
        ``sighting_of_ref`` is the observable itself (it does NOT follow
        the ``based-on`` edge from Indicator to Observable).  Operators
        clicking through to an IP page therefore see an empty Sightings
        tab — confusing and easy to misread as "we have no telemetry".

        To fix that without losing the STIX-correct Indicator sighting,
        we emit BOTH:

          1. Indicator-side Sighting — preserved ID family
             (``sighting:<sensor>:<session>``).  This is the canonical
             Sighting and is what cross-cycle preservation keys off.
          2. Observable-side Sighting — distinct ID family
             (``sighting:<sensor>:<session>:ipv4``).  Same first/last
             seen, same count, same description, same sensor identity.

        Callers pass the already-resolved ``indicator_id`` and
        ``ipv4_id``; if either is None that side is skipped.
        """
        out: list[dict] = []
        if indicator_id:
            sighting = self.build_sighting(
                indicator_id, sensor_hostname, session,
                count=count, description=description,
            )
            if sighting:
                out.append(sighting)
        if ipv4_id:
            obs_sighting = self.build_sighting(
                ipv4_id, sensor_hostname, session,
                count=count, description=description,
                id_discriminator="ipv4",
            )
            if obs_sighting:
                out.append(obs_sighting)
        return out

    # ──────────────────────────────────────────────────────────────────
    # High-level convenience: build the common entity bundle for one
    # session, regardless of substance.  Parsers can then layer their
    # protocol-specific extras on top.
    # ──────────────────────────────────────────────────────────────────

    # ──────────────────────────────────────────────────────────────────
    # Per-parser session builders (the V0 parser-vs-builder separation rule — STIX-shape decisions
    # live here, not in parsers).  Each method consumes one AttackSession
    # and returns the full per-protocol STIX object list.  The orchestrator
    # (main.run_cycle) dispatches to the right method via _PARSER_DISPATCH.
    # ──────────────────────────────────────────────────────────────────

    def _link_download_chain(self, session: AttackSession) -> list[dict]:
        """Intra-session attack-chain edges so the full story is navigable.

        Two edges, both referencing already-emitted objects by their
        deterministic ids (no duplicate nodes):
          - Process → `related-to` → File: the command session that ran the
            attacker's commands also dropped these files ("what they ran →
            what landed").
          - URL → `related-to` → File: the file was downloaded from this URL,
            paired per `session.downloads` (the exact sha↔url from one
            download event), so the source is explicit, not guessed.

        Without these, File / URL / Process all hang off the IP separately and
        the analyst can't see that command X pulled file Y from URL Z.
        """
        out: list[dict] = []
        if not session.src_ip:
            return out
        file_ids = {
            sha.lower(): generate_file_id(sha)
            for sha in session.malware_hashes if sha
        }
        # Process → File (command session dropped these files)
        if session.commands and file_ids:
            proc_id = generate_process_id(session.sensor_hostname, session.session_id)
            for sha, fid in file_ids.items():
                if rel := self.build_relationship(
                    proc_id, "related-to", fid,
                    description=f"Command session dropped file sha256:{sha[:16]}…",
                ):
                    out.append(rel)
        # URL → File (downloaded-from, explicit per-download pairing)
        seen_pairs: set[tuple] = set()
        for dl in session.downloads:
            sha = (dl.get("sha256") or "").lower()
            url = dl.get("url")
            if not (sha and url) or (url, sha) in seen_pairs:
                continue
            seen_pairs.add((url, sha))
            # build_url returns None for BOTH "already emitted in this bundle"
            # and "failed validation". Only the first is safe to anchor an
            # edge on — referencing a URL that was never built, and never will
            # be, is a dangling ref. `_emitted_ids` tells the two apart; this
            # mirrors the domain path in build_unattributed_payload_objects.
            #
            # The id must come from the CANONICAL value, not the raw input:
            # valid_url strips surrounding whitespace, so hashing `url` would
            # anchor on a different id than the SCO was published under.
            canon = valid_url(url)
            u = self.build_url(url, session=session)
            if u:
                out.append(u)
            if canon is None:
                continue
            url_id = generate_url_id(canon)
            if not (u or url_id in self._emitted_ids):
                continue
            # The File SDO stands on its own, so a rejected URL costs only
            # this edge — the hash is still published.
            if rel := self.build_relationship(
                url_id, "related-to", generate_file_id(sha),
                description=f"File sha256:{sha[:16]}… downloaded from {url[:80]}",
            ):
                out.append(rel)
        return out

    def build_cowrie_session(self, session: AttackSession) -> list[dict]:
        """Build the full Cowrie session STIX graph.

        Caller is expected to have already determined the session is not a
        bare scan (`_is_bare_scan()` in main.py).  For drive-by sessions the
        caller invokes `self.build_driveby_session(session)` instead.

        Emits: sensor + attacker context + IP Indicator + (HASSH key) +
        (Process) + (File + File Indicator) + URLs + Domains + Sighting +
        per-session transcript Note.
        """
        out: list[dict] = []
        if not session.events:
            return out

        # Foundation: sensor + attacker context (IP v4/v6 + geo + AS)
        out.extend(self.build_sensor_context(session.sensor_hostname))
        out.extend(self.build_attacker_context(session.events[0], session=session))

        ipv4_id = attacker_ip_observable_id(session.src_ip)

        # IP Indicator + based-on → IPv4
        ip_ind = self.build_ip_indicator(session.src_ip, session=session)
        if ip_ind:
            out.append(ip_ind)
            if rel := self.build_relationship(
                ip_ind["id"], "based-on", ipv4_id,
                description=f"IP indicator for {session.src_ip}",
            ):
                out.append(rel)

        # HASSH fingerprint → Cryptographic-Key
        if session.hassh:
            ck = self.build_cryptographic_key(session.hassh, session=session)
            if ck:
                out.append(ck)
                if rel := self.build_relationship(
                    ck["id"], "related-to", ipv4_id,
                    description=f"HASSH fingerprint observed from {session.src_ip}",
                ):
                    out.append(rel)

        # Planted SSH public keys → Cryptographic-Key SCOs (campaign IoC).
        # Each unique fingerprint becomes one observable, and every
        # attacker IP that planted that key links to it via `related-to`.
        # Operator pivot: click the key in OpenCTI → see every src_ip
        # that planted it = the full campaign footprint.  Outlaw is the
        # canonical example (470+ src_ips, one key) but this catches any
        # actor doing `echo "ssh-rsa AAA..." >> authorized_keys` style
        # persistence.
        # Keys the attacker AUTHENTICATED with. Same SCO id space as planted
        # keys (identical fingerprint convention), so one key seen on both
        # paths is one observable with edges from both — which is exactly
        # the pivot: "who holds this private key" joined to "where they
        # installed the public half". The edge description keeps the two
        # claims apart; only the planted path may say "installed".
        for key_info in (session.auth_pubkeys or []):
            if not key_info.get("fingerprint"):
                continue
            ck = self.build_attacker_ssh_key(
                key_info, session=session, context="authenticated")
            if not ck:
                continue
            out.append(ck)
            if rel := self.build_relationship(
                ipv4_id, "related-to", ck["id"],
                description=(
                    f"Authenticated to {session.event_type} by public key "
                    f"(type={key_info.get('type')}) — attacker "
                    f"{session.src_ip} holds the private half"
                ),
            ):
                out.append(rel)

        for key_info in (session.planted_ssh_keys or []):
            fp = key_info.get("fingerprint")
            if not fp:
                continue
            ck = self.build_attacker_ssh_key(key_info, session=session)
            if not ck:
                continue
            out.append(ck)
            # IP observable → key (so the key's "Related Entities" tab
            # shows every IP that planted it — the campaign view).
            if rel := self.build_relationship(
                ipv4_id, "related-to", ck["id"],
                description=(
                    f"Planted SSH key (type={key_info.get('type')}, "
                    f"comment={key_info.get('comment') or '∅'!r}) "
                    f"installed by attacker {session.src_ip}"
                ),
            ):
                out.append(rel)
            # IP Indicator → key (so the indicator-side knowledge tab
            # also shows the campaign pivot).
            if ip_ind:
                if rel := self.build_relationship(
                    ip_ind["id"], "related-to", ck["id"],
                    description=f"Indicator for IP that planted SSH key {fp[:12]}…",
                ):
                    out.append(rel)

        # Process (commands)
        process_id: Optional[str] = None
        if session.commands:
            proc = self.build_process(session, session.commands)
            if proc:
                out.append(proc)
                process_id = proc["id"]
                if rel := self.build_relationship(
                    proc["id"], "related-to", ipv4_id,
                    description=f"Commands run by {session.src_ip} in Cowrie session",
                ):
                    out.append(rel)

        # File downloads → StixFile + Indicator + URL/Domain
        for sha256 in session.malware_hashes:
            f = self.build_file(sha256, session=session)
            if f:
                out.append(f)
                if rel := self.build_relationship(
                    f["id"], "related-to", ipv4_id,
                    description=f"File {sha256[:16]}… downloaded by {session.src_ip}",
                ):
                    out.append(rel)
                # File Indicator + based-on
                f_ind = self.build_file_indicator(sha256, session=session)
                if f_ind:
                    out.append(f_ind)
                    if rel := self.build_relationship(
                        f_ind["id"], "based-on", f["id"],
                        description=f"Honeypot-captured file {sha256[:16]}…",
                    ):
                        out.append(rel)

        # URLs (download sources + URLs in commands)
        for url in session.urls:
            url_obj = self.build_url(url, session=session)
            if url_obj:
                out.append(url_obj)
                if rel := self.build_relationship(
                    url_obj["id"], "related-to", ipv4_id,
                    description=f"URL referenced by {session.src_ip}",
                ):
                    out.append(rel)

        # Domains derived from URLs
        for fqdn in session.domains:
            d = self.build_domain(fqdn, session=session)
            if d:
                out.append(d)

        # Dual sighting (Indicator + Observable) — see build_dual_sighting
        # docstring for the OpenCTI UX rationale.
        if ip_ind:
            out.extend(self.build_dual_sighting(
                ip_ind["id"], ipv4_id, session.sensor_hostname, session,
                count=session.event_count,
                description=render_cowrie_sighting_description(session),
            ))

        # Per-session Notes replaced by attacker-profile Notes emitted from
        # main.run_cycle (see tpot2cti/attacker_profile.py); per-session
        # command transcripts are preserved in the Process SDO's
        # command_line field. Per the V0 "don't emit 50K Notes/day" finding + the 2026-05-21 user
        # decision: ONE rolling Note per attacker IP scales; 50 per-session
        # Notes per attacker do not.
        _ = process_id  # referenced above; kept for future per-session links

        # Intra-session attack chain: Process→File (dropped) + URL→File
        # (downloaded-from). Makes the command→malware→source story navigable.
        out.extend(self._link_download_chain(session))

        return out

    def build_suricata_alert(self, session: AttackSession) -> list[dict]:
        """Build the STIX graph for one Suricata alert.

        Because each session wraps a single alert (one_event_per_session),
        we pull metadata directly from the lone event rather than from
        any pre-aggregated session fields.
        """
        out: list[dict] = []
        if not session.events:
            return out
        event = session.events[0]
        meta = event.meta

        # Mirror the alert metadata onto session.meta so downstream
        # consumers can introspect without reaching into events[0].
        for k, v in meta.items():
            session.meta.setdefault(k, v)

        # Foundation: sensor + attacker context (IP v4/v6 + geo + AS)
        out.extend(self.build_sensor_context(session.sensor_hostname))
        out.extend(self.build_attacker_context(event, session=session))

        ipv4_id = attacker_ip_observable_id(session.src_ip)

        # IP Indicator + based-on → IPv4
        ip_ind = self.build_ip_indicator(session.src_ip, session=session)
        if ip_ind:
            out.append(ip_ind)
            if rel := self.build_relationship(
                ip_ind["id"], "based-on", ipv4_id,
                description=f"IP indicator for {session.src_ip}",
            ):
                out.append(rel)

        # ── AttackPattern(s) from MITRE technique metadata ────────────
        attack_pattern_ids: list[str] = []
        techniques: list[str] = meta.get("mitre_techniques") or []
        for tid in techniques:
            name = _KNOWN_MITRE_TECHNIQUES.get(tid)
            if not name:
                logger.debug(
                    f"suricata: unknown MITRE technique id {tid!r} in signature "
                    f"{meta.get('signature')!r}; skipping AttackPattern emission"
                )
                continue
            ap = self.build_attack_pattern(name=name, mitre_id=tid, session=session)
            if ap:
                out.append(ap)
                attack_pattern_ids.append(ap["id"])

        # Fallback: if no recognized MITRE technique attached, emit a
        # generic "Network Attack" AttackPattern so we always have an
        # indicates-target per V1_SPEC §5.2.
        if ip_ind and not attack_pattern_ids and self.config.cycle.emit_generic_attack_pattern:
            generic = self.build_attack_pattern(name="Network Attack", session=session)
            if generic:
                out.append(generic)
                attack_pattern_ids.append(generic["id"])

        # Indicator → indicates → AttackPattern(s)
        if ip_ind:
            for ap_id in attack_pattern_ids:
                if rel := self.build_relationship(
                    ip_ind["id"], "indicates", ap_id,
                    description=(
                        f"Suricata rule {meta.get('signature_id') or '?'}: "
                        f"{meta.get('signature') or 'alert'}"
                    ),
                ):
                    out.append(rel)

        # ── Vulnerabilities (CVE refs from signature name) ────────────
        for cve in meta.get("cves") or []:
            vuln = self.build_vulnerability(
                cve,
                description=f"Referenced by Suricata signature: {meta.get('signature')!r}",
            )
            if vuln:
                out.append(vuln)
                if ip_ind:
                    if rel := self.build_relationship(
                        ip_ind["id"], "indicates", vuln["id"],
                        description=(
                            f"{session.src_ip} attempted exploit of {cve} "
                            f"(Suricata SID {meta.get('signature_id') or '?'})"
                        ),
                    ):
                        out.append(rel)

        # ── Domain-Name (TLS SNI or HTTP host) ────────────────────────
        # Collect candidate domains, dedup, build Domain-Name observables.
        domain_candidates: list[str] = []
        if sni := meta.get("tls_sni"):
            domain_candidates.append(sni)
        if host := meta.get("http_host"):
            if host not in domain_candidates:
                domain_candidates.append(host)

        for fqdn in domain_candidates:
            d = self.build_domain(fqdn, session=session)
            if d:
                out.append(d)
                # Domain-Name → resolves-to → IPv4-Addr (dst_ip preferred,
                # since the SNI/host refers to the destination the
                # attacker is trying to reach; if no dst_ip, fall back to
                # the alert's src_ip per V1_SPEC §5.2 phrasing).
                # Build the target observable via build_ipv4 so it is (a)
                # validated (malformed/IPv6 dst_ip → skipped, not a bad SCO)
                # and (b) present IN this bundle — otherwise the resolves-to
                # edge dangles into MISSING_REFERENCE.
                target_ip = event.dst_ip or session.src_ip
                if target_ip:
                    target_ipv4 = self.build_ipv4(target_ip, session=session)
                    if target_ipv4:
                        out.append(target_ipv4)
                        if rel := self.build_relationship(
                            d["id"], "resolves-to", target_ipv4["id"],
                            description=f"{fqdn} resolved-to {target_ip} per honeypot observation",
                        ):
                            out.append(rel)

        # ── URL observable (if HTTP request URL captured) ─────────────
        if (url := meta.get("http_url")) and (host := meta.get("http_host")):
            full_url = url if url.startswith("http") else f"http://{host}{url}"
            url_obj = self.build_url(full_url, session=session)
            if url_obj:
                out.append(url_obj)
                if rel := self.build_relationship(
                    url_obj["id"], "related-to", ipv4_id,
                    description=f"URL requested by {session.src_ip}",
                ):
                    out.append(rel)

        # ── Dual sighting (Indicator + IPv4 observable) ───────────────
        if ip_ind:
            out.extend(self.build_dual_sighting(
                ip_ind["id"], ipv4_id, session.sensor_hostname, session,
                count=1,
            ))

        return out

    def build_honeytrap_probe(self, session: AttackSession) -> list[dict]:
        """Build the STIX graph for a Honeytrap port-scan / probe session.

        The session is a whole attacker burst (see
        ``HoneytrapParser.correlate``), so its ``dst_ports`` set *is* the
        scan. We surface that on the indicator: which ports were swept, the
        service family they map to (cPanel / Telnet / SMB / …), the scan
        shape (single / multi-port / vertical), and — for the valuable
        minority that carried a payload — a fingerprint (HTTP probe, TLS
        ClientHello, known scanner/botnet/exploit signature). The per-burst
        summary lives on the Sighting `description` (LESSONS §7.1: per-event
        Notes at hive scale produce 50k+/day nobody reads).
        """
        out: list[dict] = []
        if not session.events:
            return out

        event = session.events[0]

        # Foundation: sensor + attacker context (IPv4 + GeoIP + AS)
        out.extend(self.build_sensor_context(session.sensor_hostname))
        out.extend(self.build_attacker_context(event, session=session))

        ipv4_id = attacker_ip_observable_id(session.src_ip)

        # Scan classification + payload fingerprint — computed once, reused
        # for both the indicator labels/description and the Sighting text.
        scan_labels, scan_phrase = port_intel.classify_scan(session.dst_ports)
        printable = session.meta.get("payload_printable") or (
            event.meta.get("payload_printable") if event else None
        )
        hex_str = session.meta.get("payload_hex") or (
            event.meta.get("payload_hex") if event else None
        )
        fp = port_intel.fingerprint_payload(printable, hex_str)

        # IP Indicator + based-on → IPv4 observable
        ip_ind = self.build_ip_indicator(session.src_ip, session=session)
        if ip_ind:
            self._enrich_honeytrap_indicator(ip_ind, session, scan_labels, scan_phrase, fp)
            out.append(ip_ind)
            if rel := self.build_relationship(
                ip_ind["id"], "based-on", ipv4_id,
                description=f"IP indicator for {session.src_ip}",
            ):
                out.append(rel)

            # Dual sighting (Indicator + IPv4 observable).
            out.extend(self.build_dual_sighting(
                ip_ind["id"], ipv4_id, session.sensor_hostname, session,
                count=session.event_count,
                description=render_honeytrap_sighting_description(session, event),
            ))

        # Rare but valuable: a captured follow-up binary. Emit the File
        # observable + URL→File / probe→File edges via the shared chain.
        out.extend(self._link_download_chain(session))

        return out

    @staticmethod
    def _enrich_honeytrap_indicator(
        ip_ind: dict,
        session: AttackSession,
        scan_labels: list[str],
        scan_phrase: str,
        fp: Optional[dict],
    ) -> None:
        """Mutate a generic IP indicator into a port-scan indicator.

        Adds scan-shape + ``target:<family>`` + fingerprint labels, rewrites
        the name to reflect the sweep, and appends a scan-profile paragraph
        (port list + service annotations + payload fingerprint) to the
        description. Keeps the generic indicator's pattern / score / refs.
        """
        labels = list(ip_ind.get("labels") or [])
        for lbl in scan_labels:
            if lbl not in labels:
                labels.append(lbl)
        if fp and fp.get("label") and fp["label"] not in labels:
            labels.append(fp["label"])
        ip_ind["labels"] = labels

        nports = len(session.dst_ports)
        if nports:
            ip_ind["name"] = (
                f"Honeytrap scan - {session.src_ip} "
                f"({nports} port{'s' if nports != 1 else ''})"
            )

        port_summary = port_intel.summarize_ports(session.dst_ports)
        profile_bits = [f"Scan profile: {scan_phrase}."]
        if port_summary:
            profile_bits.append(f"Ports: {port_summary}.")
        if fp and fp.get("summary"):
            profile_bits.append(f"Payload fingerprint: {fp['summary']}.")
        if session.malware_hashes:
            profile_bits.append(
                f"{len(session.malware_hashes)} file(s) captured during the burst."
            )
        tags = session.meta.get("tags") or []
        if tags:
            profile_bits.append("Sensor tags: " + ", ".join(str(t) for t in tags[:8]) + ".")
        profile = " ".join(profile_bits)
        ip_ind["description"] = (
            f"{ip_ind['description']}\n\n{profile}"
            if ip_ind.get("description") else profile
        )

    def build_fallback_event(self, session: AttackSession) -> list[dict]:
        """Build STIX for one unknown-type (fallback) session.

        Always emits a Note describing the unknown event when src_ip is
        missing.  When ``src_ip`` is present, emits IPv4-Addr +
        IP-Indicator + Sighting + sensor context with the per-event
        summary on the Sighting.description (no Note — per
        LESSONS §7.1).
        """
        out: list[dict] = []
        if not session.events:
            return out

        first = session.events[0]
        unknown_type = first.event_type

        # Sensor identity is foundation — emit even when there's no IP
        # so the Note can hang off the sensor.
        out.extend(self.build_sensor_context(session.sensor_hostname))

        ipv4_id: Optional[str] = None

        if first.src_ip:
            # Attacker context (IPv4 + GeoIP + AS + located-at / belongs-to)
            attacker_objs = self.build_attacker_context(first, session=session)
            out.extend(attacker_objs)
            if attacker_objs:
                ipv4_id = attacker_ip_observable_id(first.src_ip)

            # IP Indicator + based-on → IPv4
            ip_ind = self.build_ip_indicator(first.src_ip, session=session)
            if ip_ind:
                out.append(ip_ind)
                if ipv4_id:
                    if rel := self.build_relationship(
                        ip_ind["id"], "based-on", ipv4_id,
                        description=f"IP indicator for {first.src_ip}",
                    ):
                        out.append(rel)

                # Dual sighting on Indicator + IPv4 observable — per-event
                # summary (unknown_type + dst_port) lives on the Sighting
                # `description` field. Per LESSONS §7.1 we do NOT
                # emit a separate Note per event for high-volume / low-
                # signal protocols. If a maintainer wants per-event
                # forensics, the raw doc is preserved on T-Pot's ES.
                out.extend(self.build_dual_sighting(
                    ip_ind["id"], ipv4_id, session.sensor_hostname, session,
                    count=session.event_count,
                    description=render_fallback_sighting_description(first, unknown_type),
                ))
        else:
            # Edge case: unknown-type event has no src_ip.  Without an IP
            # there is no Sighting to attach a description to — emit a
            # single free-floating Note so the event isn't silently lost.
            # This is the ONE remaining Note-emission path in the fallback
            # builder (LESSONS §7.1 carve-out: per-event Notes for
            # the IP-bearing common case are dropped; the rare no-IP case
            # keeps a Note as the only signal we can surface).
            body = render_fallback_no_ip_note_body(first, unknown_type)
            note = self.build_session_note(
                session,
                body_md=body,
                abstract=f"Unrecognized T-Pot event: {unknown_type} (no src_ip)",
                object_refs=[generate_sensor_id(session.sensor_hostname)],
            )
            if note:
                out.append(note)

        return out

    def build_attacker_context(
        self,
        event: ParsedEvent,
        *,
        session: Optional[AttackSession] = None,
    ) -> list[dict]:
        """Build the attacker-IP (IPv4 or IPv6) + Location +
        AutonomousSystem + relationships triple for one event's source.

        Returns a list of STIX dicts (skipping anything already-emitted
        within this bundle).  Used by both the driveby and substantive
        code paths.

        When `session` is provided, observables get the OpenCTI x_opencti_*
        enrichment + pivot menu external_references.
        """
        out: list[dict] = []
        ip_obj = self.build_ip_observable(event.src_ip, session=session)
        if not ip_obj:
            return out
        out.append(ip_obj)

        # GeoIP (logstash-enriched)
        if event.src_country_code:
            country = self.build_country_location(
                event.src_country_code, event.src_country_name, session=session,
            )
            if country:
                out.append(country)
                rel = self.build_relationship(
                    ip_obj["id"], "located-at", country["id"],
                    description=f"{event.src_ip} geolocated to {event.src_country_code}",
                )
                if rel:
                    out.append(rel)
            if event.src_city:
                city = self.build_city_location(
                    event.src_country_code, event.src_city, session=session,
                )
                if city:
                    out.append(city)
                    rel = self.build_relationship(
                        ip_obj["id"], "located-at", city["id"],
                        description=f"{event.src_ip} geolocated to {event.src_city}",
                    )
                    if rel:
                        out.append(rel)

        if event.src_asn:
            asn = self.build_autonomous_system(
                event.src_asn, event.src_as_org, session=session,
            )
            if asn:
                out.append(asn)
                # Use the canonical STIX "belongs-to" for IPv4 → AS
                rel = self.build_relationship(
                    ip_obj["id"], "belongs-to", asn["id"],
                    description=f"{event.src_ip} belongs to AS{event.src_asn}",
                )
                if rel:
                    out.append(rel)

        return out

    def build_sensor_context(self, sensor_hostname: str) -> list[dict]:
        """Sensor Identity (foundation, emitted once per bundle per sensor)."""
        out = []
        sensor = self.build_sensor_identity(sensor_hostname)
        if sensor:
            out.append(sensor)
        return out

    def build_driveby_session(self, session: AttackSession) -> list[dict]:
        """Minimal STIX for a probe-and-leave session per LESSONS §2.

        Emits: IPv4 observable + GeoIP + AS + IP Indicator + Sighting.
        NO Process, Note, AttackPattern, malware artifacts, etc.

        Total typical objects per drive-by session: 4-7
        (vs ~30 for the full treatment).
        """
        if not session.events:
            return []
        first = session.events[0]
        out: list[dict] = []
        out.extend(self.build_sensor_context(session.sensor_hostname))
        out.extend(self.build_attacker_context(first, session=session))

        # IP Indicator + Sighting
        ip_ind = self.build_ip_indicator(session.src_ip, session=session)
        if ip_ind:
            out.append(ip_ind)
            # based-on → IPv4 observable (already emitted above)
            ipv4_id = attacker_ip_observable_id(session.src_ip)
            rel = self.build_relationship(
                ip_ind["id"], "based-on", ipv4_id,
                description=f"IP indicator for {session.src_ip}",
            )
            if rel:
                out.append(rel)
            # Dual sighting (Indicator + IPv4 observable)
            out.extend(self.build_dual_sighting(
                ip_ind["id"], ipv4_id, session.sensor_hostname, session,
                count=session.event_count,
            ))

        return out

    # ──────────────────────────────────────────────────────────────────
    # Web / HTTP honeypot family
    # ──────────────────────────────────────────────────────────────────

    def _build_web_session(self, session: AttackSession) -> list[dict]:
        """Rich builder for HTTP/web honeypots.

        Base attacker graph (IP + geo + AS + Indicator + Sighting) PLUS:
          - URL observables for the paths the attacker requested, each
            `related-to` the attacker IP;
          - an AttackPattern when the parser flagged a technique
            (`attack_type` / `mitre_technique`) or a CVE, with the IP
            Indicator `indicates` it;
          - a Vulnerability for each `matched_cve`, likewise `indicates`-d.

        Object-graph only — no per-event Notes (LESSONS §7.1). Shared by the
        dedicated build_<web>_session dispatch entries.
        """
        out = self.build_driveby_session(session)
        if not session.src_ip or not session.events:
            return out
        ipv4_id = attacker_ip_observable_id(session.src_ip)
        ind_id = attacker_ip_indicator_id(session.src_ip)

        # URL observables (parser-validated full URLs), capped.
        seen: set[str] = set()
        for url in session.urls:
            if len(seen) >= _MAX_WEB_URLS:
                break
            if url in seen:
                continue
            seen.add(url)
            u = self.build_url(url, session=session)
            if not u:
                continue
            out.append(u)
            if rel := self.build_relationship(
                ipv4_id, "related-to", u["id"],
                description=f"{session.src_ip} requested {url}",
            ):
                out.append(rel)

        # Aggregate exploit signals across the session's events.
        cves: set[str] = set()
        attack_types: set[str] = set()
        mitre: set[str] = set()
        for ev in session.events:
            m = ev.meta
            if c := m.get("matched_cve"):
                cves.add(str(c))
            if a := m.get("attack_type"):
                attack_types.add(str(a))
            if t := m.get("mitre_technique"):
                mitre.add(str(t))

        # AttackPattern — only when a real technique/CVE was seen (no AP for
        # a bare probe, to avoid flooding OpenCTI with empty patterns).
        mitre_id = next(iter(sorted(mitre)), None)
        ap_names = set(attack_types)
        if not ap_names and (cves or mitre):
            ap_names = {"Web application exploit attempt"}
        for name in sorted(ap_names):
            ap = self.build_attack_pattern(name, mitre_id, session=session)
            if not ap:
                continue
            out.append(ap)
            if ind_id and (rel := self.build_relationship(
                ind_id, "indicates", ap["id"],
                description=f"{session.event_type} technique from {session.src_ip}",
            )):
                out.append(rel)

        # Vulnerability per matched CVE signature.
        for cve in sorted(cves):
            v = self.build_vulnerability(
                cve,
                description=(
                    f"Exploit attempt observed via {session.event_type} "
                    f"from {session.src_ip}."
                ),
            )
            if not v:
                continue
            out.append(v)
            if ind_id and (rel := self.build_relationship(
                ind_id, "indicates", v["id"],
                description=f"{session.src_ip} attempted to exploit {cve}",
            )):
                out.append(rel)
        return out

    # ──────────────────────────────────────────────────────────────────
    # Unattributed payload salvage
    # ──────────────────────────────────────────────────────────────────

    def build_unattributed_payload_objects(
        self, events: list[ParsedEvent],
    ) -> list[dict]:
        """STIX for events with a usable payload but NO usable source IP.

        The motivating case is Log4Shell against h0neytr4p: that honeypot
        reports the attacker-controlled ``X-Forwarded-For`` header as the
        client address, so a scanner's obfuscated JNDI payload lands in
        ``src_ip`` and nothing in the document preserves the real TCP
        peer. The source is genuinely unrecoverable — but the payload
        contains the attacker's live C2 / DNS-exfil endpoint, which is
        the more durable IoC of the two.

        So we emit the payload's own graph and anchor it at the SENSOR:

          URL (C2 endpoint) ──resolves-to──▶ Domain-Name (C2 zone)
            │                                  │
            └──related-to──▶ Vulnerability (CVE-2021-44228)
            └──related-to──▶ AttackPattern (T1190)
            └──◀ Sighting (where_sighted = sensor Identity)
            └──◀ Note (raw obfuscated payload + why there is no source IP)

        There is deliberately NO IPv4-Addr, no IP Indicator and no
        attacker Identity: minting any of those would assert an
        attribution we do not have. Callers pass only events that already
        failed the source-address gate in ``main.run_cycle``.
        """
        out: list[dict] = []
        if not events:
            return out

        # Group by C2 *host*, not by URL. Measured on live traffic: the
        # scanner encodes which header it probed into the URL's leading
        # label (``XFl0c-…`` for X-Forwarded-For, ``REl0c-…`` for
        # Referer, and so on for ~12 headers), so one probe of one host
        # yields a dozen near-identical URLs. Grouping by URL would mint
        # a dozen Sightings and a dozen Notes for what is one campaign
        # against one C2 zone. The zone is also the durable pivot: the
        # leading labels are per-probe, the zone is the attacker's.
        #
        # Payloads whose host is entirely templated have no zone to group
        # on and fall back to their URL as the key.
        groups: dict[str, dict] = {}
        for i, ev in enumerate(events):
            for payload in (ev.meta.get("jndi_payloads") or []):
                url = payload.get("url")
                if not url:
                    continue
                key = payload.get("host") or url
                g = groups.setdefault(key, {"events": {}, "urls": {}})
                # Keyed by event index, NOT appended: one request carrying
                # 12 header variants of the same zone is ONE observation.
                # A plain append counted that request twelve times and
                # inflated both the Sighting count and the Note's request
                # tally — 7x on the live sample (243 vs the true 33).
                g["events"][i] = ev
                g["urls"].setdefault(url, payload)

        for key in sorted(groups):
            group = sorted(groups[key]["events"].values(), key=lambda e: e.timestamp)
            urls = groups[key]["urls"]
            first, last = group[0], group[-1]
            # The representative payload — its `host`/`decoded`/`raw` are
            # shared by the whole group by construction.
            url, payload = sorted(urls.items())[0]
            extra_urls = sorted(u for u in urls if u != url)
            # EVERY edge in this group anchors on the URL's id — resolves-to,
            # the CVE and attack-pattern edges, the Sighting, and the Note's
            # object_refs. If the representative URL fails validation there is
            # nothing to anchor to, and emitting the group anyway would hang
            # the whole graph off an SCO that is never published.
            #
            # A payload with no netloc at all (`${jndi:ldap:///Exploit}`)
            # names no C2 endpoint, so there is genuinely nothing to record
            # here. Skipping costs the Sighting and the CVE edge for that
            # group; publishing dangling refs costs a MISSING_REFERENCE_ERROR
            # storm, which LESSONS_LEARNED_FROM_V0 §3 calls the costliest
            # failure in this project. Loud, because a rising count here means
            # the payload extractor is producing anchors we cannot publish.
            canon_url = valid_url(url)
            if canon_url is None:
                self.rejected_urls += 1
                logger.warning(
                    "unattributed salvage: group %r skipped — representative "
                    "URL %r failed validation, so the Sighting/CVE/Note graph "
                    "has no anchor", key, url[:120],
                )
                continue
            # Synthetic session purely as a carrier for the shared
            # build_* helpers (timestamps, sensor, deterministic ids).
            # Its src_ip is a LABEL, never an address — nothing on this
            # path calls build_ip_observable, and the label is what the
            # helpers' descriptions will read.
            session = AttackSession.from_event(first)
            session.src_ip = _UNATTRIBUTED_SRC
            session.last_seen = last.timestamp
            # The group key MUST be part of session_id. Sighting and Note
            # ids are both derived from it, and one request can carry
            # payloads for several C2 zones — every such group shares the
            # same `first` event, so without this the ids collide and
            # _dedup silently drops the second zone's Sighting and Note,
            # leaving a naked URL+Domain with no sensor anchor. Same
            # collision hits any payload whose host is fully literal,
            # where grouping degenerates to one group per URL.
            session.session_id = f"{session.session_id}:{key}"

            out.extend(self.build_sensor_context(first.sensor_hostname))

            # The URL's id, NOT the built object, anchors this graph.
            # build_url returns None when _dedup has already emitted that
            # URL in this bundle — which happens whenever a normal web
            # session referenced the same value. Keying off the returned
            # object would then discard the Domain, CVE, Sighting and Note
            # for an endpoint we DID observe, purely because the SCO was
            # already present. The id is deterministic, so referencing it
            # is always valid — but ONLY because the group was skipped above
            # if the URL could not be validated, and only if the id is taken
            # from the canonical (stripped) value the SCO is published under.
            url_id = generate_url_id(canon_url)
            if u := self.build_url(url, session=session):
                out.append(u)
            # The per-header URL variants are real observations, so emit
            # them too — but under this one group's Sighting/Note rather
            # than a graph each.
            for variant in extra_urls[:_MAX_WEB_URLS]:
                if uv := self.build_url(variant, session=session):
                    out.append(uv)
            if len(extra_urls) > _MAX_WEB_URLS:
                logger.info(
                    f"unattributed salvage: {key} — emitted "
                    f"{_MAX_WEB_URLS + 1} of {len(extra_urls) + 1} URL "
                    f"variants (capped)"
                )

            # Every edge below anchors on a DETERMINISTIC id rather than on
            # the builder's return value. `_dedup` returns None for an
            # object already emitted in this bundle — which happens from
            # the second C2 group onward, and from the first if a normal
            # web session emitted the same CVE/technique earlier in the
            # cycle (the scanner sprays the whole hive, so that is the
            # common case, not the corner case). Gating the relationship
            # on the object would drop the edge for evidence we really
            # observed; the id is valid whether or not the SDO was
            # re-emitted.
            if host := payload.get("host"):
                # build_domain returns None for BOTH "already emitted"
                # and "malformed". Only the first is safe to reference —
                # an edge to a malformed domain that was never built (and
                # never will be) is a dangling ref. _emitted_ids tells the
                # two cases apart.
                d = self.build_domain(host, session=session)
                domain_id = generate_domain_id(host)
                if d:
                    out.append(d)
                if (d or domain_id in self._emitted_ids) and (
                    rel := self.build_relationship(
                        url_id, "resolves-to", domain_id,
                        description=f"C2 endpoint {url[:120]} resolves to {host}",
                    )
                ):
                    out.append(rel)

            if cve := first.meta.get("matched_cve"):
                if v := self.build_vulnerability(
                    cve,
                    description=(
                        f"Exploitation attempt observed via "
                        f"{first.event_type} on sensor "
                        f"{first.sensor_hostname!r}. Source address not "
                        f"recoverable — the honeypot reports the "
                        f"attacker-controlled X-Forwarded-For header as "
                        f"the client address."
                    ),
                ):
                    out.append(v)
                if rel := self.build_relationship(
                    url_id, "related-to", generate_vulnerability_id(cve),
                    description=f"C2 endpoint delivered in a {cve} payload",
                ):
                    out.append(rel)

            if attack_type := first.meta.get("attack_type"):
                if ap := self.build_attack_pattern(
                    attack_type, first.meta.get("mitre_technique"),
                    session=session,
                ):
                    out.append(ap)
                if rel := self.build_relationship(
                    url_id, "related-to", generate_attack_pattern_id(attack_type),
                    description=f"C2 endpoint used by {attack_type}",
                ):
                    out.append(rel)

            if sighting := self.build_sighting(
                url_id, first.sensor_hostname, session,
                count=len(group),
                description=(
                    f"{len(group)} exploitation attempt(s) carrying this C2 "
                    f"endpoint, observed by {first.event_type}. No source "
                    f"address: see the attached Note."
                ),
                id_discriminator="unattributed",
            ):
                out.append(sighting)

            note = self.build_session_note(
                session,
                self._unattributed_note_body(url, extra_urls, payload, group),
                abstract=f"Unattributed {first.event_type} payload → {key[:80]}",
                object_refs=[url_id],
            )
            if note:
                out.append(note)

        return out

    @staticmethod
    def _unattributed_note_body(
        url: str, extra_urls: list[str], payload: dict, group: list[ParsedEvent],
    ) -> str:
        """Markdown body for the salvage Note.

        Records the recovered endpoint, the raw obfuscated text it was
        extracted from, and — importantly — an explicit statement that the
        source address is unknown, so nobody reading this in OpenCTI
        mistakes the absence of an IP for an oversight.
        """
        sensors = sorted({e.sensor_hostname for e in group})
        raw = str(payload.get("raw") or "")
        if len(raw) > _UNATTRIBUTED_RAW_CAP:
            raw = raw[:_UNATTRIBUTED_RAW_CAP] + " … [truncated]"
        lines = [
            "## Unattributed exploitation payload",
            "",
            f"- **Recovered C2 endpoint:** `{url}`",
            f"- **C2 host:** `{payload.get('host') or '(templated — not a fixed name)'}`",
            f"- **Observed:** {len(group)} request(s) "
            f"{group[0].timestamp.isoformat()} → {group[-1].timestamp.isoformat()}",
            f"- **Sensors:** {', '.join(sensors)}",
        ]
        if extra_urls:
            lines += [
                "",
                f"### {len(extra_urls)} further URL variant(s) on the same host",
                "",
                "The scanner encodes the probed header into the URL's "
                "leading label, so one probe produces one variant per "
                "header it tried:",
                "",
            ] + [f"- `{u}`" for u in extra_urls[:_MAX_WEB_URLS]]
        lines += [
            "",
            "### Why there is no source IP",
            "",
            "This honeypot reports the attacker-controlled "
            "`X-Forwarded-For` header as the client address, and the "
            "request carried an obfuscated payload in that header. The "
            "real TCP peer is not preserved anywhere in the event, so no "
            "IP observable, Indicator or Sighting has been minted for a "
            "source — asserting one would be a fabricated attribution.",
            "",
            "### Deobfuscated payload",
            "",
            "```",
            str(payload.get("decoded") or "")[:_UNATTRIBUTED_RAW_CAP],
            "```",
            "",
            "### Raw payload as received",
            "",
            "```",
            raw,
            "```",
        ]
        return "\n".join(lines)

    # Dedicated per-type entries (registered in main._PARSER_DISPATCH).
    def build_galah_session(self, session: AttackSession) -> list[dict]:
        return self._build_web_session(session)

    def build_tanner_session(self, session: AttackSession) -> list[dict]:
        return self._build_web_session(session)

    def build_h0neytr4p_session(self, session: AttackSession) -> list[dict]:
        return self._build_web_session(session)

    def build_elasticpot_session(self, session: AttackSession) -> list[dict]:
        return self._build_web_session(session)

    def build_ciscoasa_session(self, session: AttackSession) -> list[dict]:
        return self._build_web_session(session)

    def build_wordpot_session(self, session: AttackSession) -> list[dict]:
        return self._build_web_session(session)

    def build_nginx_session(self, session: AttackSession) -> list[dict]:
        return self._build_web_session(session)

    def build_honeyaml_session(self, session: AttackSession) -> list[dict]:
        return self._build_web_session(session)

    # ──────────────────────────────────────────────────────────────────
    # Malware-drop family (file captures + downloads)
    # ──────────────────────────────────────────────────────────────────

    def _build_malware_session(self, session: AttackSession) -> list[dict]:
        """Base attacker graph + dropped files (File + File-Indicator
        `based-on` it), download URLs/domains, and a command Process —
        mirroring the Cowrie malware path. Each extra is gated on its
        signal, so a bare connection degrades to the base graph."""
        out = self.build_driveby_session(session)
        if not session.src_ip or not session.events:
            return out
        ipv4_id = attacker_ip_observable_id(session.src_ip)

        if session.commands:
            proc = self.build_process(session, session.commands)
            if proc:
                out.append(proc)
                if rel := self.build_relationship(
                    proc["id"], "related-to", ipv4_id,
                    description=f"Commands executed by {session.src_ip}",
                ):
                    out.append(rel)


        for sha256 in session.malware_hashes:
            f = self.build_file(sha256, session=session)
            if not f:
                continue
            out.append(f)
            if rel := self.build_relationship(
                f["id"], "related-to", ipv4_id,
                description=f"File dropped by {session.src_ip}",
            ):
                out.append(rel)
            f_ind = self.build_file_indicator(sha256, session=session)
            if f_ind:
                out.append(f_ind)
                if rel := self.build_relationship(
                    f_ind["id"], "based-on", f["id"],
                    description=f"Indicator for file {sha256[:16]}…",
                ):
                    out.append(rel)

        for url in session.urls:
            u = self.build_url(url, session=session)
            if u:
                out.append(u)
                if rel := self.build_relationship(
                    u["id"], "related-to", ipv4_id,
                    description=f"Download URL from {session.src_ip}",
                ):
                    out.append(rel)
        for dom in session.domains:
            d = self.build_domain(dom, session=session)
            if d:
                out.append(d)
                if rel := self.build_relationship(
                    d["id"], "related-to", ipv4_id,
                    description=f"Domain referenced by {session.src_ip}",
                ):
                    out.append(rel)
        # Intra-session attack chain: URL→File (downloaded-from) +
        # Process→File where commands are present (e.g. adbhoney).
        out.extend(self._link_download_chain(session))
        return out

    def build_adbhoney_session(self, session: AttackSession) -> list[dict]:
        return self._build_malware_session(session)

    def build_dionaea_session(self, session: AttackSession) -> list[dict]:
        return self._build_malware_session(session)

    # ──────────────────────────────────────────────────────────────────
    # Fingerprint family (passive TLS/SSH client fingerprints)
    # ──────────────────────────────────────────────────────────────────

    def build_fatt_session(self, session: AttackSession) -> list[dict]:
        """Base attacker graph + the attacker's CLIENT fingerprints (HASSH
        SSH-client hash, JA3 TLS-client hash) as Cryptographic-Key SCOs
        `related-to` the IP — so the same tool seen from different IPs
        links onto one SCO in OpenCTI. (ja3s is the server's — skipped.)"""
        out = self.build_driveby_session(session)
        if not session.src_ip:
            return out
        ipv4_id = attacker_ip_observable_id(session.src_ip)
        for fp in (session.hassh, session.ja3):
            if not fp:
                continue
            ck = self.build_cryptographic_key(fp, session=session)
            if ck:
                out.append(ck)
                if rel := self.build_relationship(
                    ck["id"], "related-to", ipv4_id,
                    description=f"Client fingerprint observed from {session.src_ip}",
                ):
                    out.append(rel)
        return out

    # ──────────────────────────────────────────────────────────────────
    # Protocol / ICS / VoIP / shell family
    # ──────────────────────────────────────────────────────────────────

    def _build_protocol_session(self, session: AttackSession, ap_name: str) -> list[dict]:
        """Base attacker graph + a protocol-targeting AttackPattern (deduped;
        IP Indicator `indicates` it) + a command Process when present.

        The AttackPattern is emitted only when the session shows real
        interaction (commands, parser-populated event meta, or >2 events),
        so a bare connect stays at the base graph and we don't mint patterns
        for noise. Credential pairs for these types are handled separately
        as the per-IP credential Note (see run_cycle), not here."""
        out = self.build_driveby_session(session)
        if not session.src_ip or not session.events:
            return out
        ipv4_id = attacker_ip_observable_id(session.src_ip)
        ind_id = attacker_ip_indicator_id(session.src_ip)

        # Raw protocol requests are preserved as a Note, never as a Process.
        # This is what the old `commands` overload was actually for: the
        # evidence is kept, the false claim of execution is not.
        if session.protocol_requests:
            blob = _render_protocol_requests(session.protocol_requests)
            if blob:
                if note := self.build_session_note(
                    session,
                    body_md=(
                        f"Raw protocol request(s) received by "
                        f"{session.event_type} from {session.src_ip}. These "
                        f"were SENT to the sensor; nothing was executed.\n\n"
                        + blob
                    ),
                    abstract=(
                        f"{len(session.protocol_requests)} protocol request(s) "
                        f"to {session.event_type} from {session.src_ip}"
                    ),
                    object_refs=[ipv4_id],
                ):
                    out.append(note)

        interacted = (
            bool(session.commands)
            or bool(session.credentials_tried)
            or any(e.meta for e in session.events)
            or session.event_count > 2
        )
        if interacted:
            ap = self.build_attack_pattern(ap_name, session=session)
            if ap:
                out.append(ap)
                if ind_id and (rel := self.build_relationship(
                    ind_id, "indicates", ap["id"],
                    description=f"{session.event_type} activity from {session.src_ip}",
                )):
                    out.append(rel)
        if session.commands:
            proc = self.build_process(session, session.commands)
            if proc:
                out.append(proc)
                if rel := self.build_relationship(
                    proc["id"], "related-to", ipv4_id,
                    description=f"Commands from {session.src_ip}",
                ):
                    out.append(rel)
        # Payload/dropper URLs in the command transcript: SSH & protocol
        # honeypots log `wget http://c2/x.sh` but never run it, so the
        # payload URL + C2 host are IOCs we would otherwise lose. (Cowrie
        # has its own extraction in build_cowrie_session.)
        _seen_urls = set()
        for _cmd in session.commands:
            for _url in _CMD_URL_RE.findall(_cmd):
                _url = _url.rstrip(".,;)")
                if _url in _seen_urls:
                    continue
                _seen_urls.add(_url)
                _url_obj = self.build_url(_url, session=session)
                if not _url_obj:
                    continue
                out.append(_url_obj)
                if rel := self.build_relationship(
                    _url_obj["id"], "related-to", ipv4_id,
                    description=f"Payload URL fetched via {session.event_type} by {session.src_ip}",
                ):
                    out.append(rel)
                _host = urlparse(_url).hostname
                if not _host:
                    continue
                _host_obj = (
                    self.build_referenced_ipv4(_host, session=session)
                    if _IPV4_RE.match(_host)
                    else self.build_domain(_host, session=session)
                )
                if _host_obj:
                    out.append(_host_obj)
                    if rel := self.build_relationship(
                        _url_obj["id"], "related-to", _host_obj["id"],
                        description="Payload URL hosted on this endpoint",
                    ):
                        out.append(rel)
        return out

    def build_conpot_session(self, session: AttackSession) -> list[dict]:
        return self._build_protocol_session(session, "ICS/SCADA protocol interaction")

    def build_dicompot_session(self, session: AttackSession) -> list[dict]:
        return self._build_protocol_session(session, "DICOM medical-imaging probe")

    def build_ipphoney_session(self, session: AttackSession) -> list[dict]:
        return self._build_protocol_session(session, "IPP printer-service probe")

    def build_redishoneypot_session(self, session: AttackSession) -> list[dict]:
        return self._build_protocol_session(session, "Redis unauthorized-access attempt")

    def build_sentrypeer_session(self, session: AttackSession) -> list[dict]:
        return self._build_protocol_session(session, "SIP/VoIP fraud probe")

    def build_miniprint_session(self, session: AttackSession) -> list[dict]:
        return self._build_protocol_session(session, "Printer PJL/raw-port probe")

    def build_medpot_session(self, session: AttackSession) -> list[dict]:
        return self._build_protocol_session(session, "HL7 medical-messaging probe")

    def build_router_session(self, session: AttackSession) -> list[dict]:
        return self._build_protocol_session(session, "Router/Telnet console interaction")

    def build_heralding_session(self, session: AttackSession) -> list[dict]:
        return self._build_protocol_session(session, "Credential brute-force attempt")

    def build_mailoney_session(self, session: AttackSession) -> list[dict]:
        return self._build_protocol_session(session, "SMTP abuse / relay probe")

    def build_beelzebub_session(self, session: AttackSession) -> list[dict]:
        return self._build_protocol_session(session, "Interactive shell session (LLM honeypot)")
