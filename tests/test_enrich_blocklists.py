"""blocklists — free bulk-list matching (Lane A)."""
from __future__ import annotations

import ipaddress
import json
import sqlite3
from types import SimpleNamespace

import pytest

from tpot2cti.enrich import blocklists as bl
from tpot2cti.enrich import sources as src
from tpot2cti.stix_ids import attacker_ip_observable_id


# ── CIDR matching ────────────────────────────────────────────────────────

def _cs(*cidrs):
    return src.CidrSet([ipaddress.ip_network(c) for c in cidrs])


def test_cidrset_matches_inside_and_rejects_outside():
    s = _cs("45.9.0.0/16", "203.0.113.7/32")
    assert ipaddress.ip_address("45.9.1.2") in s
    assert ipaddress.ip_address("203.0.113.7") in s
    assert ipaddress.ip_address("8.8.8.8") not in s


def test_cidrset_handles_networks_shorter_than_the_bucket():
    """Bucketing by first octet is only correct if a network spanning several
    octets is registered in every one of them — otherwise a /3 silently matches
    just 1/32nd of its range."""
    s = _cs("224.0.0.0/3")           # 224.0.0.0 – 255.255.255.255
    for ip in ("224.0.0.1", "240.1.2.3", "255.255.255.254"):
        assert ipaddress.ip_address(ip) in s, f"{ip} missed by bucketing"
    assert ipaddress.ip_address("223.255.255.255") not in s


def test_cidrset_ignores_ipv6():
    s = _cs("45.9.0.0/16")
    assert ipaddress.ip_address("2001:db8::1") not in s


# ── parsers ──────────────────────────────────────────────────────────────

def test_netset_parser_handles_both_comment_styles_and_trailing_data():
    """FireHOL comments with '#', Spamhaus with ';' AND appends '; SBL…' after
    the CIDR. A parser that only knows one of these silently drops a feed."""
    text = (
        "# firehol comment\n"
        "; spamhaus comment\n"
        "45.9.0.0/16\n"
        "203.0.113.0/24 ; SBL123456\n"
        "\n"
        "not-an-address\n"
    )
    cidrs, _ = src._parse_netset(text)
    assert len(cidrs) == 2
    assert ipaddress.ip_address("203.0.113.9") in cidrs


def test_feodo_parser_matches_ONLY_online_c2s():
    """Feodo retains long-dead infrastructure — 4 of its 5 entries were offline
    when this was written. Publishing a decommissioned host as an active C2,
    attached to a Malware SDO, is the unqualified-claim class of mistake that
    got the predecessor's abuse.ch key banned."""
    text = json.dumps([
        {"ip_address": "45.9.1.2", "status": "online", "malware": "QakBot"},
        {"ip_address": "45.9.9.9", "status": "offline", "malware": "Emotet"},
    ])
    cidrs, extra = src._parse_feodo(text)
    assert ipaddress.ip_address("45.9.1.2") in cidrs
    assert ipaddress.ip_address("45.9.9.9") not in cidrs, "published an OFFLINE C2"
    assert extra["families"] == {"45.9.1.2": "QakBot"}


def test_feodo_parser_raises_on_a_shape_change():
    with pytest.raises(src.SourceParseError):
        src._parse_feodo("<html>rate limited</html>")
    with pytest.raises(src.SourceParseError):
        src._parse_feodo('{"not":"a list"}')


def test_unknown_source_name_is_rejected_loudly():
    """A typo in ENRICH_BLOCKLIST_SOURCES silently disabling a feed is a
    configuration-shaped silent-zero-work bug."""
    with pytest.raises(ValueError, match="firehol"):
        src.selected_sources("firehol,typo-here")
    assert [s.key for s in src.selected_sources("firehol,tor")] == ["firehol", "tor"]


# ── fetch guards ─────────────────────────────────────────────────────────

def test_a_short_parse_is_refused_rather_than_un_labelling_the_world(monkeypatch):
    """These feeds are plain text over HTTP: a captive portal or rate-limit
    page parses to zero networks perfectly happily. Accepting that would make
    a broken fetch look like a clean internet."""
    class _Resp:
        status = 200
        def read(self): return b"<html>429 Too Many Requests</html>"
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(bl.urllib.request, "urlopen", lambda *a, **k: _Resp())
    with pytest.raises(src.SourceParseError, match="below the floor"):
        bl.fetch_source(src.SOURCES_BY_KEY["firehol"])


def test_one_source_failing_does_not_take_down_the_others(monkeypatch, state_db):
    good = "45.9.0.0/16\n" + "\n".join(f"10.{i}.0.0/16" for i in range(1100))
    def fake(source, timeout=None):
        if source.key == "firehol":
            raise src.SourceParseError("simulated")
        return src._parse_netset(good)
    monkeypatch.setattr(bl, "fetch_source", fake)
    out = bl.refresh_lists(list(src.SOURCES[:3]), state_db)
    assert "firehol" not in out
    assert "spamhaus" in out and "tor" in out


# ── staleness: this lane's whole health question ─────────────────────────

def _seed_core_db(path, rows):
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE attacker_activity (
        src_ip TEXT, parser TEXT, sensor TEXT, sessions_count INT,
        events_count INT, auth_success_count INT, credentials_count INT,
        commands_count INT, malware_drop_count INT, first_seen TEXT,
        last_seen TEXT, sample_dst_ports_json TEXT,
        PRIMARY KEY (src_ip, parser, sensor))""")
    conn.executemany(
        "INSERT INTO attacker_activity (src_ip,parser,sensor,sessions_count,"
        "events_count,auth_success_count,credentials_count,commands_count,"
        "malware_drop_count,first_seen,last_seen,sample_dst_ports_json) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    conn.commit(); conn.close()


class _Pub:
    def __init__(self, ok=True):
        self._ok, self.objects = ok, None
    def publish(self, objects, cycle_id=None):
        self.objects = objects
        return SimpleNamespace(cycle_id=str(cycle_id), pass_counts={},
                               errors=[] if self._ok else ["simulated"])


def _core(tmp_path, ips):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db = str(tmp_path / "core.db")
    _seed_core_db(db, [(ip, "Cowrie", "s1", 1, 1, 0, 0, 0, 0, now, now, None)
                       for ip in ips])
    return db


def _lists(state_db, key="firehol", cidrs=("45.9.0.0/16",), age_iso=None):
    from datetime import datetime, timezone
    when = age_iso or datetime.now(timezone.utc).isoformat()
    state_db.set(f"bl_fetched_at:{key}", when)
    return {key: {"cidrs": _cs(*cidrs), "extra": {},
                  "fetched_at": when, "fresh": True}}


def test_a_stale_list_fails_the_cycle_instead_of_matching_anyway(cfg, state_db, tmp_path):
    """Matching against a frozen list is a confident answer built on expired
    evidence, and once it reaches the graph it is indistinguishable from a
    fresh one. Refusing is right — but it is NOT a successful cycle, or a
    runner that stopped refreshing months ago reads perfectly healthy."""
    from datetime import datetime, timedelta, timezone
    from tpot2cti.stix.builder import STIXBuilder
    old = (datetime.now(timezone.utc) - timedelta(hours=bl.MAX_LIST_AGE_HOURS + 5)).isoformat()
    lists = _lists(state_db, age_iso=old)
    db = _core(tmp_path, ["45.9.1.2"])
    pub = _Pub()
    s = bl.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), pub,
                     lists, src.SOURCES_BY_KEY)
    assert s["stale"] is True and s["publish_ok"] is False
    assert pub.objects is None
    assert not state_db.recent_cycles(1)[0]["success"], \
        "a fully stale runner recorded a SUCCESSFUL cycle"


def test_a_read_failure_fails_the_cycle(cfg, state_db, tmp_path):
    from tpot2cti.stix.builder import STIXBuilder
    lists = _lists(state_db)
    s = bl.run_cycle(cfg, state_db, str(tmp_path / "gone.db"),
                     lambda: STIXBuilder(cfg), _Pub(), lists, src.SOURCES_BY_KEY)
    assert s["publish_ok"] is False and "read_error" in s
    assert not state_db.recent_cycles(1)[0]["success"]


# ── build + cycle ────────────────────────────────────────────────────────

def test_labels_land_on_the_observable_core_already_created(builder):
    objs = bl.build_objects(builder, "45.9.1.2", [("firehol", {})], src.SOURCES_BY_KEY)
    assert objs[0]["id"] == attacker_ip_observable_id("45.9.1.2")
    assert "blocklist:firehol-level1" in objs[0]["x_opencti_labels"]


def test_a_feodo_online_c2_promotes_to_a_malware_sdo_WITH_an_edge(builder):
    """Never emit a floating SDO: the predecessor created ~1,600 edgeless
    Spamhaus Indicators, which are unqueryable clutter — worse than a label."""
    objs = bl.build_objects(builder, "45.9.1.2",
                            [("feodo", {"families": {"45.9.1.2": "QakBot"}})],
                            src.SOURCES_BY_KEY)
    kinds = [o["type"] for o in objs]
    assert "malware" in kinds and "relationship" in kinds
    rel = next(o for o in objs if o["type"] == "relationship")
    mal = next(o for o in objs if o["type"] == "malware")
    assert rel["source_ref"] == attacker_ip_observable_id("45.9.1.2")
    assert rel["target_ref"] == mal["id"]


def test_a_feodo_hit_without_a_named_family_labels_but_does_not_promote(builder):
    objs = bl.build_objects(builder, "45.9.1.2", [("feodo", {"families": {}})],
                            src.SOURCES_BY_KEY)
    assert [o["type"] for o in objs] == ["ipv4-addr"]


def test_cycle_matches_labels_and_skips_repeats(cfg, state_db, tmp_path):
    from tpot2cti.stix.builder import STIXBuilder
    lists = _lists(state_db)
    db = _core(tmp_path, ["45.9.1.2", "8.8.8.8"])
    first = bl.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), _Pub(),
                         lists, src.SOURCES_BY_KEY)
    assert first["matched"] == 1 and first["per_source"] == {"firehol": 1}

    second = bl.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), _Pub(),
                          lists, src.SOURCES_BY_KEY)
    assert second["matched"] == 0 and second["already"] == 1


def test_marks_are_recorded_only_after_a_confirmed_publish(cfg, state_db, tmp_path):
    from tpot2cti.stix.builder import STIXBuilder
    lists = _lists(state_db)
    db = _core(tmp_path, ["45.9.1.2"])
    bl.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), _Pub(ok=False),
                 lists, src.SOURCES_BY_KEY)
    assert state_db.get("bl:45.9.1.2:firehol") is None
    retry = bl.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), _Pub(ok=True),
                         lists, src.SOURCES_BY_KEY)
    assert retry["matched"] == 1, "must retry after a failed publish"


def test_an_ip_can_gain_a_second_list_later(cfg, state_db, tmp_path):
    """Per-(ip, source) marks, like noisefloor's per-(ip, label) cache: an
    address already marked for one list must still be able to earn another."""
    from tpot2cti.stix.builder import STIXBuilder
    db = _core(tmp_path, ["45.9.1.2"])
    one = _lists(state_db, "firehol")
    assert bl.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), _Pub(),
                        one, src.SOURCES_BY_KEY)["matched"] == 1
    both = dict(one, **_lists(state_db, "tor"))
    s = bl.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), _Pub(),
                     both, src.SOURCES_BY_KEY)
    assert s["per_source"] == {"tor": 1}, "second list lost to the skip-cache"


def test_a_list_with_no_recorded_fetch_time_is_treated_as_stale(cfg, state_db, tmp_path):
    """Unknown age must fail closed. Reading a missing timestamp as "zero hours
    old" is the safe-looking default that silently converts an unknown into a
    confident answer."""
    from tpot2cti.stix.builder import STIXBuilder
    lists = {"firehol": {"cidrs": _cs("45.9.0.0/16"), "extra": {},
                         "fetched_at": None, "fresh": True}}
    state_db.set("bl_fetched_at:firehol", "not-a-timestamp")
    db = _core(tmp_path, ["45.9.1.2"])
    pub = _Pub()
    s = bl.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), pub,
                     lists, src.SOURCES_BY_KEY)
    assert s["stale"] is True and s["publish_ok"] is False
    assert pub.objects is None
