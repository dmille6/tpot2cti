"""noisefloor — scanner-vs-focused classification from our own telemetry."""
from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace

import pytest

from tpot2cti.enrich import noisefloor as nf
from tpot2cti.stix_ids import attacker_ip_observable_id


def _row(**kw):
    d = {"src_ip": "45.9.1.2", "surfaces": 1, "sensors": 1, "sessions": 1,
         "auth_success": 0, "commands": 0, "malware_drops": 0, "ports_json": None}
    d.update(kw)
    return d


# ── classification ───────────────────────────────────────────────────────

def test_broad_surface_fanout_is_noise():
    assert nf.classify(_row(surfaces=3)) == [nf.LABEL_NOISE]
    assert nf.classify(_row(surfaces=9)) == [nf.LABEL_NOISE]


def test_substantive_activity_is_labelled():
    assert nf.classify(_row(surfaces=1, commands=5)) == [nf.LABEL_SUBSTANTIVE]
    assert nf.classify(_row(surfaces=1, auth_success=1)) == [nf.LABEL_SUBSTANTIVE]
    assert nf.classify(_row(surfaces=1, malware_drops=2)) == [nf.LABEL_SUBSTANTIVE]


def test_a_scanner_that_actually_got_in_gets_BOTH_labels():
    """The single most important case, and the one a single-label classifier
    silently loses. `noise:fleet-scan` suppresses sharing; the export gate only
    overrides that suppression if the evidence label is *present*. Emitting the
    fan-out label alone would permanently bury a real intrusion."""
    both = nf.classify(_row(surfaces=6, commands=5, auth_success=1))
    assert both == [nf.LABEL_NOISE, nf.LABEL_SUBSTANTIVE]


def test_ambiguous_middle_stays_unlabelled():
    """Silence is a valid answer — a wrong suppression hides real intel."""
    assert nf.classify(_row(surfaces=2)) == []            # 2 surfaces, no substance
    assert nf.classify(_row(surfaces=1)) == []            # 1 surface, no substance


def test_works_on_a_SINGLE_sensor_install():
    """The OSS default is one sensor. Classification must not depend on sensor
    count — the predecessor's sensor-based rule returns '1 sensor' for
    everything there, making the feature useless for its target audience."""
    one_sensor_scan = _row(sensors=1, surfaces=5)
    one_sensor_focused = _row(sensors=1, surfaces=1, commands=9)
    assert nf.classify(one_sensor_scan) == [nf.LABEL_NOISE]
    assert nf.classify(one_sensor_focused) == [nf.LABEL_SUBSTANTIVE]


def test_port_fanout_counts_as_surface_breadth():
    """A Honeytrap-only scanner sweeping many ports is fanning out even though
    it touched a single parser."""
    ports = json.dumps(list(range(1, 41)))
    assert nf.classify(_row(surfaces=1, ports_json=ports)) == [nf.LABEL_NOISE]


def test_distinct_ports_parses_concatenated_json():
    assert nf._distinct_ports(None) == 0
    assert nf._distinct_ports("[22,23],[23,80]") == 3
    assert nf._distinct_ports("garbage") == 0


# ── build ────────────────────────────────────────────────────────────────

def test_build_attaches_label_to_the_existing_observable(builder):
    objs = nf.build_objects(builder, _row(), [nf.LABEL_NOISE])
    assert len(objs) == 1
    o = objs[0]
    assert o["id"] == attacker_ip_observable_id("45.9.1.2"), \
        "must land on the observable CORE already created"
    assert nf.LABEL_NOISE in o["x_opencti_labels"]


def test_build_skips_malformed_ip(builder):
    assert nf.build_objects(builder, _row(src_ip="not-an-ip"), [nf.LABEL_NOISE]) == []


def test_build_attaches_every_label_at_once(builder):
    objs = nf.build_objects(builder, _row(), [nf.LABEL_NOISE, nf.LABEL_SUBSTANTIVE])
    assert set(objs[0]["x_opencti_labels"]) >= {nf.LABEL_NOISE, nf.LABEL_SUBSTANTIVE}


# ── reading CORE telemetry ───────────────────────────────────────────────

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


def test_read_activity_aggregates_surfaces_per_ip(tmp_path):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db = str(tmp_path / "core.db")
    _seed_core_db(db, [
        ("45.9.1.2", "Cowrie",   "s1", 3, 9, 1, 2, 4, 0, now, now, None),
        ("45.9.1.2", "Dionaea",  "s1", 1, 2, 0, 0, 0, 1, now, now, None),
        ("45.9.1.2", "ConPot",   "s1", 1, 1, 0, 0, 0, 0, now, now, None),
        ("45.9.9.9", "Cowrie",   "s1", 1, 1, 0, 0, 0, 0, now, now, None),
    ])
    rows = {r["src_ip"]: r for r in nf.read_activity(db, window_hours=24)}
    assert rows["45.9.1.2"]["surfaces"] == 3          # three distinct parsers
    assert rows["45.9.1.2"]["auth_success"] == 1
    assert rows["45.9.9.9"]["surfaces"] == 1
    assert nf.classify(rows["45.9.1.2"]) == [nf.LABEL_NOISE, nf.LABEL_SUBSTANTIVE]


def test_a_missing_db_RAISES_rather_than_looking_like_a_quiet_fleet(tmp_path):
    """This test previously asserted the opposite — that a missing DB returns
    [] — which made a broken module indistinguishable from a fleet with nothing
    to label: publish nothing, record success, go green. That is this project's
    signature failure mode, and the test was enforcing it."""
    with pytest.raises(nf.ActivityReadError):
        nf.read_activity(str(tmp_path / "nope.db"))


def test_schema_drift_RAISES(tmp_path):
    db = str(tmp_path / "core.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE unrelated (x INT)")
    conn.commit(); conn.close()
    with pytest.raises(nf.ActivityReadError):
        nf.read_activity(db)


def test_a_read_failure_makes_the_cycle_fail_and_health_go_unhealthy(cfg, state_db, tmp_path):
    from tpot2cti.stix.builder import STIXBuilder
    pub = _Pub()
    s = nf.run_cycle(cfg, state_db, str(tmp_path / "gone.db"),
                     lambda: STIXBuilder(cfg), pub)
    assert s["publish_ok"] is False and "read_error" in s
    assert pub.objects is None
    row = state_db.recent_cycles(1)[0]
    assert not row["success"], "a broken read recorded a SUCCESSFUL cycle"


def test_read_activity_never_writes_to_core_db(tmp_path):
    """Opened with mode=ro — CORE's DB must never be mutated by enrichment."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db = str(tmp_path / "core.db")
    _seed_core_db(db, [("45.9.1.2", "Cowrie", "s1", 1, 1, 0, 0, 0, 0, now, now, None)])
    before = open(db, "rb").read()
    nf.read_activity(db, window_hours=24)
    assert open(db, "rb").read() == before, "enrichment mutated CORE's state DB"


# ── cycle ────────────────────────────────────────────────────────────────

class _Pub:
    def __init__(self, ok=True):
        self._ok, self.objects = ok, None

    def publish(self, objects, cycle_id=None):
        self.objects = objects
        return SimpleNamespace(cycle_id=str(cycle_id), pass_counts={},
                               errors=[] if self._ok else ["simulated"])


def test_cycle_labels_and_reports(cfg, state_db, tmp_path):
    from datetime import datetime, timezone
    from tpot2cti.stix.builder import STIXBuilder
    now = datetime.now(timezone.utc).isoformat()
    db = str(tmp_path / "core.db")
    _seed_core_db(db, [
        ("45.9.1.2", "Cowrie",  "s1", 1, 1, 0, 0, 0, 0, now, now, None),
        ("45.9.1.2", "Dionaea", "s1", 1, 1, 0, 0, 0, 0, now, now, None),
        ("45.9.1.2", "ConPot",  "s1", 1, 1, 0, 0, 0, 0, now, now, None),
        ("45.9.3.3", "Cowrie",  "s1", 1, 1, 1, 0, 5, 0, now, now, None),
    ])
    pub = _Pub()
    s = nf.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), pub)
    assert s["fleet_scan"] == 1 and s["substantive"] == 1
    assert s["publish_ok"] is True


def test_cycle_with_nothing_to_label_publishes_nothing(cfg, state_db, tmp_path):
    from tpot2cti.stix.builder import STIXBuilder
    db = str(tmp_path / "core.db")
    _seed_core_db(db, [])
    pub = _Pub()
    s = nf.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), pub)
    assert s["ips"] == 0
    assert pub.objects is None, "must not publish a foundation-only bundle"


def test_module_uses_its_own_state_db_and_patient_connect():
    """Must not write into CORE's state DB (its heartbeat/cycle_log rows are
    what CORE's /health reads), and must not crash-loop a warming OpenCTI."""
    import inspect
    src = inspect.getsource(nf.main)
    assert "noisefloor.db" in src and nf.STATE_DB_ENV == "ENRICH_NOISEFLOOR_STATE_DB"
    assert "_connect_opencti" in src
    assert "HealthServer" in src


def test_already_classified_ips_are_skipped_so_the_tail_is_reached(cfg, state_db, tmp_path):
    """With a per-cycle cap, re-labelling the busiest IPs forever would starve
    the long tail (tens of thousands of addresses). A recorded classification
    is skipped on later cycles."""
    from datetime import datetime, timezone
    from tpot2cti.stix.builder import STIXBuilder
    now = datetime.now(timezone.utc).isoformat()
    db = str(tmp_path / "core.db")
    _seed_core_db(db, [
        ("45.9.1.2", "Cowrie",  "s1", 1, 1, 0, 0, 0, 0, now, now, None),
        ("45.9.1.2", "Dionaea", "s1", 1, 1, 0, 0, 0, 0, now, now, None),
        ("45.9.1.2", "ConPot",  "s1", 1, 1, 0, 0, 0, 0, now, now, None),
    ])
    first = nf.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), _Pub())
    assert first["fleet_scan"] == 1 and first["already"] == 0

    second = nf.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), _Pub())
    assert second["fleet_scan"] == 0 and second["already"] == 1


def test_a_scanner_that_later_gets_in_still_earns_the_evidence_label(cfg, state_db, tmp_path):
    """The skip-cache must key on (ip, label). Keyed on ip alone, an address
    already marked as a scanner could never gain the evidence label that lifts
    export suppression — the cache would make the miss permanent."""
    from datetime import datetime, timezone
    from tpot2cti.stix.builder import STIXBuilder
    now = datetime.now(timezone.utc).isoformat()
    db = str(tmp_path / "core.db")
    rows = [("45.9.1.2", p, "s1", 1, 1, 0, 0, 0, 0, now, now, None)
            for p in ("Cowrie", "Dionaea", "ConPot")]
    _seed_core_db(db, rows)
    first = nf.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), _Pub())
    assert first["fleet_scan"] == 1 and first["substantive"] == 0

    # same IP comes back and actually authenticates + runs commands
    conn = sqlite3.connect(db)
    conn.execute("UPDATE attacker_activity SET auth_success_count=1, "
                 "commands_count=7 WHERE parser='Cowrie'")
    conn.commit(); conn.close()

    second = nf.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), _Pub())
    assert second["substantive"] == 1, "evidence label lost to the skip-cache"
    assert second["fleet_scan"] == 0, "fan-out label re-emitted needlessly"


def test_classification_is_recorded_only_after_a_successful_publish(cfg, state_db, tmp_path):
    """A cache that records work which never landed is the failure this project
    keeps re-learning."""
    from datetime import datetime, timezone
    from tpot2cti.stix.builder import STIXBuilder
    now = datetime.now(timezone.utc).isoformat()
    db = str(tmp_path / "core.db")
    _seed_core_db(db, [
        ("45.9.1.2", "Cowrie",  "s1", 1, 1, 0, 0, 0, 0, now, now, None),
        ("45.9.1.2", "Dionaea", "s1", 1, 1, 0, 0, 0, 0, now, now, None),
        ("45.9.1.2", "ConPot",  "s1", 1, 1, 0, 0, 0, 0, now, now, None),
    ])
    nf.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), _Pub(ok=False))
    assert state_db.get(f"nf:45.9.1.2:{nf.LABEL_NOISE}") is None, \
        "recorded despite failed publish"

    retry = nf.run_cycle(cfg, state_db, db, lambda: STIXBuilder(cfg), _Pub(ok=True))
    assert retry["fleet_scan"] == 1, "must retry after a failed publish"
