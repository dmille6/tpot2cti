"""Research scanners and CDN edges are capped at a low score.

Audit 2026-10-03 (v2, live): 66 Indicators labelled ``scanner:*`` and 36
inside Cloudflare's ranges had score >= 50. The ceiling is applied in the
publisher AFTER the cross-cycle max(score) merge, which is the only place a
score can be lowered at all (builder._ip_score: "a score can only ever
ratchet UP"). See tpot2cti/score_ceiling.py.

Addresses here: 104.16.0.0/13 and 151.101.0.0/16 are the providers' own
published edge ranges (public facts, not fleet data); everything else is
documentation space.
"""
from __future__ import annotations

import pytest

from tpot2cti.publisher import Publisher
from tpot2cti.score_ceiling import (
    DEFAULT_CEILING, ScoreCeiling, ScoreCeilingError, load_edge_networks)

CF = "104.16.1.2"         # Cloudflare edge
FASTLY = "151.101.1.1"    # Fastly edge
PLAIN = "203.0.113.9"


def _ind(ip, score=80, labels=("honeypot",)):
    return {"type": "indicator", "id": f"indicator--{abs(hash(ip)) % 10**8:08d}-0000-5000-8000-000000000000",
            "pattern_type": "stix", "pattern": f"[ipv4-addr:value = '{ip}']",
            "labels": list(labels), "x_opencti_score": score}


def _obs(ip, score=80, labels=("honeypot",)):
    return {"type": "ipv4-addr", "id": f"ipv4-addr--{abs(hash(ip)) % 10**8:08d}-0000-5000-8000-000000000000",
            "value": ip, "x_opencti_labels": list(labels), "x_opencti_score": score}


@pytest.fixture
def ceiling():
    return ScoreCeiling.from_env({})


def test_bundled_edge_list_loads_and_covers_both_providers(ceiling):
    assert ceiling.ceiling == DEFAULT_CEILING == 25
    assert ceiling.edge_provider(CF) == "cloudflare"
    assert ceiling.edge_provider("2606:4700::6810:1") == "cloudflare"
    assert ceiling.edge_provider(FASTLY) == "fastly"
    assert ceiling.edge_provider(PLAIN) is None
    assert ceiling.edge_provider("not-an-ip") is None


@pytest.mark.parametrize("body", [
    "providers: {}\n",
    "providers:\n  cloudflare:\n    cidrs: []\n",
    "providers:\n  cloudflare:\n    cidrs: [104.16.0.1/13]\n",      # host bits set
    "providers:\n  cloudflare:\n    cidrs: [banana]\n",
    "providers:\n  Bad Name:\n    cidrs: [104.16.0.0/13]\n",
])
def test_a_bad_edge_list_stops_startup(tmp_path, body):
    p = tmp_path / "edge.yaml"
    p.write_text(body)
    with pytest.raises(ScoreCeilingError):
        load_edge_networks(p)
    with pytest.raises(ScoreCeilingError):
        ScoreCeiling.from_env({"TPOT2CTI_EDGE_NETWORKS_FILE": str(p)})


def test_a_missing_edge_list_stops_startup(tmp_path):
    with pytest.raises(ScoreCeilingError):
        ScoreCeiling.from_env({"TPOT2CTI_EDGE_NETWORKS_FILE": str(tmp_path / "nope.yaml")})


@pytest.mark.parametrize("raw", ["abc", "-1", "101", "2.5"])
def test_a_bad_ceiling_stops_startup(raw):
    with pytest.raises(ScoreCeilingError):
        ScoreCeiling.from_env({"TPOT2CTI_SCORE_CEILING": raw})


def test_ceiling_value_and_inline_comment(ceiling):
    assert ScoreCeiling.from_env({"TPOT2CTI_SCORE_CEILING": "10  # low"}).ceiling == 10


def test_scanner_label_caps_indicator_and_observable(ceiling):
    for obj in (_ind(PLAIN, labels=["scanner:research", "scanner:driftnet"]),
                _obs(PLAIN, labels=["scanner:research"])):
        assert ceiling.apply(obj) == "scanner"
        assert obj["x_opencti_score"] == 25
    assert ceiling.counts == {"scanner": 2}


def test_edge_address_is_capped_and_labelled(ceiling):
    ind, obs = _ind(CF), _obs(FASTLY, score=50)
    assert ceiling.apply(ind) == "edge:cloudflare"
    assert ind["x_opencti_score"] == 25 and "edge-network:cloudflare" in ind["labels"]
    assert ceiling.apply(obs) == "edge:fastly"
    assert obs["x_opencti_score"] == 25 and "edge-network:fastly" in obs["x_opencti_labels"]


def test_nothing_is_raised_and_others_are_untouched(ceiling):
    low = _ind(PLAIN, score=10, labels=["scanner:censys"])
    plain = _ind(PLAIN, score=95)
    file_ind = {"type": "indicator", "id": "indicator--f", "x_opencti_score": 90,
                "pattern": "[file:hashes.'SHA-256' = 'aa']", "labels": ["scanner:x"]}
    before = [dict(o) for o in (low, plain, file_ind)]
    for o in (low, plain, file_ind):
        assert ceiling.apply(o) is None
    assert [low, plain, file_ind] == before


def test_a_label_containing_scanner_elsewhere_does_not_match(ceiling):
    o = _ind(PLAIN, labels=["mass-scanner", "port-scanner:x"])
    assert ceiling.apply(o) is None and o["x_opencti_score"] == 80


# ---------------------------------------------------------------------------
# In the publisher: after the max(score) merge, recorded capped
# ---------------------------------------------------------------------------

class _Client:
    def __init__(self):
        self.objects = []

    def send_bundle(self, envelope):
        self.objects += envelope["objects"]
        return {"sent": len(envelope["objects"]), "duration_s": 0.0}


@pytest.fixture(autouse=True)
def _no_sleep():
    Publisher._sleep_seconds = 0
    yield


def _sent(client, oid):
    return [o for o in client.objects if o.get("id") == oid][-1]


def test_publisher_caps_after_restoring_a_higher_persisted_score(tmp_path):
    """Cycle 1 publishes the address at 80 with no scanner label. Cycle 2
    sees the scanner label (score 50); the merge restores 80, the ceiling
    then caps at 25 and records 25. Cycle 3 emits it WITHOUT the label: the
    persisted label still caps it."""
    from tpot2cti.state import CycleState
    state = CycleState(db_path=tmp_path / "state.db")
    c = _Client()
    pub = Publisher(c, state=state, redactor=False)
    pub.publish([_ind(PLAIN, 80)], cycle_id="1")
    assert _sent(c, _ind(PLAIN)["id"])["x_opencti_score"] == 80

    pub.publish([_ind(PLAIN, 50, labels=["scanner:research"])], cycle_id="2")
    assert _sent(c, _ind(PLAIN)["id"])["x_opencti_score"] == 25
    assert state.get_max_state_bulk([_ind(PLAIN)["id"]])[_ind(PLAIN)["id"]]["max_score"] == 25

    pub.publish([_ind(PLAIN, 90)], cycle_id="3")
    out = _sent(c, _ind(PLAIN)["id"])
    assert out["x_opencti_score"] == 25 and "scanner:research" in out["labels"]


def test_publisher_caps_a_duplicate_whose_other_variant_has_the_label():
    """The bundle dedup unions labels but keeps the LAST variant's score."""
    c = _Client()
    pub = Publisher(c, state=None, redactor=False)
    pub.publish([_ind(PLAIN, 60, labels=["scanner:research"]), _ind(PLAIN, 85)],
                cycle_id="d")
    out = _sent(c, _ind(PLAIN)["id"])
    assert out["x_opencti_score"] == 25 and "scanner:research" in out["labels"]


def test_publisher_ceiling_is_on_by_default_and_can_be_opted_out():
    assert isinstance(Publisher(_Client(), state=None, redactor=False).score_ceiling, ScoreCeiling)
    c = _Client()
    Publisher(c, state=None, redactor=False, score_ceiling=False).publish([_ind(CF, 80)], cycle_id="x")
    assert _sent(c, _ind(CF)["id"])["x_opencti_score"] == 80
