"""Publisher three-pass send shape.

The Publisher partitions objects into foundation / entities /
relationships and ships each pass as its own bundle envelope (V1_SPEC
§3 + audit #12 deterministic bundle_id).  Tests use a fake client so
no network I/O.
"""

from __future__ import annotations

import pytest

from tpot2cti.publisher import Publisher


class _FakeClient:
    """Captures every bundle handed to send_bundle()."""

    def __init__(self):
        self.bundles: list[dict] = []

    def send_bundle(self, envelope: dict) -> dict:
        self.bundles.append(envelope)
        return {"sent": len(envelope["objects"]), "duration_s": 0.0}


@pytest.fixture(autouse=True)
def _no_sleep():
    Publisher._sleep_seconds = 0
    yield


def _identity(cfg):
    from tpot2cti.stix.builder import STIXBuilder
    return STIXBuilder(cfg).build_operator_identity()


def _ipv4(cfg):
    from tpot2cti.stix.builder import STIXBuilder
    return STIXBuilder(cfg).build_ipv4("203.0.113.42")


def _rel(cfg):
    from tpot2cti.stix.builder import STIXBuilder
    b = STIXBuilder(cfg)
    ind = b.build_ip_indicator("203.0.113.42")
    ipv4 = b.build_ipv4("203.0.113.42")
    return b.build_relationship(ind["id"], "based-on", ipv4["id"])


class _ExistsClient(_FakeClient):
    """Fake client that answers the referential-integrity pre-flight."""

    def __init__(self, existing):
        super().__init__()
        self._existing = set(existing)
        self.checked: list = []

    def exists_bulk(self, ids):
        self.checked = list(ids)
        return {i for i in ids if i in self._existing}


def test_strip_unresolvable_references(cfg):
    """Cross-cycle refs absent from OpenCTI are dropped; present ones and
    in-bundle ones are kept; Note.object_refs are pruned not dropped."""
    from tpot2cti.stix.builder import STIXBuilder
    b = STIXBuilder(cfg)
    ipv4 = b.build_ipv4("203.0.113.7")
    ind = b.build_ip_indicator("203.0.113.7")
    prior_id = "campaign--11111111-1111-5111-a111-111111111111"   # exists in OpenCTI
    missing_id = "campaign--00000000-0000-5000-a000-0000000000ab"  # absent

    rel_keep = b.build_relationship(ind["id"], "based-on", ipv4["id"])   # both in-bundle
    rel_prior = b.build_relationship(ind["id"], "indicates", prior_id)   # exists → keep
    rel_drop = b.build_relationship(ind["id"], "indicates", missing_id)  # absent → drop
    note_prune = {"type": "note", "id": "note--aaaaaaaa-aaaa-5aaa-aaaa-aaaaaaaaaaaa",
                  "abstract": "a", "content": "x",
                  "object_refs": [ipv4["id"], missing_id]}
    note_drop = {"type": "note", "id": "note--bbbbbbbb-bbbb-5bbb-bbbb-bbbbbbbbbbbb",
                 "abstract": "b", "content": "y", "object_refs": [missing_id]}

    objs = [ipv4, ind, rel_keep, rel_prior, rel_drop, note_prune, note_drop]
    client = _ExistsClient(existing={prior_id})
    pub = Publisher(client, state=None)
    kept, n_dropped = pub._strip_unresolvable_references(objs, "c1")

    kept_ids = {o["id"] for o in kept}
    assert rel_keep["id"] in kept_ids        # in-bundle endpoints → kept
    assert rel_prior["id"] in kept_ids       # exists in OpenCTI → kept
    assert rel_drop["id"] not in kept_ids    # absent → dropped
    assert note_prune["id"] in kept_ids      # note kept, refs pruned
    pruned = next(o for o in kept if o["id"] == note_prune["id"])
    assert pruned["object_refs"] == [ipv4["id"]]
    assert note_drop["id"] not in kept_ids   # object_refs emptied → dropped
    assert n_dropped == 2
    # Only out-of-bundle ids were checked — in-bundle endpoints were not.
    assert set(client.checked) == {prior_id, missing_id}


def test_preflight_noop_without_exists_bulk(cfg):
    """A client lacking exists_bulk (legacy/stub) leaves the bundle untouched."""
    b = __import__("tpot2cti.stix.builder", fromlist=["STIXBuilder"]).STIXBuilder(cfg)
    ind = b.build_ip_indicator("203.0.113.8")
    rel = b.build_relationship(ind["id"], "indicates",
                               "campaign--00000000-0000-5000-a000-0000000000cd")
    objs = [ind, rel]
    kept, n = Publisher(_FakeClient(), state=None)._strip_unresolvable_references(objs, "c2")
    assert n == 0 and len(kept) == 2


def test_publish_partitions_three_passes(cfg):
    """Foundation/entities/relationships go out as three separate bundles."""
    client = _FakeClient()
    pub = Publisher(client, state=None)
    objs = [_identity(cfg), _ipv4(cfg), _rel(cfg)]
    result = pub.publish(objs, cycle_id="test-cycle-001")
    assert len(client.bundles) == 3
    types_per_pass = [{o["type"] for o in b["objects"]} for b in client.bundles]
    assert types_per_pass[0] == {"identity"}
    assert types_per_pass[1] == {"ipv4-addr"}
    assert types_per_pass[2] == {"relationship"}
    assert result.bundle_id.startswith("bundle--")


def test_publish_skips_empty_passes(cfg):
    """A pass with no objects MUST NOT be sent."""
    client = _FakeClient()
    pub = Publisher(client, state=None)
    pub.publish([_ipv4(cfg)], cycle_id="entities-only")
    assert len(client.bundles) == 1
    assert client.bundles[0]["objects"][0]["type"] == "ipv4-addr"


def test_bundle_id_is_deterministic(cfg):
    """Same cycle_id → same bundle_id (audit #12)."""
    a = Publisher(_FakeClient(), state=None).publish([_ipv4(cfg)], cycle_id="x").bundle_id
    b = Publisher(_FakeClient(), state=None).publish([_ipv4(cfg)], cycle_id="x").bundle_id
    assert a == b


def test_publish_continues_after_pass_failure(cfg):
    """If one pass raises, the next pass still ships (V1_SPEC §7)."""
    class FlakyClient(_FakeClient):
        def send_bundle(self, envelope):
            if any(o["type"] == "identity" for o in envelope["objects"]):
                raise RuntimeError("simulated worker error")
            return super().send_bundle(envelope)

    flaky = FlakyClient()
    pub = Publisher(flaky, state=None)
    result = pub.publish([_identity(cfg), _ipv4(cfg)], cycle_id="flaky")
    # Foundation pass failed; entities pass still went through.
    assert any("identity" not in {o["type"] for o in b["objects"]}
               for b in flaky.bundles)
    assert result.errors  # error recorded


def test_publish_dedup_label_union(cfg):
    """Two emissions of the same ipv4 with different labels merge."""
    a = _ipv4(cfg)
    a["x_opencti_labels"] = ["honeypot", "cowrie"]
    b = dict(a, x_opencti_labels=["honeypot", "ssh-telnet"])
    client = _FakeClient()
    pub = Publisher(client, state=None)
    result = pub.publish([a, b], cycle_id="dedup")
    assert result.total_objects_before_dedup == 2
    assert result.total_objects_after_dedup == 1
    # Union should have all three labels
    sent_obj = client.bundles[0]["objects"][0]
    assert set(sent_obj["x_opencti_labels"]) == {"honeypot", "cowrie", "ssh-telnet"}
