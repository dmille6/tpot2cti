"""Emit-once suppression: never restate an immutable edge, never lose one.

`object_max_state` merges cross-cycle state but does not suppress
re-emission, so every recurring IP dragged its geo and ASN edges through the
queue again on every cycle. Cycle 649 -- the first clean one after the
2026-09-03 outage -- published 35,836 objects and created 6,201.

The danger of the cure is worse than the disease it treats: an id recorded
but never actually landed is suppressed for ever, existing in our ledger and
nowhere else. These tests exist mainly to pin that down.
"""
from __future__ import annotations

import os
import tempfile

from tpot2cti.state import CycleState


def _state():
    d = tempfile.mkdtemp()
    return CycleState(os.path.join(d, "s.db"))


def test_ledger_roundtrip():
    s = _state()
    assert s.immutable_already_emitted(["a", "b"]) == set()
    s.mark_immutable_emitted(["a", "b"])
    assert s.immutable_already_emitted(["a", "b", "c"]) == {"a", "b"}
    assert s.immutable_emitted_count() == 2


def test_ledger_is_idempotent():
    s = _state()
    s.mark_immutable_emitted(["a"])
    s.mark_immutable_emitted(["a"])
    assert s.immutable_emitted_count() == 1


def test_ledger_survives_a_bundle_larger_than_the_sql_variable_limit():
    """An unchunked IN (...) raises "too many SQL variables" and stalls
    ingestion -- that outage already happened here once (2026-07-19)."""
    s = _state()
    ids = [f"relationship--{i:06d}" for i in range(5000)]
    s.mark_immutable_emitted(ids)
    assert s.immutable_already_emitted(ids) == set(ids)


def test_clear_is_available_as_an_escape_hatch():
    """If OpenCTI loses these edges the ledger must be forgettable."""
    s = _state()
    s.mark_immutable_emitted(["a", "b", "c"])
    assert s.clear_immutable_emitted() == 3
    assert s.immutable_already_emitted(["a"]) == set()


def _rel(rid, rtype):
    return {"id": rid, "type": "relationship", "relationship_type": rtype,
            "source_ref": "ipv4-addr--x", "target_ref": "location--y"}


def test_only_immutable_types_are_suppressed():
    """A sighting's last_seen advances and related-to carries session prose;
    suppressing either would freeze live intelligence."""
    from tpot2cti.publisher import IMMUTABLE_RELATIONSHIP_TYPES
    for t in ("located-at", "belongs-to", "based-on"):
        assert t in IMMUTABLE_RELATIONSHIP_TYPES
    for t in ("stix-sighting-relationship", "related-to", "indicates",
              "uses", "object"):
        assert t not in IMMUTABLE_RELATIONSHIP_TYPES, (
            f"{t} can change after publication and must keep being upserted"
        )


def test_suppression_drops_only_known_ids(monkeypatch):
    from tpot2cti import publisher as pub

    class _P:
        state = _state()
    p = _P()
    p.state.mark_immutable_emitted(["relationship--seen"])
    objs = [_rel("relationship--seen", "located-at"),
            _rel("relationship--new", "located-at"),
            _rel("relationship--sight", "stix-sighting-relationship")]
    kept, dropped = pub.Publisher._suppress_already_emitted(p, objs, "c1")
    ids = {o["id"] for o in kept}
    assert "relationship--seen" not in ids, "already published — suppress"
    assert "relationship--new" in ids, "never published — must still be sent"
    assert "relationship--sight" in ids, "mutable type — must never be suppressed"
    assert dropped == ["relationship--seen"]


def test_a_ledger_read_failure_fails_OPEN():
    """Publishing a duplicate is free. Dropping an edge because a lookup
    broke is not."""
    from tpot2cti import publisher as pub

    class _Boom:
        def immutable_already_emitted(self, ids):
            raise RuntimeError("db locked")

    class _P:
        state = _Boom()
    objs = [_rel("relationship--a", "located-at")]
    kept, dropped = pub.Publisher._suppress_already_emitted(_P(), objs, "c1")
    assert len(kept) == 1, "a broken ledger must not silently drop edges"
    assert dropped == []
