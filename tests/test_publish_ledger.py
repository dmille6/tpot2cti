"""The cursor may only advance when every PLANNED chunk landed clean.

Publishing through a queue moves the unit of risk from the cycle to the
chunk. A cycle-level "errors_count = 0" cannot tell you that only 8 of 12
chunks ever ran, and the two frontier models reviewing this design
independently identified the same hole: a gate that quantifies over "every
row that exists" can never notice a row that does not.

Two facts from the contract test drive the shape of these tests:

  * a work reported ``status: "complete"`` while carrying TWO per-object
    errors, so completeness is not success;
  * ``import_expected_number == import_processed_number == 4`` for a
    4-object bundle containing 2 rejects, so those counters track SUBMITTED
    and are useless as an acceptance gate.

And the asymmetry that decides every tie: re-reading a window is free here
(deterministic UUID5 ids, publisher keeps max(score) with label union),
while skipping one cannot be detected afterwards at all.
"""
from __future__ import annotations

import os
import tempfile

import pytest

from tpot2cti.state import CycleState


@pytest.fixture()
def st(tmp_path):
    return CycleState(db_path=tmp_path / "ledger.db")


def _seal(st, cycle=1, pass_name="entities", chunks=None):
    return st.seal_publish_plan(cycle, pass_name,
                                chunks or [["a", "b"], ["c", "d"], ["e"]])


def test_unsealed_cycle_never_passes():
    """A cycle that recorded no plan has no evidence it published anything."""
    with tempfile.TemporaryDirectory() as d:
        st = CycleState(db_path=os.path.join(d, "x.db"))
        ok, why = st.publish_is_clean(99)
        assert ok is False and "no publish plan" in why


def test_planned_but_unsent_blocks(st):
    _seal(st)
    ok, why = st.publish_is_clean(1)
    assert ok is False and "planned" in why


def test_enqueued_but_unconfirmed_blocks(st):
    """Handed to the broker is not the same as landed."""
    _seal(st)
    for i in range(3):
        st.mark_chunk_enqueued(1, "entities", i, f"w{i}")
    ok, why = st.publish_is_clean(1)
    assert ok is False and "enqueued" in why


def test_complete_with_errors_blocks(st):
    """The contract test's finding, encoded.

    OpenCTI reported status=complete for a work that rejected two objects.
    Gating on completeness alone would advance the cursor over them.
    """
    _seal(st)
    for i in range(3):
        st.mark_chunk_enqueued(1, "entities", i, f"w{i}")
        st.mark_chunk_terminal(1, "entities", i, status="complete")
    st.mark_chunk_terminal(1, "entities", 2, status="complete",
                           error_count=2, error_summary="FUNCTIONAL_ERROR")
    ok, why = st.publish_is_clean(1)
    assert ok is False and "import error" in why


def test_all_clean_passes(st):
    _seal(st)
    for i in range(3):
        st.mark_chunk_enqueued(1, "entities", i, f"w{i}")
        st.mark_chunk_terminal(1, "entities", i, status="complete")
    ok, why = st.publish_is_clean(1)
    assert ok is True, why


# ---------------------------------------------------------------------------
# The crash window — the flaw both reviewers found in the first design
# ---------------------------------------------------------------------------

def test_a_missing_chunk_row_cannot_hide(st):
    """Sealing before enqueue is what makes this detectable.

    Had rows been written AFTER enqueueing, a crash between the two would
    leave a SHORT ledger in which every row present is clean — perfectly
    self-consistent, and wrong. The gate would pass and the cursor would
    advance over a chunk nothing recorded as missing. That is the
    2026-07-19 incident in a new costume.
    """
    _seal(st)
    for i in range(3):
        st.mark_chunk_enqueued(1, "entities", i, f"w{i}")
        st.mark_chunk_terminal(1, "entities", i, status="complete")
    # Simulate the row for chunk 2 never having been written at all.
    with st._conn() as c:
        c.execute("DELETE FROM publish_chunk WHERE cycle_id=1 AND chunk_index=2")
    ok, why = st.publish_is_clean(1)
    assert ok is False, "a vanished chunk row must fail the gate"
    assert "plan sealed 3" in why


def test_object_count_drift_is_caught(st):
    """The plan seals object counts, not just chunk counts."""
    _seal(st)
    for i in range(3):
        st.mark_chunk_enqueued(1, "entities", i, f"w{i}")
        st.mark_chunk_terminal(1, "entities", i, status="complete")
    with st._conn() as c:
        c.execute("UPDATE publish_chunk SET expected_objects=1"
                  " WHERE cycle_id=1 AND chunk_index=0")
    ok, why = st.publish_is_clean(1)
    assert ok is False and "objects sum to" in why


# ---------------------------------------------------------------------------
# Quarantine — the failure mode the gate itself introduces
# ---------------------------------------------------------------------------

def test_quarantine_releases_a_permanently_wedged_cursor(st):
    """A strict gate has its own way of losing data.

    A malformed observable will NEVER be accepted. If error_count > 0
    blocks for ever, the cycle never passes, the cursor never moves, and
    the pipeline silently stops consuming — the 2026-07-19 incident
    inverted. Quarantine moves past a known-bad chunk deliberately, and
    leaves the evidence in the ledger rather than deleting it.
    """
    _seal(st)
    for i in range(3):
        st.mark_chunk_enqueued(1, "entities", i, f"w{i}")
        st.mark_chunk_terminal(1, "entities", i, status="complete")
    st.mark_chunk_terminal(1, "entities", 1, status="complete",
                           error_count=1, error_summary="malformed observable")
    assert st.publish_is_clean(1)[0] is False

    st.quarantine_chunk(1, "entities", 1, "malformed observable, unfixable")
    ok, why = st.publish_is_clean(1)
    assert ok is True, why

    with st._conn() as c:
        row = c.execute("SELECT work_status, error_summary FROM publish_chunk"
                        " WHERE cycle_id=1 AND chunk_index=1").fetchone()
    assert row[0] == "quarantined"
    assert "malformed observable" in row[1], "evidence must survive"
    assert "QUARANTINED" in row[1], "the decision must be recorded, not implied"


def test_timeout_and_unknown_are_not_terminal_success(st):
    """Fail closed: what we could not establish must not advance a cursor."""
    for status in ("timeout", "unknown", "send_failed"):
        s2 = CycleState(db_path=None) if False else st
        _seal(s2, cycle=7, chunks=[["a"]])
        s2.mark_chunk_enqueued(7, "entities", 0, "w")
        s2.mark_chunk_terminal(7, "entities", 0, status=status)
        ok, why = s2.publish_is_clean(7)
        assert ok is False, f"{status} must block the cursor"
        assert status in why


def test_every_pass_must_be_sealed_and_clean(st):
    """One clean pass does not license the cycle."""
    st.seal_publish_plan(3, "entities", [["a"]])
    st.seal_publish_plan(3, "relationships", [["r1"], ["r2"]])
    st.mark_chunk_enqueued(3, "entities", 0, "w")
    st.mark_chunk_terminal(3, "entities", 0, status="complete")
    ok, why = st.publish_is_clean(3)
    assert ok is False and "relationships" in why


def test_quarantining_a_clean_chunk_is_refused(st):
    """Quarantine must be justified by the errors it exists to excuse.

    Found by both reviewers reading the shipped gate: as first written,
    `status == "quarantined"` skipped every other check, so a chunk
    quarantined by mistake — or by a bug in whatever sets that status —
    sailed through with no verification at all. That is the original
    incident relabelled: data waved past with nothing recording why.
    """
    _seal(st, chunks=[["a"], ["b"]])
    for i in range(2):
        st.mark_chunk_enqueued(1, "entities", i, f"w{i}")
        st.mark_chunk_terminal(1, "entities", i, status="complete")
    # This chunk had NO errors. Quarantining it excuses nothing.
    st.quarantine_chunk(1, "entities", 1, "operator error")
    ok, why = st.publish_is_clean(1)
    assert ok is False, "a quarantine with nothing to excuse must not pass"
    assert "nothing to excuse" in why


def test_quarantine_still_works_when_there_are_real_errors(st):
    """The escape hatch must survive the hardening."""
    _seal(st, chunks=[["a"], ["b"]])
    for i in range(2):
        st.mark_chunk_enqueued(1, "entities", i, f"w{i}")
        st.mark_chunk_terminal(1, "entities", i, status="complete")
    st.mark_chunk_terminal(1, "entities", 1, status="complete",
                           error_count=3, error_summary="FUNCTIONAL_ERROR x3")
    st.quarantine_chunk(1, "entities", 1, "malformed observables, unfixable")
    ok, why = st.publish_is_clean(1)
    assert ok is True, why
