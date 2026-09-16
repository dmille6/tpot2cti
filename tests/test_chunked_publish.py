"""Chunked publishing must be faster AND must not advance a cursor on failure.

Measured over 50 cycles: v2 publishes 5.5 obj/s and publish is ~93% of cycle
time. Timed to work COMPLETION, chunking measured:

    serial            9.1 obj/s
    1 bundle queued  11.3 obj/s  1.25x   <- one bundle goes to ONE worker
    6 bundles        20.7 obj/s  2.28x
    12 bundles       29.1 obj/s  3.20x   peak
    24 bundles       24.9 obj/s  2.74x   overhead exceeds the gain

The 1.25x is the finding: RabbitMQ distributes MESSAGES, not objects, so
chunking is not a size workaround -- it IS the parallelism.

Default is 6 rather than the fastest 12 because both reviewers independently
said to ship below the peak first.
"""
from __future__ import annotations

import pytest

from tpot2cti.chunked_publish import (DEFAULT_CHUNKS, MIN_CHUNK_OBJECTS,
                                      publish_pass_chunked, split)
from tpot2cti.work_wait import WorkOutcome


# ---------------------------------------------------------------- splitting

def test_default_is_below_the_measured_peak():
    assert DEFAULT_CHUNKS == 6, (
        "12 measured fastest but 6 is the deliberate first increment; "
        "changing this is a decision, not a tweak"
    )


def test_a_large_pass_splits_into_the_requested_chunks():
    parts = split(list(range(1200)), 6)
    assert len(parts) == 6
    assert sum(len(p) for p in parts) == 1200, "no object may be dropped"
    assert len({id(o) for p in parts for o in p}) == 1200, "and none duplicated"


def test_a_small_pass_is_not_over_split():
    """Splitting 50 objects six ways pays six messages to parallelise nothing."""
    parts = split(list(range(50)), 6)
    assert len(parts) == 1, f"expected 1 chunk for 50 objects, got {len(parts)}"


def test_chunk_size_floor_is_respected():
    parts = split(list(range(MIN_CHUNK_OBJECTS * 3)), 12)
    assert len(parts) <= 3, (
        "past ~24 chunks per-message overhead measurably beat the gain "
        "(24.9 obj/s vs 29.1); the floor exists to stay clear of that"
    )


def test_empty_pass_yields_nothing():
    assert split([], 6) == []


# ------------------------------------------------------------- publish path

class _Helper:
    def __init__(self, fail_on=None):
        self.sent = []
        self._fail_on = fail_on
        self.api = type("A", (), {"work": object()})()

    def send_stix2_bundle(self, bundle, update=False, work_id=None):
        if self._fail_on is not None and len(self.sent) == self._fail_on:
            raise RuntimeError("broker refused")
        self.sent.append(bundle)


class _State:
    def __init__(self):
        self.sealed = []
        self.enqueued = []
        self.terminal = []

    def seal_publish_plan(self, cycle_id, pass_name, chunks):
        self.sealed.append((cycle_id, pass_name, len(chunks)))
        return "hash"

    def mark_chunk_enqueued(self, *a):
        self.enqueued.append(a)

    def mark_chunk_terminal(self, *a, **k):
        self.terminal.append((a, k))


def _objs(n):
    return [{"id": f"x--{i}"} for i in range(n)]


def test_the_plan_is_sealed_before_anything_is_enqueued():
    """A crash mid-enqueue must leave a detectable row, not a short ledger."""
    h, s = _Helper(), _State()
    publish_pass_chunked(
        helper=h, state=s, cycle_id=1, pass_name="entities", objects=_objs(600),
        work_id="w", wait_for_work=lambda *a, **k: WorkOutcome("w", "complete", []),
        chunks=6)
    assert s.sealed and s.sealed[0][2] == 6
    assert len(h.sent) == 6


def test_a_clean_run_reports_ok():
    h, s = _Helper(), _State()
    ok, why = publish_pass_chunked(
        helper=h, state=s, cycle_id=1, pass_name="entities", objects=_objs(600),
        work_id="w",
        wait_for_work=lambda *a, **k: WorkOutcome("w", "complete", [], 600, 600),
        chunks=6)
    assert ok is True, why


def test_complete_with_errors_is_not_ok():
    """The measured trap: OpenCTI reports `complete` while rejecting objects."""
    h, s = _Helper(), _State()
    ok, why = publish_pass_chunked(
        helper=h, state=s, cycle_id=1, pass_name="entities", objects=_objs(600),
        work_id="w",
        wait_for_work=lambda *a, **k: WorkOutcome(
            "w", "complete", [{"message": "FUNCTIONAL_ERROR"}], 600, 600),
        chunks=6)
    assert ok is False and "error" in why


def test_a_timeout_is_not_ok():
    """Unknown must never advance a cursor."""
    h, s = _Helper(), _State()
    ok, _ = publish_pass_chunked(
        helper=h, state=s, cycle_id=1, pass_name="entities", objects=_objs(600),
        work_id="w", wait_for_work=lambda *a, **k: WorkOutcome("w", "timeout", []),
        chunks=6)
    assert ok is False


def test_an_enqueue_failure_is_recorded_not_swallowed():
    h, s = _Helper(fail_on=2), _State()
    publish_pass_chunked(
        helper=h, state=s, cycle_id=1, pass_name="entities", objects=_objs(600),
        work_id="w",
        wait_for_work=lambda *a, **k: WorkOutcome("w", "complete", [], 600, 600),
        chunks=6)
    statuses = [k.get("status") for _, k in s.terminal]
    assert "send_failed" in statuses, (
        "a chunk the broker refused must be recorded as send_failed, or the "
        "ledger would show a complete pass that never fully shipped"
    )


def test_total_enqueue_failure_is_not_ok():
    class _Dead(_Helper):
        def send_stix2_bundle(self, *a, **k):
            raise RuntimeError("broker down")

    ok, why = publish_pass_chunked(
        helper=_Dead(), state=_State(), cycle_id=1, pass_name="entities",
        objects=_objs(600), work_id="w",
        wait_for_work=lambda *a, **k: WorkOutcome("w", "complete", []),
        chunks=6)
    assert ok is False and "nothing enqueued" in why
