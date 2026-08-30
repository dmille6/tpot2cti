"""Publish a pass as several bundles through the queue, not one at a time.

WHY
---
Measured over 50 cycles: v2 publishes 567,247 objects in 103,093 seconds =
5.5 obj/s, and publish is ~93% of cycle time. It goes through pycti's
`import_bundle_from_json`, which issues one GraphQL mutation PER OBJECT,
serially, in-process, while four OpenCTI workers sit idle because nothing
uses the queue.

Measured alternatives, timed to work COMPLETION (never to enqueue -- an
enqueue returns in 0.5s and means nothing):

    serial in-process     9.1 obj/s
    1 bundle via queue   11.3 obj/s   1.25x
    6 bundles            20.7 obj/s   2.28x
    12 bundles           29.1 obj/s   3.20x   <- peak
    24 bundles           24.9 obj/s   2.74x   <- overhead exceeds the gain

The 1.25x for a single bundle is the whole point: RabbitMQ distributes
MESSAGES, not objects. One bundle goes to ONE worker while the others idle,
so "switch to the queue" alone buys almost nothing. Chunking IS the
parallelism.

DEFAULT IS 6, NOT THE 12 THAT MEASURED FASTEST. Both reviewers said the
same thing independently: ship below the peak first. Six nearly doubles
throughput, exercises the full parallel path, and leaves less concurrency
to reason about when something goes wrong.

SAFETY
------
Every chunk is sealed into the publish ledger BEFORE anything is enqueued,
so a crash mid-enqueue leaves a detectable `planned` row rather than a
short, self-consistent ledger that reads as a clean cycle. The cursor may
only advance if `state.publish_is_clean(cycle_id)` agrees, and a work that
reports `complete` WITH errors is not clean -- that was measured against
the live API, not assumed.
"""
from __future__ import annotations

import json
import logging
import uuid

logger = logging.getLogger(__name__)

#: Chunks per pass. 6 is deliberate and below the measured 12-chunk peak.
DEFAULT_CHUNKS = 6

#: Never make a chunk smaller than this: past ~24 chunks the per-message
#: overhead measurably exceeded the concurrency gain (24.9 obj/s vs 29.1).
MIN_CHUNK_OBJECTS = 40


def split(objects: list, chunks: int = DEFAULT_CHUNKS) -> list[list]:
    """Split a pass into at most `chunks` bundles of near-equal size.

    Fewer, larger chunks are returned when the pass is small -- splitting 50
    objects six ways would pay six messages of overhead to parallelise
    almost nothing.
    """
    n = len(objects)
    if n == 0:
        return []
    usable = max(1, min(chunks, n // MIN_CHUNK_OBJECTS or 1))
    size = (n + usable - 1) // usable
    return [objects[i:i + size] for i in range(0, n, size)]


def publish_pass_chunked(*, helper, state, cycle_id, pass_name, objects,
                         work_id, wait_for_work, chunks=DEFAULT_CHUNKS,
                         timeout_s=900.0):
    """Enqueue one pass as chunks and wait for every one to finish.

    Returns (ok, detail). `ok` is False if ANY chunk failed to enqueue or
    did not complete cleanly -- the caller must not advance the cursor on a
    False, and `state.publish_is_clean()` will independently agree.

    Waits per pass rather than per chunk: relationships reference entities,
    so the dependency barrier between passes has to hold. Within a pass the
    chunks run concurrently, which is where the parallelism comes from, and
    is safe because the publisher deduplicates by id before partitioning --
    one id appears in at most one chunk.
    """
    parts = split(objects, chunks)
    if not parts:
        return True, "empty pass"

    state.seal_publish_plan(cycle_id, pass_name,
                            [[o.get("id") for o in p] for p in parts])
    logger.info("[%s] pass %r: sealed %d chunk(s) of ~%d objects",
                cycle_id, pass_name, len(parts), len(parts[0]))

    enqueued = 0
    for idx, part in enumerate(parts):
        bundle = json.dumps({"type": "bundle",
                             "id": f"bundle--{uuid.uuid4()}",
                             "objects": part})
        try:
            helper.send_stix2_bundle(bundle, update=True, work_id=work_id)
            state.mark_chunk_enqueued(cycle_id, pass_name, idx, work_id)
            enqueued += 1
        except Exception as exc:  # noqa: BLE001
            state.mark_chunk_terminal(cycle_id, pass_name, idx,
                                      status="send_failed",
                                      error_summary=str(exc)[:300])
            logger.error("[%s] pass %r chunk %d failed to enqueue: %s",
                         cycle_id, pass_name, idx, exc)

    if enqueued == 0:
        return False, f"pass {pass_name}: nothing enqueued"

    # Tell OpenCTI no more bundles are coming BEFORE waiting for the work to
    # finish. A work only reaches `complete` once the connector has signalled
    # to_processed AND its expectations are met, so waiting first is a
    # deadlock: the wait blocks the very call that would let it finish.
    #
    # Found by the pre-flight rather than by review -- the module hung until
    # its 900s timeout, which from the outside looked exactly like a slow
    # OpenCTI. Worth stating plainly: the failure mode of getting this wrong
    # is indistinguishable from the system being slow.
    try:
        helper.api.work.to_processed(work_id, f"{pass_name}: {enqueued} chunk(s) sent")
    except Exception as exc:  # noqa: BLE001
        logger.warning("[%s] pass %r: to_processed failed (%s) — the wait "
                       "below will time out rather than hang for ever",
                       cycle_id, pass_name, exc)

    outcome = wait_for_work(helper.api.work, work_id, timeout_s=timeout_s)
    for idx in range(len(parts)):
        state.mark_chunk_terminal(
            cycle_id, pass_name, idx,
            status=outcome.status if outcome.status != "complete"
            else ("complete" if idx < enqueued else "send_failed"),
            error_count=outcome.error_count,
            error_summary=outcome.summary(),
            import_expected=outcome.import_expected,
            import_processed=outcome.import_processed)

    if not outcome.is_clean:
        logger.error("[%s] pass %r NOT clean: status=%s errors=%d — the "
                     "cursor must not advance on this cycle",
                     cycle_id, pass_name, outcome.status, outcome.error_count)
        return False, f"pass {pass_name}: {outcome.status}, {outcome.error_count} error(s)"

    return True, f"pass {pass_name}: {enqueued} chunk(s) clean"
