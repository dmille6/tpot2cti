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

import hashlib
import json
import os
import re
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



#: Consecutive cycles that must fail with the IDENTICAL error signature before
#: a chunk is quarantined. Three is ~1.5h at current cycle times: long enough
#: that a transient platform problem has had several chances to clear, short
#: enough that a genuine deadlock does not run for five hours as it did on
#: 2026-09-02.
POISON_QUARANTINE_AFTER = 3


def _error_signature(errors):
    """A stable fingerprint for a set of import errors, plus a human sample.

    TIMESTAMPS ARE EXCLUDED. Each error carries the moment it occurred, and
    including that would make the same rejection look like a brand-new failure
    every cycle -- the streak would never reach two and quarantine could never
    fire. The whole mechanism turns on recognising the same failure again.

    Keyed on the offending object's STIX id plus the error text, so a
    DIFFERENT bad object produces a different signature and correctly resets
    the streak rather than inheriting one.
    """
    parts = []
    for e in errors or []:
        msg = str(e.get("message") or "")
        src = str(e.get("source") or "")
        m = re.search(r'"id":\s*"([a-z0-9-]+--[0-9a-fA-F-]+)"', src)
        parts.append(f"{m.group(1) if m else ''}|{msg}")
    parts.sort()
    sig = hashlib.sha256("\n".join(parts).encode("utf-8", "replace")).hexdigest()[:32]
    return sig, "; ".join(parts[:3])[:800]


#: How long a pass may make NO measurable progress before we call it stuck.
#:
#: This was 420s, which was never plausible on this platform. The cycle
#: ledger records healthy passes from the serial era taking 3,627s and
#: 3,550s with zero errors, and a work sitting in a deep queue can wait
#: minutes before its FIRST message is consumed -- during which there is no
#: progress to observe and nothing is wrong. 420s only avoided firing
#: because a short queue meant works were served immediately.
#:
#: 1800s is deliberately generous: this measures the GAP BETWEEN progress
#: increments, not total pass duration, so on a healthy platform it is never
#: approached. Its job is to catch a genuine wedge, not to bound runtime --
#: that is what the ceiling is for.
DEFAULT_STALL_S = float(os.environ.get("TPOT2CTI_PUBLISH_STALL_S") or 1800.0)

#: Hard backstop. Bounds a pass that trickles for ever without ever stalling.
DEFAULT_CEILING_S = float(os.environ.get("TPOT2CTI_PUBLISH_CEILING_S") or 7200.0)


def publish_pass_chunked(*, helper, state, cycle_id, pass_name, objects,
                         work_id, wait_for_work, chunks=DEFAULT_CHUNKS,
                         timeout_s=None, stall_s=None,
                         quarantine_after=POISON_QUARANTINE_AFTER):
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

    # stall_s is the limit that matters; timeout_s is only a backstop.
    # See work_wait.wait_for_work -- a 900s wall-clock deadline killed a
    # perfectly healthy relationships pass at 6,896/11,760 with 0 errors.
    outcome = wait_for_work(
        helper.api.work, work_id,
        timeout_s=DEFAULT_CEILING_S if timeout_s is None else timeout_s,
        stall_s=DEFAULT_STALL_S if stall_s is None else stall_s)
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
        sig, sample = _error_signature(outcome.errors)
        streak = state.note_publish_failure(pass_name, sig, sample)

        # Quarantine ONLY a proven-permanent rejection. `complete with errors`
        # means OpenCTI finished and refused specific objects -- retrying that
        # produces the identical refusal for ever. A timeout or a stall is the
        # opposite: the work never finished, so the data may well land next
        # time, and abandoning it would be real loss dressed up as recovery.
        permanent = (outcome.status == "complete" and outcome.error_count > 0)

        if permanent and streak >= quarantine_after:
            for idx in range(len(parts)):
                state.quarantine_chunk(
                    cycle_id, pass_name, idx,
                    reason=(f"identical import error on {streak} consecutive "
                            f"cycles (sig {sig}); objects abandoned: {sample}"))
            logger.error(
                "[%s] pass %r QUARANTINED after %d consecutive identical "
                "failures (sig %s). The cursor will advance and these objects "
                "are ABANDONED, not retried: %s",
                cycle_id, pass_name, streak, sig, sample)
            return True, (f"pass {pass_name}: QUARANTINED after {streak} identical "
                          f"failures — objects abandoned")

        logger.error("[%s] pass %r NOT clean: status=%s errors=%d (identical "
                     "failure %d/%d — quarantine at %d) — the cursor must not "
                     "advance on this cycle",
                     cycle_id, pass_name, outcome.status, outcome.error_count,
                     streak, quarantine_after, quarantine_after)
        return False, f"pass {pass_name}: {outcome.status}, {outcome.error_count} error(s)"

    # A clean pass clears the streak: whatever was wrong is gone, and an
    # unrelated failure later must start counting from one.
    state.clear_publish_failure(pass_name)
    return True, f"pass {pass_name}: {enqueued} chunk(s) clean"
