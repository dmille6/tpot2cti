"""tpot2cti — STIX bundle publisher.

Per-cycle orchestrator that ships one logical STIX bundle to OpenCTI in
the three ordered passes mandated by V1_SPEC §3 (lines 278-294):

1. **Foundation** — Identity, Marking-Definition, AttackPattern,
   Location, Autonomous-System. The objects everything else references.
2. **Sleep 30s** — let OpenCTI's eventually-consistent ES index the
   foundation objects so the entity pass doesn't trip
   ``MISSING_REFERENCE_ERROR``.
3. **Entities** — IPv4-Addr, IPv6-Addr, File, URL, Domain-Name, Process,
   Cryptographic-Key, Indicator, Note, Vulnerability.
4. **Sleep 30s** — let entities index.
5. **Relationships** — Relationship, Sighting.

Per ``docs/LESSONS_LEARNED_FROM_V0.md`` §7.2 we use **simple
``time.sleep(30)`` between passes — NOT sentinel polling.** The V0
sentinel-poll plateau-detection bug ate ~36% of relationships during
container restarts; V1_SPEC explicitly mandates the simpler approach.
If we hit ``MISSING_REFERENCE_ERROR``, we log + continue; the next
cycle re-emits with the same deterministic IDs and OpenCTI upserts
the duplicate.

Per ``docs/LESSONS_LEARNED_FROM_V0.md`` §6 we apply **label-union
dedup** before partitioning the bundle: when the same STIX object id
appears twice within a single cycle (e.g. the same attacker IPv4-Addr
emerged from two different sessions), we collapse them into one
object and union list-valued semantic-set fields (``labels``,
``x_opencti_labels``, ``external_references``) and take the max of
``confidence``. The PoC sees consistent 20-25% reduction with this.

Per ``docs/LESSONS_LEARNED_FROM_V0.md`` §8.4 we run
:func:`tpot2cti.stix.types.validate_types` over the bundle before
sending. Unknown types are logged but NOT dropped (the type might be
real and just missing from our allowlist; let OpenCTI decide).

This module catches and logs all exceptions from
:meth:`OpenCTIClient.send_bundle`: a failed pass appends to
``PublishResult.errors`` and the next pass still runs. Partial publish
is better than no publish — next cycle re-emits.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from tpot2cti.opencti_client import OpenCTIClient
from tpot2cti.state import CycleState
from tpot2cti.stix.types import (
    KNOWN_STIX_TYPES,
    log_unknown_types,
    validate_types,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Three-pass type partitioning
# ---------------------------------------------------------------------------

#: Objects that everything else references (V1_SPEC §3 line 284).
FOUNDATION_TYPES: frozenset[str] = frozenset({
    "identity",
    "marking-definition",
    "attack-pattern",
    "location",
    "autonomous-system",
    # Malware SDOs are referenced by relationships (file --related-to--> malware,
    # indicator --indicates--> malware), so they must land before the
    # relationships pass — same rationale as attack-pattern.
    "malware",
})

#: Per-event entities the relationships then connect (V1_SPEC §3 line 287).
ENTITY_TYPES: frozenset[str] = frozenset({
    "ipv4-addr",
    "ipv6-addr",
    "file",
    "url",
    "domain-name",
    "process",
    "cryptographic-key",
    "indicator",
    "note",
    "vulnerability",
    "campaign",
})

#: Relationships and sightings — must go last (V1_SPEC §3 line 290).
RELATIONSHIP_TYPES: frozenset[str] = frozenset({
    "relationship",
    "sighting",
})


# Import-time sanity check: every KNOWN_STIX_TYPE (except the bundle
# envelope itself) must be assigned to exactly one pass. If someone adds
# a new type to stix/types.py without updating these frozensets, we want
# an obvious crash here rather than a silent drop during a 3am cycle.
_assigned = FOUNDATION_TYPES | ENTITY_TYPES | RELATIONSHIP_TYPES | {"bundle"}
if _assigned != KNOWN_STIX_TYPES:
    missing = KNOWN_STIX_TYPES - _assigned
    extra = _assigned - KNOWN_STIX_TYPES
    raise AssertionError(
        "tpot2cti.publisher pass partitioning is out of sync with "
        "tpot2cti.stix.types.KNOWN_STIX_TYPES. "
        f"Missing from any pass: {sorted(missing)}. "
        f"In a pass but not allowlisted: {sorted(extra)}. "
        "Fix FOUNDATION_TYPES / ENTITY_TYPES / RELATIONSHIP_TYPES or "
        "KNOWN_STIX_TYPES so they agree."
    )


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PublishResult:
    """Outcome of one ``Publisher.publish()`` call.

    Recorded into :class:`tpot2cti.state.CycleState` by the caller (via
    a generic key/value row keyed by ``cycle_id``) and surfaced in the
    cycle summary log line + the ``data/cycles.jsonl`` audit doc.
    """

    cycle_id: str
    pass_counts: dict[str, int]
    total_objects_before_dedup: int
    total_objects_after_dedup: int
    dedup_reduction_pct: float
    unknown_types: dict[str, int]
    duration_s: float
    errors: list[str]
    bundle_id: str


# ---------------------------------------------------------------------------
# Publisher
# ---------------------------------------------------------------------------

class Publisher:
    """Three-pass STIX bundle publisher.

    Args:
        client: The :class:`OpenCTIClient` used to ship bundles.
        state: Optional :class:`CycleState` for recording per-cycle
            publish stats. When ``None`` (tests, dry-runs), the result
            dict is still returned but nothing is persisted.

    Attributes:
        _sleep_seconds: Seconds slept between non-empty passes. Default
            60 per the post-cycle-5 tuning + PoC HP_CONNECTOR_HANDOFF §4
            ("the single most impactful tuning parameter"). V1_SPEC §3
            originally said 30s but live data showed pycti's per-object
            Create call rate makes 30s too aggressive for substantive
            bundles — the second pass can land before OpenCTI's ES
            finishes indexing the first. Operator-configurable via the
            ``TPOT2CTI_INDEXING_DELAY_SECONDS`` env var (see config.py
            and .env.example). Tests override to 0 to skip sleeps without
            mocking ``time.sleep``.
    """

    #: Default sleep between non-empty passes when no env override is set.
    #: Overridden per-instance from cfg.cycle.indexing_delay_seconds.
    #: Tests set this class attribute to 0 to skip indexing waits.
    _sleep_seconds: int = 60

    #: Semantic-set fields whose duplicates should be unioned together
    #: when collapsing duplicate STIX IDs. ``labels`` and the
    #: OpenCTI-specific x_opencti_labels mirror it per LESSONS §6.
    _MERGE_LIST_KEYS: tuple[str, ...] = (
        "labels",
        "x_opencti_labels",
    )

    def __init__(
        self,
        client: OpenCTIClient,
        state: Optional[CycleState] = None,
        *,
        indexing_delay_seconds: Optional[int] = None,
    ) -> None:
        self.client = client
        self.state = state
        # Per-instance override of the class-level default; lets main()
        # thread cfg.cycle.indexing_delay_seconds through without touching
        # the class attr (which tests reset to 0).
        if indexing_delay_seconds is not None:
            self._sleep_seconds = int(indexing_delay_seconds)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def publish(
        self,
        objects: list[dict],
        cycle_id: Optional[str] = None,
    ) -> PublishResult:
        """Publish one cycle's worth of STIX objects to OpenCTI.

        See module docstring for the three-pass flow.
        """
        started = time.monotonic()
        if cycle_id is None:
            cycle_id = datetime.now(timezone.utc).strftime("cycle-%Y%m%dT%H%M%SZ")

        # Bundle id: derived from cycle_id so two publishes of the same
        # cycle produce identical bundle envelopes.  Per 2026-05-22 audit
        # #12: bundle id was previously ``uuid.uuid4()``, the only non-
        # deterministic id in the codebase.  OpenCTI dedups by member id
        # in practice so this is mostly cosmetic, but deterministic ids
        # make replay-and-diff debugging tractable and align with the
        # ``stix_ids.py`` UUID5 discipline everywhere else.  We import
        # locally to avoid a top-of-module circular (stix_ids → config
        # → publisher in some test paths).
        from tpot2cti.stix_ids import sdo_id
        bundle_id = sdo_id("bundle", "bundle", "cycle", str(cycle_id))
        errors: list[str] = []

        # --- Step 0: cross-cycle state merge ----------------------------
        # Per the V0 finding on pycti UPSERT overwriting scalar fields + the 2026-05-21 live-find: pycti's UPSERT
        # overwrites scalar fields on Indicators/SCOs across cycles. To
        # preserve the highest-signal observation of each id, we merge
        # this cycle's emission against `object_max_state` in our DB:
        # union the labels, take max(x_opencti_score), and (when the
        # persisted score wins) preserve the prior name/description too.
        # See state.py:get_max_state_bulk / upsert_max_state_bulk.
        merged_state_updates: list[tuple[str, Optional[int], list[str],
                                          Optional[str], Optional[str]]] = []
        if self.state is not None and objects:
            stix_ids = [o.get("id") for o in objects if o.get("id")]
            persisted = self.state.get_max_state_bulk(stix_ids)
            n_promoted = 0
            for obj in objects:
                oid = obj.get("id")
                if not oid:
                    continue
                cur_score = obj.get("x_opencti_score")
                cur_labels = list(obj.get("labels") or []) + \
                             list(obj.get("x_opencti_labels") or [])
                p = persisted.get(oid)
                if p is not None:
                    # Union labels (always)
                    merged_labels = sorted(set(cur_labels) | set(p["labels"] or []))
                    p_score = p.get("max_score")
                    if isinstance(p_score, int) and (
                        cur_score is None or p_score > cur_score
                    ):
                        # Persisted is the higher-signal version — restore it.
                        obj["x_opencti_score"] = p_score
                        if p.get("name"):
                            obj["name"] = p["name"]
                        if p.get("description"):
                            obj["description"] = p["description"]
                        n_promoted += 1
                    # Write labels back to whichever slot the obj uses
                    if "labels" in obj:
                        obj["labels"] = merged_labels
                    if "x_opencti_labels" in obj:
                        obj["x_opencti_labels"] = merged_labels
                # Stage the new persisted state with the merged values.
                # The score we record is the max(current, persisted).
                final_score = obj.get("x_opencti_score")
                merged_state_updates.append((
                    oid,
                    final_score if isinstance(final_score, int) else None,
                    list(obj.get("labels") or obj.get("x_opencti_labels") or []),
                    obj.get("name"),
                    obj.get("description"),
                ))
            if n_promoted:
                logger.info(
                    f"[{cycle_id}] Cross-cycle merge: restored {n_promoted} "
                    f"object(s) to their previously-higher-signal version "
                    f"(cross-cycle label/score preservation — pycti UPSERT "
                    f"overwrite + 2026-05-21 P0f-overwrite bug)"
                )

        # --- Step 1: label-union dedup (LESSONS §6) ----------------------
        before = len(objects)
        deduped = self._dedup_label_union(objects)
        after = len(deduped)
        if before > 0:
            reduction_pct = 100.0 * (before - after) / before
        else:
            reduction_pct = 0.0
        if before != after:
            logger.info(
                f"[{cycle_id}] Bundle dedup: collapsed {before - after} "
                f"duplicate object(s) (label-union applied); "
                f"{before} -> {after} ({reduction_pct:.1f}% reduction)"
            )

        # --- Step 2: validate types (LESSONS §8.4) -----------------------
        unknown = validate_types(deduped)
        if unknown:
            log_unknown_types(unknown)

        # --- Step 2b: referential-integrity pre-flight -------------------
        # Drop relationships/sightings (and prune Note.object_refs) whose
        # endpoints are neither in this bundle nor currently in OpenCTI —
        # the recurring MISSING_REFERENCE_ERROR root cause (cross-cycle refs
        # to objects that decayed / were pruned / never imported). Converts
        # an opaque OpenCTI import error + silent edge loss into a clean,
        # logged, intentional drop.
        deduped, n_stripped = self._strip_unresolvable_references(deduped, cycle_id)

        # --- Step 3: partition into three passes -------------------------
        passes = self._partition(deduped, cycle_id)
        pass_counts = {name: len(objs) for name, objs in passes.items()}

        # --- Step 4: three-pass send with 30s sleeps between non-empty ---
        # Determine which passes will actually be sent so we can skip
        # sleeping after the last non-empty one.
        non_empty_names = [n for n, objs in passes.items() if objs]
        for idx, name in enumerate(["foundation", "entities", "relationships"]):
            objs = passes[name]
            if not objs:
                logger.debug(
                    f"[{cycle_id}] Pass '{name}' is empty; skipping send."
                )
                continue
            envelope = {
                "type": "bundle",
                "id": bundle_id,
                "objects": objs,
            }
            try:
                stats = self.client.send_bundle(envelope)
                logger.info(
                    f"[{cycle_id}] Pass '{name}' sent: "
                    f"{stats.get('sent', len(objs))} object(s) in "
                    f"{stats.get('duration_s', 0.0):.2f}s"
                )
            except Exception as exc:  # noqa: BLE001
                # Partial publish > no publish. Continue to next pass.
                msg = (
                    f"Pass '{name}' failed: {type(exc).__name__}: {exc}. "
                    f"Continuing to next pass — V1_SPEC §7 says never "
                    f"block a cycle on a single failure."
                )
                logger.warning(f"[{cycle_id}] {msg}")
                errors.append(msg)

            # Liveness heartbeat — each pass can take minutes at hive
            # scale; bump after every one (success OR partial failure) so
            # /health stays at 200 through a long publish. Best-effort;
            # never let a state write abort the publish. See health.py.
            if self.state is not None:
                try:
                    self.state.heartbeat()
                except Exception as exc:  # noqa: BLE001
                    logger.debug(f"[{cycle_id}] heartbeat failed (ignored): {exc}")

            # Sleep between non-empty passes only. No need to sleep after
            # the last one — there's nothing waiting on it to be indexed.
            is_last_non_empty = (
                non_empty_names and name == non_empty_names[-1]
            )
            if not is_last_non_empty and self._sleep_seconds > 0:
                logger.debug(
                    f"[{cycle_id}] Sleeping {self._sleep_seconds}s before "
                    f"next pass (V1_SPEC §3 indexing delay)."
                )
                time.sleep(self._sleep_seconds)

        duration_s = time.monotonic() - started

        result = PublishResult(
            cycle_id=cycle_id,
            pass_counts=pass_counts,
            total_objects_before_dedup=before,
            total_objects_after_dedup=after,
            dedup_reduction_pct=reduction_pct,
            unknown_types=dict(unknown),
            duration_s=duration_s,
            errors=errors,
            bundle_id=bundle_id,
        )

        # --- Step 5: persist into state ----------------------------------
        if self.state is not None:
            self._record_result(result)
            # Cross-cycle merge state — write back AFTER successful publish
            # so a failed publish doesn't poison future cycles' baselines.
            # We persist regardless of partial errors (some passes ok, some
            # not) because the in-bundle state was at-least-attempted; this
            # matches V1_SPEC §7 "partial publish > no publish" semantics.
            try:
                self.state.upsert_max_state_bulk(merged_state_updates)
            except Exception as e:
                logger.warning(
                    f"[{cycle_id}] object_max_state upsert failed "
                    f"(non-fatal): {e}"
                )

        logger.info(
            f"[{cycle_id}] Publish complete: "
            f"passes={pass_counts} dedup={before}->{after} "
            f"errors={len(errors)} duration={duration_s:.2f}s"
        )

        return result

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _dedup_label_union(self, objects: list[dict]) -> list[dict]:
        """Collapse duplicate STIX ids; union list-set fields.

        Port of the PoC's bundle dedup block per LESSONS §6, with two
        adjustments for V1:

        * ``external_references`` are list-extended with id-dedupe (PoC
          relied on OpenCTI's worker for this; we do it client-side
          since the worker silently drops dupes anyway).
        * ``confidence`` takes the max across duplicates (PoC was last-
          write-wins; max is safer because high-confidence emissions
          shouldn't be downgraded by a later low-confidence dupe).

        Objects without an ``id`` (or ``standard_id``) field are passed
        through untouched. Insertion order is preserved on first-seen.
        """
        by_id: dict[str, list[dict]] = {}
        order: list[str] = []
        passthrough: list[dict] = []
        for obj in objects:
            oid = obj.get("id") or obj.get("standard_id")
            if not oid:
                # Bundle envelopes, parser-internal stubs, etc. Keep as-is.
                passthrough.append(obj)
                continue
            if oid not in by_id:
                order.append(oid)
            by_id.setdefault(oid, []).append(obj)

        out: list[dict] = []
        collapsed = 0
        for oid in order:
            variants = by_id[oid]
            if len(variants) == 1:
                out.append(variants[0])
                continue
            collapsed += len(variants) - 1

            # Last-write-wins for scalars, except confidence (max) and
            # the list-set merge keys (union).
            base = dict(variants[-1])

            # --- list-set unions (preserve first-seen order) -------------
            for key in self._MERGE_LIST_KEYS:
                seen: list[Any] = []
                for v in variants:
                    for val in (v.get(key) or []):
                        if val not in seen:
                            seen.append(val)
                if seen:
                    base[key] = seen

            # --- external_references id-dedupe ---------------------------
            xref_seen_ids: set[str] = set()
            xref_merged: list[dict] = []
            for v in variants:
                for xref in (v.get("external_references") or []):
                    key = (
                        xref.get("source_name", "")
                        + "|"
                        + xref.get("external_id", "")
                        + "|"
                        + xref.get("url", "")
                    )
                    if key in xref_seen_ids:
                        continue
                    xref_seen_ids.add(key)
                    xref_merged.append(xref)
            if xref_merged:
                base["external_references"] = xref_merged

            # --- confidence: max across variants -------------------------
            confidences = [
                v.get("confidence") for v in variants
                if isinstance(v.get("confidence"), (int, float))
            ]
            if confidences:
                base["confidence"] = max(confidences)

            out.append(base)

        # Append any passthrough (id-less) objects at the end so they
        # don't shuffle ahead of the well-formed ones.
        return out + passthrough

    @staticmethod
    def _endpoint_refs(obj: dict) -> list[str]:
        """STIX ids this object points AT as a relationship/sighting endpoint.

        (``Note.object_refs`` is handled separately — those are pruned in
        place rather than dropping the whole Note.)
        """
        t = obj.get("type")
        if t == "relationship":
            return [r for r in (obj.get("source_ref"), obj.get("target_ref")) if r]
        if t == "sighting":
            rs = [obj.get("sighting_of_ref")]
            rs += obj.get("where_sighted_refs") or []
            rs += obj.get("observed_data_refs") or []
            return [r for r in rs if r]
        return []

    def _strip_unresolvable_references(
        self, objects: list[dict], cycle_id: str,
    ) -> tuple[list[dict], int]:
        """Drop objects whose endpoints OpenCTI can't resolve.

        Every relationship/sighting endpoint and every ``Note.object_refs``
        target must resolve at import time or OpenCTI raises
        MISSING_REFERENCE_ERROR. Endpoints that are in THIS bundle are fine
        (created in an earlier pass). For endpoints NOT in the bundle —
        cross-cycle references (campaign attribution edges, attacker-profile
        Notes, etc.) — we verify they actually still exist in OpenCTI via
        ``client.exists_bulk`` and drop the ones that don't.

        Returns ``(kept_objects, n_dropped)``. No-op (and zero cost) when the
        bundle has no out-of-bundle references or the client predates
        ``exists_bulk`` (test stubs).
        """
        if not objects:
            return objects, 0
        present = {o.get("id") for o in objects if o.get("id")}

        out_of_bundle: set[str] = set()
        for o in objects:
            for r in self._endpoint_refs(o):
                if r not in present:
                    out_of_bundle.add(r)
            for r in (o.get("object_refs") or []):
                if r not in present:
                    out_of_bundle.add(r)
        if not out_of_bundle:
            return objects, 0

        exists_bulk = getattr(self.client, "exists_bulk", None)
        if not callable(exists_bulk):
            return objects, 0  # stub client (tests) — skip the check
        try:
            existing = exists_bulk(out_of_bundle)
        except Exception as exc:  # noqa: BLE001 — fail-open
            logger.debug(
                f"[{cycle_id}] exists_bulk raised (ignored, keeping all refs): {exc}"
            )
            return objects, 0
        missing = {r for r in out_of_bundle if r not in existing}
        if not missing:
            return objects, 0

        kept: list[dict] = []
        dropped = 0
        detail: dict[str, int] = defaultdict(int)
        for o in objects:
            bad = [r for r in self._endpoint_refs(o) if r in missing]
            if bad:
                dropped += 1
                detail[f"{o.get('type')}[{o.get('relationship_type', '-')}]→"
                       f"{bad[0].split('--')[0]}"] += 1
                continue
            # Prune dangling object_refs from a Note; drop it only if that
            # empties the list (an object-less Note can't import).
            orefs = o.get("object_refs")
            if orefs:
                good = [r for r in orefs if r not in missing]
                if not good:
                    dropped += 1
                    detail["note[object_refs-emptied]"] += 1
                    continue
                if len(good) != len(orefs):
                    o["object_refs"] = good
            kept.append(o)

        logger.warning(
            f"[{cycle_id}] referential-integrity pre-flight: dropped {dropped} "
            f"object(s) referencing {len(missing)} endpoint(s) absent from "
            f"OpenCTI (would MISSING_REFERENCE). Breakdown: {dict(detail)}. "
            f"Sample missing: {sorted(missing)[:3]}"
        )
        return kept, dropped

    def _partition(
        self, objects: list[dict], cycle_id: str,
    ) -> dict[str, list[dict]]:
        """Split into foundation / entities / relationships sub-lists.

        Objects with a type not in any pass set fall through to
        ``relationships`` with a WARN — keeps the cycle moving but makes
        the misclassification visible. (The import-time assertion at
        module load should make this unreachable in practice.)
        """
        out: dict[str, list[dict]] = {
            "foundation": [],
            "entities": [],
            "relationships": [],
        }
        for obj in objects:
            t = obj.get("type")
            if t in FOUNDATION_TYPES:
                out["foundation"].append(obj)
            elif t in ENTITY_TYPES:
                out["entities"].append(obj)
            elif t in RELATIONSHIP_TYPES:
                out["relationships"].append(obj)
            else:
                logger.warning(
                    f"[{cycle_id}] Unclassified STIX type {t!r} on object "
                    f"{obj.get('id')!r}; falling through to relationships "
                    f"pass. Update FOUNDATION/ENTITY/RELATIONSHIP_TYPES "
                    f"in tpot2cti.publisher."
                )
                out["relationships"].append(obj)
        return out

    def _record_result(self, result: PublishResult) -> None:
        """Persist a publish result into :class:`CycleState`.

        ``state.record_cycle`` (Phase 2) is keyed by an integer cycle_id
        from the importer's outer cycle loop, not our per-publish UUID,
        and its column set is the broader audit shape (events_read,
        sdos_emitted, etc.) — fields the publisher doesn't know about.
        Rather than fabricating values, we stash the publish-specific
        result via the generic key/value store under
        ``publish:<cycle_id>``. The Phase 6 audit writer joins this with
        the cycle_log row when emitting the jsonl audit doc.
        """
        import json as _json

        try:
            self.state.set(
                f"publish:{result.cycle_id}",
                _json.dumps({
                    "cycle_id": result.cycle_id,
                    "bundle_id": result.bundle_id,
                    "pass_counts": result.pass_counts,
                    "total_objects_before_dedup": result.total_objects_before_dedup,
                    "total_objects_after_dedup": result.total_objects_after_dedup,
                    "dedup_reduction_pct": result.dedup_reduction_pct,
                    "unknown_types": result.unknown_types,
                    "duration_s": result.duration_s,
                    "errors": result.errors,
                }),
            )
        except Exception as exc:  # noqa: BLE001
            # State persistence MUST NOT fail the cycle.
            logger.warning(
                f"Could not persist publish result for {result.cycle_id}: "
                f"{type(exc).__name__}: {exc}"
            )


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s %(message)s",
    )

    # --- A fake OpenCTIClient with no network requirement ----------------
    class FakeClient:
        def __init__(self) -> None:
            self.sent_bundles: list[dict] = []

        def send_bundle(self, bundle: dict, update: bool = False) -> dict:
            self.sent_bundles.append(bundle)
            return {
                "sent": len(bundle.get("objects", [])),
                "duration_s": 0.01,
                "raw_response": None,
            }

    # --- Build ~30 objects mixing the three passes -----------------------
    foundation_objs = [
        {"type": "identity", "id": "identity--op", "name": "Operator"},
        {
            "type": "marking-definition",
            "id": "marking-definition--tlp-amber-strict",
        },
        {"type": "attack-pattern", "id": "attack-pattern--t1110"},
        {"type": "location", "id": "location--us"},
        {"type": "autonomous-system", "id": "autonomous-system--as15169"},
    ]

    entity_objs = []
    for i in range(12):
        entity_objs.append({
            "type": "ipv4-addr",
            "id": f"ipv4-addr--{i:08x}",
            "value": f"10.0.0.{i}",
            "labels": [f"src:cowrie", "honeypot"],
        })
    entity_objs.extend([
        {"type": "file", "id": "file--abc",
         "hashes": {"SHA-256": "deadbeef"}},
        {"type": "url", "id": "url--xyz", "value": "http://bad.example/"},
        {"type": "domain-name", "id": "domain--ex", "value": "bad.example"},
        {"type": "indicator", "id": "indicator--1",
         "pattern": "[ipv4-addr:value='10.0.0.1']"},
        {"type": "note", "id": "note--abc", "content": "..."},
    ])

    relationship_objs = []
    for i in range(8):
        relationship_objs.append({
            "type": "sighting",
            "id": f"sighting--{i:08x}",
            "sighting_of_ref": f"indicator--{i % 2}",
        })
    relationship_objs.append({
        "type": "relationship",
        "id": "relationship--r1",
        "relationship_type": "uses",
    })

    objs: list[dict] = foundation_objs + entity_objs + relationship_objs

    # --- Insert duplicates to exercise label-union dedup ----------------
    objs.append({
        "type": "ipv4-addr",
        "id": "ipv4-addr--00000001",   # duplicate of entity 1
        "value": "10.0.0.1",
        "labels": ["src:dionaea", "high-volume"],
        "confidence": 50,
    })
    objs.append({
        "type": "ipv4-addr",
        "id": "ipv4-addr--00000001",   # second duplicate
        "value": "10.0.0.1",
        "labels": ["src:honeytrap"],
        "confidence": 80,
        "external_references": [
            {"source_name": "abuseipdb", "external_id": "1234"},
        ],
    })
    objs.append({
        "type": "sighting",
        "id": "sighting--00000000",    # duplicate sighting
        "sighting_of_ref": "indicator--0",
        "labels": ["second-emission"],
    })

    print(f"Total objects in synthetic bundle: {len(objs)}")

    # --- Run the publisher with the fake client -------------------------
    fake = FakeClient()
    pub = Publisher(client=fake, state=None)
    # Disable sleeps for the smoke test.
    Publisher._sleep_seconds = 0

    result = pub.publish(objs, cycle_id="smoke-cycle-0001")

    # --- Assertions -----------------------------------------------------
    assert result.cycle_id == "smoke-cycle-0001"
    assert result.bundle_id.startswith("bundle--")
    assert not result.errors, f"expected no errors, got {result.errors!r}"

    # 3 duplicate object ids -> after dedup, 3 fewer
    expected_after = len(objs) - 3
    assert result.total_objects_after_dedup == expected_after, (
        f"expected {expected_after} after dedup, "
        f"got {result.total_objects_after_dedup}"
    )

    # Pass counts add up to the deduped total
    assert sum(result.pass_counts.values()) == expected_after, (
        f"pass counts {result.pass_counts} should sum to {expected_after}"
    )

    # Pass partitioning sanity
    assert result.pass_counts["foundation"] == len(foundation_objs), (
        f"foundation pass: expected {len(foundation_objs)}, "
        f"got {result.pass_counts['foundation']}"
    )
    assert result.pass_counts["entities"] == len(entity_objs), (
        f"entities pass: expected {len(entity_objs)}, "
        f"got {result.pass_counts['entities']}"
    )
    # relationships: 9 originals + the duplicate sighting was collapsed
    # into one of the originals, so deduped count == len(relationship_objs).
    assert result.pass_counts["relationships"] == len(relationship_objs), (
        f"relationships pass: expected {len(relationship_objs)}, "
        f"got {result.pass_counts['relationships']}"
    )

    # All three passes should have been sent to the fake client (one
    # call per non-empty pass).
    assert len(fake.sent_bundles) == 3, (
        f"expected 3 sub-bundles sent, got {len(fake.sent_bundles)}"
    )
    types_per_pass = [
        {o.get("type") for o in b["objects"]} for b in fake.sent_bundles
    ]
    assert types_per_pass[0] <= FOUNDATION_TYPES
    assert types_per_pass[1] <= ENTITY_TYPES
    assert types_per_pass[2] <= RELATIONSHIP_TYPES

    # Verify label-union actually happened on the duplicated IPv4-Addr.
    entity_bundle = fake.sent_bundles[1]
    merged_ip = next(
        o for o in entity_bundle["objects"]
        if o.get("id") == "ipv4-addr--00000001"
    )
    merged_labels = set(merged_ip.get("labels") or [])
    expected_labels = {
        "src:cowrie", "honeypot", "src:dionaea", "high-volume", "src:honeytrap",
    }
    assert merged_labels == expected_labels, (
        f"label-union failed: got {merged_labels}, expected {expected_labels}"
    )
    # Confidence should be max(50, 80) = 80
    assert merged_ip.get("confidence") == 80, (
        f"confidence should be 80 (max), got {merged_ip.get('confidence')!r}"
    )
    # external_references should be preserved
    xrefs = merged_ip.get("external_references") or []
    assert any(x.get("external_id") == "1234" for x in xrefs), (
        f"external_references missing: {xrefs!r}"
    )

    print(
        f"Dedup: {result.total_objects_before_dedup} -> "
        f"{result.total_objects_after_dedup} "
        f"({result.dedup_reduction_pct:.2f}% reduction)"
    )
    print(f"Pass counts: {result.pass_counts}")
    print(f"Bundle id: {result.bundle_id}")
    print(f"Errors: {result.errors}")
    print(f"Duration: {result.duration_s:.4f}s")
    print("OK")
