# Changelog

All notable changes to `tpot2cti` are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); dates are UTC.

## [Unreleased]

### Fixed

- **CORE: attacker-IP ATT&CK patterns are no longer re-emitted per session
  (ingestion-outage fix).** `STIXBuilder.build_attack_pattern()` ended with
  `return self._dedup(...) or obj`; the `or obj` fallback re-emitted the full
  AttackPattern SDO on every duplicate id instead of returning `None` like
  every sibling `build_*` method. Because `build_session_attack_patterns()`
  runs for **every** session, the ~30 unique techniques were re-minted once
  per substantive session — a busy catch-up window produced ~947k duplicate
  attack-pattern dicts in a single bundle (~96% of all emitted SDOs). All five
  call sites already guard with `if ap:` / `if not ap: continue`, so `None`
  is the correct contract. (`tpot2cti/stix/builder.py`)

- **CORE: `/health` no longer stays green while cycles fail forever.** The
  health check kept returning 200 as long as cycles *started* (the heartbeat
  arm), so during the outage above it reported healthy for 16 days while no
  cycle ever *completed*. The heartbeat arm now has a hard ceiling
  (`NO_SUCCESS_CEILING_MULTIPLIER = 3.0` × cycle interval): if no cycle has
  succeeded within it, `/health` returns 503 with `liveness:
  "cycling-no-success"` even while the process keeps looping, so the Docker
  healthcheck (`curl -f`) marks the container unhealthy within ~3 intervals.
  A genuinely long single cycle stays under the ceiling and still won't flap.
  (`tpot2cti/health.py`)

- **CORE: `CycleState.get_max_state_bulk()` now chunks its `IN (...)` lookup.**
  The pre-dedup cross-cycle state lookup put one bound variable per emitted
  object into a single `WHERE stix_id IN (...)`. Combined with the runaway
  attack-pattern bundle above, this overflowed SQLite's
  `SQLITE_MAX_VARIABLE_NUMBER` and raised `OperationalError: too many SQL
  variables` on **every** publish. Because the cursor only advances on publish
  success (by design), `last_run` never moved and the importer retried the
  same window indefinitely — ingestion was stalled from ~2026-07-19 to
  2026-08-04 while the process stayed "healthy." The lookup now batches at
  `_SQL_VAR_CHUNK = 500`, well under the oldest limit (999), so no bundle size
  can trip it. (`tpot2cti/state.py`)

### Tests

- Added regression coverage for both fixes (442 passing, up from 439):
  - `tests/test_attack_mapping.py::test_attack_patterns_dedupe_across_sessions`
    and `::test_build_attack_pattern_returns_none_on_duplicate` — a duplicate
    technique from a second same-IP session must not be re-emitted.
  - `tests/test_state.py::test_get_max_state_bulk_chunks_large_id_list` —
    `get_max_state_bulk()` over 5,000 ids succeeds and still returns the rows
    it has.

### Operational note

- The window auto-caps to 1 day when `last_run` is >24h stale
  (`main.py:_compute_window`), so a multi-day stall resumes from *now* forward
  rather than backfilling. Recovering a gap requires a manual cursor rewind;
  see `docs/SOAK_NOTES.md` → "Known incidents."
