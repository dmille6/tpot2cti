# Credential store

`tpot2cti/credential_store.py`

A single bruteforce run can be tens of thousands of (username, password)
attempts. Emitting those as OpenCTI objects would flood the platform, so we
**keep the bulk pairs out of OpenCTI entirely** and record them in a local
database instead. OpenCTI receives only **one Note per attacker IP** that
summarises the pairs tried and flags which (if any) was accepted.

This mirrors the production `tsec-tpot-connectors` approach (which uses
DuckDB) — here implemented with stdlib `sqlite3`, the same engine OSS already
uses for `state.db`, to avoid adding a dependency to the lean core.

## Schema

- **`credential_pairs`** — one row per unique `(username, password)` with
  `total_attempts`, `first_seen`/`last_seen`, password length / empty flag.
- **`credential_usage`** — one row per `(credential_id, attacker_ip,
  honeypot_name, service, port)` with `attempt_count`, `success_count`, and
  attacker geo/ASN. Repeat attempts increment counters (UPSERT), so a
  10k-attempt spray collapses to a bounded set of rows, not 10k inserts.

`get_ip_credentials(ip)` returns the per-IP summary the publisher renders
into the Note.

## TODO (wiring step)

- **Batch writes.** `record_attempt()` commits per call; at bruteforce scale
  the cycle should write all of a cycle's attempts in one transaction (add a
  `record_attempts(iterable)` batch method) to avoid an fsync per attempt.
- **Pruning.** Add retention so the store stays bounded (mirror the
  `state.py` prune pattern).
