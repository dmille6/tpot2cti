# tpot2cti-vault — DISABLED 2026-05-29

This sidecar SFTPs malware samples off the T-Pot host (Dionaea / Cowrie
file drops) into a local `data/malware-vault/` and emits one File SCO
per artifact to OpenCTI.

## Why it's disabled

Audit on 2026-05-29 found:

- Fetched samples are now published to OpenCTI as StixFile IOCs (see opencti.py).
- Container ran `unhealthy` for most of its lifetime.
- The use case (file SCOs for malware drops) is already covered by the
  main importer's Dionaea parser via T-Pot's logstash output — which
  emits the SHA256 + filename + size as ES fields. The Dionaea parser
  in `tpot2cti/parsers/dionaea.py` extracts those into File SCOs
  with Indicator + Sighting graph.
- The duplicate SFTP path adds a moving part (SSH tunnel reuse,
  filesystem state, vault_state.db) without observed payoff.

## To re-enable

```bash
# In ~/tpot2cti/.env, add "vault" back to COMPOSE_PROFILES:
COMPOSE_PROFILES=credentials,vault

# Bring it up:
cd ~/tpot2cti && docker compose up -d tpot2cti-vault
```

Before re-enabling consider whether the original premise still holds:
- Is Dionaea's logstash output missing fields you need? (Check ES.)
- Is the SFTP path the only way to pull artifact *bytes* (not just
  hashes)? If yes, the vault is the right tool.
- Are you on a hive with > 5 sensors and the central import path
  scales poorly? (Original design rationale.)

## Files

Code is preserved as-is in this directory:

- `main.py` (279 LOC) — cycle loop
- `sftp_client.py` (182 LOC) — SFTP fetch with state tracking
- `store.py` (147 LOC) — DuckDB write of artifact metadata
- `config.py`, `log.py` — env loader + structured logging

`vault_state.db` and any `samples/` content from the prior runs are
left in place under `data/malware-vault/` for reference.

The compose service definition is still in `docker-compose.yml` under
`profiles: [vault]` so it doesn't run unless explicitly opted in.
