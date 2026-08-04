"""ES query construction for the credentials sidecar.

Kept in its own dependency-free module (stdlib only) so the field-name
contract is unit-testable without importing the sidecar's DuckDB stack.
"""
from __future__ import annotations

from datetime import datetime, timezone


def build_credential_query(credential_types, start: datetime, end: datetime) -> dict:
    """Build the ES ``bool`` query for credential-bearing events in [start, end).

    The honeypot ``type`` filter MUST use ``type.keyword``. T-Pot's ``type`` is
    an analyzed (lowercased, tokenized) field, so a ``terms`` query against the
    capitalized values ("Cowrie", "Heralding", …) matches NOTHING — this exact
    bug made the sidecar silently collect zero credentials for weeks. Same fix
    as ``tpot2cti/es_client.py``; see ``LESSONS_LEARNED_FROM_V0`` B.1.
    """
    return {
        "bool": {
            "must": [
                {"range": {"@timestamp": {
                    "gte": start.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "lt": end.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                }}},
                {"terms": {"type.keyword": list(credential_types)}},
            ]
        }
    }
