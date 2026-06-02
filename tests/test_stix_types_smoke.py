"""Smoke test for tpot2cti.stix.types (migrated from its old
`if __name__` block so CI runs it)."""
from __future__ import annotations

import tpot2cti.stix.types as _m
globals().update({k: v for k, v in vars(_m).items() if not k.startswith('__')})


def test_types_smoke():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    sample = [
        {"type": "ipv4-addr", "value": "1.2.3.4"},
        {"type": "indicator", "pattern": "[ipv4-addr:value = '1.2.3.4']"},
        {"type": "x-opencti-cryptographic-key", "value": "abc"},  # bad — should warn
        {"type": "user-account", "user_id": "root"},               # bad — should warn
        {"type": "frobnicator"},                                    # unknown
        {},                                                         # missing type
    ]
    unknown = validate_types(sample)
    print(f"unknown types found: {dict(unknown)}")
    log_unknown_types(unknown)
    print(f"\nallowlist has {len(KNOWN_STIX_TYPES)} types")
