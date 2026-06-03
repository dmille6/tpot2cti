"""tpot2cti — STIX 2.1 type allowlist.

See docs/stix/types.md for design notes.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Iterable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# The allowlist
# ---------------------------------------------------------------------------

#: Every STIX 2.1 `type` value tpot2cti deliberately emits.
#: ADD an entry here whenever V1_SPEC introduces a new object type.
#: REMOVE an entry only after auditing all parsers don't still emit it.
KNOWN_STIX_TYPES: frozenset[str] = frozenset({
    # ─── Foundation SDOs (per V1_SPEC §4) ─────────────────────────────
    "identity",
    "marking-definition",
    "location",
    "attack-pattern",
    "autonomous-system",

    # ─── Entities (per V1_SPEC §4) ────────────────────────────────────
    "ipv4-addr",
    "ipv6-addr",          # rarely seen but legal — emit if we see it
    "file",
    "url",
    "domain-name",
    "process",
    "cryptographic-key",  # CORRECT spelling per V1_SPEC + §8.4 lesson
    "indicator",
    "note",
    "vulnerability",      # CVE refs from Suricata + parsers that extract
    "campaign",           # shared-IoC attacker grouping (tpot2cti/campaigns.py)

    # ─── Relationships (per V1_SPEC §4) ───────────────────────────────
    "relationship",
    "sighting",

    # ─── Bundle envelope ─────────────────────────────────────────────
    "bundle",
})

#: STIX `type` values that LOOK plausible but are NOT what tpot2cti emits.
#: Used by `validate_types()` to log a more specific warning when one of
#: these slips in — e.g. the V0 bug where `x-opencti-cryptographic-key`
#: was emitted instead of `cryptographic-key`.
KNOWN_BAD_TYPES: dict[str, str] = {
    "x-opencti-cryptographic-key": "type is `cryptographic-key` (no x-opencti prefix)",
    "stixfile":     "type is `file` per STIX 2.1",
    "ipv4_addr":    "type is `ipv4-addr` (hyphen, not underscore)",
    "stix-file":    "type is `file`",
    "user-account": "tpot2cti does NOT emit user-account SCOs — credentials go in daily Note (V1_SPEC §6)",
}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_types(objects: Iterable[dict]) -> Counter:
    """Walk a list of STIX dicts and return a Counter of unknown types.

    Empty counter = all types are allowlisted.  Non-empty counter =
    one or more objects have types NOT in `KNOWN_STIX_TYPES`.  The
    publisher logs WARNING for each unknown type with the bad-type
    hint if applicable, then ships the bundle anyway (we don't drop
    objects pre-emptively — the type might be a real one we just
    forgot to allowlist; let OpenCTI's worker decide).
    """
    unknown: Counter = Counter()
    for obj in objects:
        t = obj.get("type")
        if not t:
            unknown["__missing_type__"] += 1
        elif t not in KNOWN_STIX_TYPES:
            unknown[t] += 1
    return unknown


def hint_for(type_name: str) -> str:
    """Return a helpful hint for an unknown type, or generic guidance."""
    if type_name in KNOWN_BAD_TYPES:
        return KNOWN_BAD_TYPES[type_name]
    return (
        f"Add to KNOWN_STIX_TYPES in tpot2cti/stix/types.py if intentional, "
        f"or fix the parser.  Unknown types are silently dropped by "
        f"OpenCTI's worker — see LESSONS §8.4."
    )


def log_unknown_types(unknown: Counter) -> None:
    """Emit one WARNING per unknown type with a helpful hint."""
    for t, count in unknown.most_common():
        logger.warning(
            f"SILENT-DROP RISK: emitted {count} object(s) with unrecognized "
            f"STIX type {t!r}.  {hint_for(t)}"
        )
