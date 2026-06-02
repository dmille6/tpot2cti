# tpot2cti — STIX 2.1 type allowlist.

Per docs/LESSONS_LEARNED_FROM_V0.md §8.4:

    Silent drop of unknown STIX types.  If you emit an object with a
    STIX `type` field that OpenCTI's worker doesn't recognize, it's
    silently dropped.  No error, no warning.

    The PoC's defense: maintain a `KNOWN_STIX_TYPES` allowlist. Before
    sending a bundle, check every object's type against the allowlist.
    Anything unknown logs a WARNING.

This module is that allowlist plus the validation helper the publisher
calls before send.  Keep it CURRENT — when V1_SPEC §5 adds support for
a new STIX type, add it here too or the publisher will silently
warn-spam the logs and the new type will be dropped.

The set below is EXACTLY what we intend to emit per V1_SPEC §4
("STIX object model" table).  We deliberately keep it tight — adding
a type should require a deliberate change here, not slip in from a
typo in a parser.
