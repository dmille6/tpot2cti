# tpot2cti — STIX text-rendering helpers.

Per the V0 parser-vs-builder separation rule ("Honeypot-specific IoC extraction belongs in the
STIX builder, not the parser"), parsers stay pure (model-only). They
convert raw ES docs into typed Python objects; STIX-shape decisions and
text rendering for Notes / Sighting descriptions live here.

These are PURE FUNCTIONS taking AttackSession (and sometimes ParsedEvent).
No I/O, no STIX-object construction — they only produce strings the
STIXBuilder methods embed into emitted SDOs.
