# Parser design notes

One file per honeypot parser in `tpot2cti/parsers/`, holding the **narrative**
documentation — protocol background, the T-Pot ES fields the parser reads, the
STIX graph emitted per session, and the substance-filter rationale — that used
to live in long module docstrings.

The parser source keeps only a concise summary docstring plus a pointer to its
note here (`docs/parsers/<name>.md`). Tests live in `tests/` (run by CI), not
in `if __name__ == "__main__"` blocks.

Conventions referenced in these notes:

- **Substance filter** (`has_substance()`): a per-parser, per-protocol decision
  about whether a correlated session is worth a full STIX SDO graph. Drive-by
  probes with no real signal are dropped. See `../LESSONS_LEARNED_FROM_V0.md` §2.
- **STIX build**: parsers only `parse()` + `correlate()` + `has_substance()`.
  The STIX bundle is built downstream in `tpot2cti/stix/builder.py`; parsers
  populate `session.meta` with whatever the builder needs.

| Parser | Honeypot |
|---|---|
| [medpot](medpot.md) | HL7 medical-messaging |
