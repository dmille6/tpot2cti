# tpot2cti — STIX 2.1 object builder.

The builder is stateful per-bundle: a new STIXBuilder instance is
created at the start of each cycle, accumulates per-bundle dedup
state (which Identities / Infrastructures / Locations have already
been emitted in THIS bundle), and produces a list of STIX object
dicts ready for the publisher.

Per V1_SPEC.md §4 (STIX object model) the builder emits:

  Foundation:    Identity (operator + sensor), Marking-Definition,
                 Location, Autonomous-System, AttackPattern
  Entities:      IPv4-Addr, StixFile, URL, Domain-Name, Process,
                 Cryptographic-Key, Indicator, Note, Vulnerability
  Relationships: Relationship, Sighting

Every emitted object:
  - has a deterministic id from `tpot2cti.stix_ids`
  - is stamped with `created_by_ref` pointing at the operator Identity
  - is stamped with `object_marking_refs` referencing the default TLP
  - has `created` + `modified` timestamps in ISO 8601 UTC
  - has `confidence` set from config

The substance-filter pattern lives in `BaseParser.has_substance()` —
the builder doesn't decide what to emit; it only knows HOW to emit
the things the parser asked for.  The caller pattern is:

    parser = get_parser(doc['type'])
    for session in parser.correlate(events):
        if parser.has_substance(session):
            stix_objects = builder.build_full_session(session)
        else:
            stix_objects = builder.build_driveby_session(session)
