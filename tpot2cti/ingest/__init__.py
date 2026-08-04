"""Additional ingest paths beyond the honeypot event stream.

CORE (``tpot2cti.main``) reads T-Pot's ``logstash-*`` honeypot events. Modules
here read *other* hive indices that already contain intelligence, and turn
them into the same STIX graph using the same identity and publish stack.

Each module runs as its own process (own compose service, own cursor, own
health), so it can never slow or break the CORE cycle — see
``docs/ENRICHMENT.md`` §3.
"""
