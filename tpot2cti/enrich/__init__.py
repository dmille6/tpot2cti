"""The ENRICH ring — adds context to observables CORE already emitted.

Every module here runs as its own process (own compose service, own state DB,
own health) so an enrichment stall can never slow or break the honeypot cycle.
Design and contracts: ``docs/ENRICHMENT.md``.
"""
