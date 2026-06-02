# tpot2cti — pivot-menu external_references for STIX observables.

Returns STIX 2.1 `external_references` dicts that give the OpenCTI
analyst one-click pivots to authoritative threat-intel lookup pages
(AbuseIPDB, VirusTotal, Shodan, Censys, GreyNoise, etc.). Analysts open
the IP page during triage far more often than they open the Indicator
page, so the pivot menu belongs on the observable too — not only the
indicator.

Adapted from the PoC at
tsec-tpot-connectors/shared/tsec_external_refs.py
(see also docs/LESSONS_LEARNED_FROM_V0.md §6 and the first-live-install
postmortem on "thin objects").

Field name is the STIX 2.1 standard `external_references` — NOT the
x_opencti_-prefixed form. The x_opencti_ prefix is reserved for
non-standard fields; external_references is in-spec.

All pivots are vendor-neutral public lookup pages — no API keys
required for analyst navigation. The links resolve in any modern
browser. If a vendor changes their URL scheme we update here; existing
emissions get the new URL automatically on the next cycle's upsert.
