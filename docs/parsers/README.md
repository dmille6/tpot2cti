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
| [adbhoney](adbhoney.md) | Android Debug Bridge honeypot (port 5555). |
| [beelzebub](beelzebub.md) | LLM-driven SSH/HTTP/TCP honeypot. |
| [ciscoasa](ciscoasa.md) | Cisco ASA emulator (CVE-2018-0101 and friends). |
| [conpot](conpot.md) | ICS/SCADA protocol honeypot. |
| [cowrie](cowrie.md) | SSH and Telnet honeypot sessions. |
| [dicompot](dicompot.md) | DICOM medical-imaging honeypot. |
| [dionaea](dionaea.md) | binary-catching honeypot (SMB / FTP / HTTP / MS-SQL / MySQL). |
| [elasticpot](elasticpot.md) | fake Elasticsearch HTTP API honeypot. |
| [fallback](fallback.md) | handles any T-Pot honeypot type without a dedicated parser. |
| [fatt](fatt.md) | passive TLS/SSH fingerprint observations. |
| [galah](galah.md) | LLM-driven HTTP/HTTPS web honeypot. |
| [h0neytr4p](h0neytr4p.md) | HTTP/HTTPS web application honeypot. |
| [heralding](heralding.md) | multi-protocol credential capture honeypot. |
| [honeyaml](honeyaml.md) | YAML / IaC config-probe honeypot. |
| [honeytrap](honeytrap.md) | TCP/UDP catchall honeypot. |
| [ipphoney](ipphoney.md) | Internet Printing Protocol (IPP) honeypot. |
| [mailoney](mailoney.md) | fake SMTP / spam-relay probe honeypot. |
| [medpot](medpot.md) | HL7 medical-messaging honeypot |
| [miniprint](miniprint.md) | line-printer / IPP / PJL honeypot (port 9100). |
| [nginx](nginx.md) | custom nginx access logs from persona HTTP fronts. |
| [redishoneypot](redishoneypot.md) | fake Redis honeypot. |
| [router](router.md) | honeypot-router (Telnet console) emulator. |
| [sentrypeer](sentrypeer.md) | SIP / VoIP honeypot. |
| [suricata](suricata.md) | network IDS alerts. |
| [tanner](tanner.md) | SNARE/TANNER web-application honeypot. |
| [wordpot](wordpot.md) | fake WordPress honeypot. |
