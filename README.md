# tpot2cti

**Turn T-Pot honeypot data into a STIX 2.1 threat-intelligence graph in OpenCTI.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![T-Pot](https://img.shields.io/badge/T--Pot-24.04-orange)](https://github.com/telekom-security/tpotce)
[![OpenCTI](https://img.shields.io/badge/OpenCTI-6.x-009688)](https://github.com/OpenCTI-Platform/opencti)
[![Status](https://img.shields.io/badge/Status-Beta-yellow)](#project-status)
[![Tests](https://img.shields.io/badge/tests-447%20passing-brightgreen)](tests/)

> 🚧 **Status: Beta — feature-complete v1.0, soak-testing in progress.**
> The importer, the three sidecars, and the install / teardown /
> wipe-and-fresh scripts all work end-to-end. Live ingestion against a
> production T-Pot has been running cleanly for multi-day soaks (see
> [`docs/SOAK_NOTES.md`](docs/SOAK_NOTES.md)). What we're polishing
> before a 1.0 tag: doc coverage, additional parsers as new T-Pot
> honeypot types ship, OpenCTI version-compat pinning. Bug reports and
> first-cycle install feedback are especially welcome.
> Predecessor V0 prototype (`tpot_threatintel`) post-mortem lives in
> [`docs/LESSONS_LEARNED_FROM_V0.md`](docs/LESSONS_LEARNED_FROM_V0.md).

---

## What is this?

`tpot2cti` is a bridge between your **T-Pot honeypot** and an
**OpenCTI** threat-intelligence platform. It runs as a small set of
containers next to a fresh OpenCTI install, connects to your T-Pot
over SSH, and continuously transforms raw honeypot events into a rich
STIX 2.1 entity-relationship graph that analysts can pivot through,
share with ISACs, and bridge into MISP.

**Before tpot2cti:**
T-Pot ships great honeypot capture. You get Elasticsearch + Kibana
dashboards with millions of flat events. Hunting for "what did this
attacker do across all my sensors?" is a manual cross-index query.

**After tpot2cti:**
Every attacker IP, captured file, command, and fingerprint becomes a
first-class entity in OpenCTI's graph. Sessions are correlated.
Sightings count. Geographic and ASN context are attached. The data is
**STIX 2.1 native** — meaning it's shareable in the format that sector
ISACs, ISAOs, and other threat-intel platforms speak natively.

> [!NOTE]
> **This project deploys OpenCTI from its official upstream repository,
> unmodified.** We don't fork or repackage OpenCTI — `setup.sh` pulls
> [OpenCTI-Platform/docker](https://github.com/OpenCTI-Platform/docker)
> directly and our containers bolt on via a shared Docker network. You
> always get exactly what OpenCTI ships.

---

## Why this exists

T-Pot is excellent at capture. OpenCTI is excellent at threat-intel
graph storage and analyst workflow. The gap is the importer that knows
T-Pot's 20+ honeypot event types and produces well-modeled STIX from
them. That importer is what this project is.

Other approaches we considered and didn't take:
- **Augmenting T-Pot's Kibana directly.** Tempting (zero new infrastructure)
  but locks you out of the STIX ecosystem.
- **MISP instead of OpenCTI.** Simpler but smaller graph capabilities.
  We chose OpenCTI for the entity-relationship richness; tpot2cti could
  add a MISP bridge as a future companion connector.
- **Custom UI.** Building yet another threat-intel UI is a tar pit.
  OpenCTI is mature, well-maintained, and what the community already
  knows.

---

## What you get

After ~10 minutes of setup, an analyst opens OpenCTI and sees:

- **Every attacker IP** as a STIX `IPv4-Addr` observable, complete with
  the country (`Location` SDO), ASN (`Autonomous-System` SDO), and a
  `Sighting` for every honeypot session they engaged in.
- **Every captured malware sample** as a `StixFile` observable (SHA-256
  keyed), linked back to the attacker who dropped it and the URL they
  downloaded it from.
- **Cowrie command sequences** as `Process` observables with the full
  command line they ran.
- **Tool fingerprints** (HASSH, JA3, JA3S, HTTP-header-hash) as
  `Cryptographic-Key` observables — letting you cluster attackers who
  use the same tooling.
- **MITRE ATT&CK alignment** — Suricata alerts with ATT&CK metadata
  become `AttackPattern` SDOs with proper STIX relationships.
- **Daily credential summaries** — top 100 username/password combos
  attempted per sensor, as a STIX `Note` (without flooding OpenCTI with
  individual credential observables).
- **STIX-native exports** — share your honeypot intel with sector ISACs,
  pipe it into MISP, or feed it into any STIX-aware tool.

---

## Architecture

```
┌─────────────────┐                       ┌──────────────────────────────────┐
│   T-Pot 24.04   │                       │  Your tpot2cti host              │
│  (your sensor)  │                       │  (4c / 16-32 GB / 128 GB)        │
│                 │                       │                                  │
│  - ES   :64298  │◄──── SSH tunnel ──────┤  ┌─ tpot-tunnel (autossh)     ─┐ │
│  - SSH  :64295  │                       │  │ forwards localhost:64298 ──┐ │ │
│                 │                       │  └────────────────────────────┘ │ │
└─────────────────┘                       │                                │ │
                                          │  ┌─ OpenCTI stack ──────────┐  │ │
                                          │  │ (cloned + run unmodified │  │ │
                                          │  │  from OpenCTI's repo)    │◄─┘ │
                                          │  └──────────────────────────┘    │
                                          │                                  │
                                          │  ┌─ tpot2cti (our connector) ─┐  │
                                          │  │ reads T-Pot ES via tunnel,  │  │
                                          │  │ emits STIX to OpenCTI       │  │
                                          │  └─────────────────────────────┘  │
                                          │                                  │
                                          │  Optional (compose profiles):    │
                                          │  ├─ tpot2cti-credentials (DuckDB)│
                                          │  └─ tpot2cti-vault (SFTP samples)│
                                          └──────────────────────────────────┘
```

Three pieces:
1. **OpenCTI** — deployed from upstream's official Docker repo, completely unmodified.
2. **tpot2cti** — our importer, attaches to OpenCTI's Docker network.
3. **An SSH tunnel** — autossh container that forwards T-Pot's ES through to our importer.

Optional add-ons (off by default):
- **`tpot2cti-credentials`** — stores full credential pairs in a local DuckDB for deeper offline analysis (top-100 summary is in the core; this is the full firehose for analysts who want it).
- **`tpot2cti-vault`** — SFTPs malware sample bytes from T-Pot into a content-addressable store, in case future enrichment connectors need the actual binaries.

---

## What's supported in v1.0

### Honeypot types parsed

Every honeypot type T-Pot 24.04 ships with — plus a **fallback parser**
that captures anything unrecognized so you never silently lose data.

The dedicated parsers cover: Cowrie (SSH/Telnet), Suricata, Dionaea,
Honeytrap, Heralding, ConPot (ICS/SCADA), H0neytr4p (HTTP), Dicompot
(DICOM medical), Medpot (HL7), Mailoney (SMTP), CiscoASA, ADBhoney,
ElasticPot, RedisHoneypot, IppHoney, Miniprint, Tanner, Wordpot,
SentryPeer (SIP/VoIP), Fatt (passive fingerprinting), NGINX, Honeyaml,
Router.

If T-Pot adds a new honeypot type, the fallback parser captures it
into OpenCTI as a `Sighting` + `Note` until someone contributes a
dedicated parser. Zero gaps.

### Out of scope for v1.0

To keep the project lean and the setup short, the following are
**explicitly NOT** in v1.0:

- ❌ Threat-intelligence enrichment (GeoIP, AbuseIPDB, VirusTotal, etc.)
- ❌ LLM-based analysis / playbook classification
- ❌ Sandbox classification (VirusTotal Sandbox, Hatching Triage, CrowdStrike, etc.)
- ❌ Multi-tenant support (use one deployment per T-Pot)
- ❌ Pre-built Docker images (build from source)
- ❌ Kubernetes (docker-compose only)
- ❌ Active responses against attackers (read-only)

Many of these will land as optional companion connectors after v1.0 —
see [Roadmap](#roadmap).

---

## Requirements

- **Hardware:** 4 cores, 16 GB RAM (32 GB recommended), 128 GB disk
- **OS:** Ubuntu 22.04 LTS or 24.04 LTS
- **Software:** Docker Engine 24+, Docker Compose plugin, git, ssh
- **Your T-Pot:** version 24.04 with SSH on port 64295 reachable from this box
- **Network:** outbound TCP to your T-Pot's SSH port

You provide and maintain your own T-Pot install. We don't help with
T-Pot setup — for that, see [the T-Pot project](https://github.com/telekom-security/tpotce).

---

## Quick start

```bash
# 1. Clone tpot2cti
git clone https://github.com/<owner>/tpot2cti.git
cd tpot2cti

# 2. Run the interactive setup
./setup.sh
```

`setup.sh` will:

1. Check prerequisites (Docker, RAM, disk)
2. Prompt for your T-Pot host, SSH user/port, operator org name
3. Ask which optional features to enable (credential analytics, malware vault)
4. Clone OpenCTI's official Docker repo into `./opencti/` (pinned version)
5. Generate all secrets (admin password, RabbitMQ creds, connector UUIDs)
6. Populate both `.env` files (ours + OpenCTI's, sharing the admin token)
7. Generate an SSH key for the T-Pot tunnel and pause for you to add it to T-Pot's `authorized_keys`
8. Test the tunnel
9. Start OpenCTI (this takes 3-5 minutes — OpenCTI's own startup)
10. Start tpot2cti (attaches to OpenCTI's Docker network)

When done, OpenCTI is at **http://localhost:8080** with the admin
password printed at the end of setup. First T-Pot ingestion cycle
starts within 15 minutes; you can watch progress with:

```bash
docker compose -p tpot2cti logs -f tpot2cti
```

### Updates

```bash
./update.sh             # Pull latest tpot2cti, rebuild our containers
./update.sh --opencti   # Also bump OpenCTI to the new pinned version
```

### Teardown

```bash
./teardown.sh           # Stop both stacks (keep data)
./teardown.sh --purge   # Stop and remove all data (with confirmation)
```

---

## What it looks like in OpenCTI

> *(Screenshot: OpenCTI "Observable" view of an attacker IP, showing
> Sightings across multiple sensors, related files, AttackPatterns,
> and the Note from a session. To be added.)*

A typical analyst workflow:

1. Navigate to **Observations → Observables → IPv4-Addr**
2. Sort by Sighting count to find your most-engaged attackers
3. Click an IP → see its Location, ASN, all Sightings, all related Files
4. Click a File → see which attackers dropped it, what URLs they used to fetch it, what AttackPatterns it's tied to
5. Click an AttackPattern → see every observable indicating that technique

---

## Configuration

Most users never touch this — `setup.sh` writes sensible defaults.
Advanced users can edit `.env` to tune:

| Variable | Default | What it does |
|---|---|---|
| `TPOT2CTI_INTERVAL` | `PT15M` | Cycle interval (ISO 8601 duration) |
| `TPOT2CTI_INITIAL_LOOKBACK_HOURS` | `0` | Backfill from N hours ago on first run; 0 = start fresh from now |
| `TPOT2CTI_DEFAULT_TLP` | `AMBER+STRICT` | TLP marking applied to all emitted entities |
| `OPERATOR_ORG_NAME` | `T-Pot Operator` | Your STIX Identity (appears as creator of all data) |
| `TPOT2CTI_IGNORE_TYPES` | (empty) | Comma-separated honeypot types to skip |

See [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) for the full list.

---

## Documentation

- [`docs/SETUP.md`](docs/SETUP.md) — Detailed install guide
- [`docs/SSH_TUNNEL.md`](docs/SSH_TUNNEL.md) — SSH tunnel configuration + troubleshooting
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — STIX object model + relationship diagram
- [`docs/PARSERS.md`](docs/PARSERS.md) — Per-honeypot parser reference
- [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) — Full env-var + YAML reference
- [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) — T-Pot + OpenCTI version matrix
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) — Common issues + fixes
- [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) — How to contribute
- [`V1_SPEC.md`](V1_SPEC.md) — The complete v1.0 specification

---

## Roadmap

The core importer is intentionally focused. Future companion
connectors (each its own optional Docker compose service) will layer
in additional capabilities **without modifying the core**:

| Companion | Purpose | Status |
|---|---|---|
| `tpot2cti-malwarebazaar` | Malware family attribution via local CSV mirror + TLSH fuzzy match | Planned |
| `tpot2cti-firehol` | IP reputation against 14 blocklists | Planned |
| `tpot2cti-otx` | AlienVault OTX pulse lookups | Planned |
| `tpot2cti-abuseipdb` | AbuseIPDB reputation scoring | Planned |
| `tpot2cti-misp` | Bidirectional MISP bridge | Planned |
| `tpot2cti-mitreattack` | Auto-import MITRE ATT&CK STIX feed | Planned |
| `tpot2cti-discord` | Daily summary webhook | Possible |

Each follows the same architectural pattern — attach to OpenCTI's
Docker network, read T-Pot ES through the same tunnel where applicable,
write to OpenCTI via pycti. Anyone can contribute one.

---

## Project status

**Beta** — actively developed against a single production T-Pot
deployment. Feature-complete for v1.0 specification but not yet
1.0-tagged.

### Compatibility

| tpot2cti | T-Pot | OpenCTI |
|---|---|---|
| v1.0.x | 24.04.x | 6.x.y (specific tag pinned in `setup.sh`) |

Every tpot2cti release tests against exactly one OpenCTI version. See
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) for what we test.

---

## Contributing

Contributions welcome. The most-needed work right now:

- **Test against your T-Pot deployment** — report what works and what doesn't
- **Add parsers** for any T-Pot honeypot type that needs better coverage
- **Document edge cases** you encounter in `docs/TROUBLESHOOTING.md`
- **Build a companion connector** from the roadmap or your own idea

See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) for the contribution
process, code style, and how to add a new parser.

---

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPLv3).

You can use tpot2cti for any purpose — commercial, non-commercial,
internal, hosted. The license requires that any modifications you
deploy are also published under AGPLv3, including SaaS deployments.
This keeps the project genuinely open and prevents anyone from
strip-mining the code into a closed-source product.

If you're considering modifying tpot2cti for your organization,
please consider contributing those changes back. The community wins
when we share.

---

## Acknowledgments

- **T-Pot** — [telekom-security/tpotce](https://github.com/telekom-security/tpotce) — The honeypot platform that captures the data this project ingests. Without T-Pot none of this exists.
- **OpenCTI** — [OpenCTI-Platform](https://github.com/OpenCTI-Platform) — The threat-intelligence platform that gives us a real entity-relationship graph and a sharing-ready data model.
- **The honeypot community** — for decades of thankless work catching attackers and sharing the data.

---

## Questions, issues, ideas

- 🐛 **Bug?** Open an issue with logs + reproduction steps
- 💡 **Feature idea?** Open a discussion before opening a PR — we want to keep the core lean
- 🤝 **Want to contribute?** See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md)
- 🔒 **Security issue?** See [`SECURITY.md`](SECURITY.md) for responsible disclosure

---

*tpot2cti is not affiliated with Telekom Security (the T-Pot
maintainers) or OpenCTI / Filigran (the OpenCTI maintainers). We use
both projects with great appreciation. All trademarks belong to their
respective owners.*
