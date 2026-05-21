# Contributing to tpot2cti

Thanks for considering contributing. tpot2cti is a small project with
a focused mission — turn T-Pot honeypot data into a high-quality STIX
2.1 graph in OpenCTI — and contributions that strengthen that mission
are very welcome.

This document covers:

- What kinds of contributions are most useful
- How to set up a development environment
- The code style we follow
- How to add a new T-Pot parser (the most common contribution)
- How to build a new companion connector
- The pull-request and review process
- License implications of contributing

---

## TL;DR

| What you want to do | Where to read |
|---|---|
| Fix a bug or improve docs | [Bug fixes and small changes](#bug-fixes-and-small-changes) |
| Add a parser for a T-Pot honeypot type | [Adding a parser](#adding-a-parser) |
| Build an entirely new companion connector | [Adding a companion connector](#adding-a-companion-connector) |
| Improve the setup script or developer tooling | [Improving setup or tooling](#improving-setup-or-tooling) |
| Just report an issue you found | [Filing issues](#filing-issues) |

---

## Code of conduct (the short version)

Be kind, assume good faith, focus on the work, and don't be a jerk.
We'd rather have fewer contributions in a respectful environment than
more in a hostile one. Maintainers reserve the right to close
discussions, lock issues, or remove comments that don't move the
project forward.

If you experience or witness behavior that violates this spirit,
contact a maintainer privately.

---

## What contributions we want most

Ranked by usefulness to the project at this stage:

1. **Testing against your real T-Pot deployment.** Tell us what worked,
   what broke, what was confusing. Issues with logs and reproduction
   steps are gold.

2. **New T-Pot parsers** or improvements to existing parsers. T-Pot
   ships many honeypot types and the v1.0 parsers vary in completeness.
   See [Adding a parser](#adding-a-parser).

3. **Documentation improvements.** If you got stuck somewhere, that's
   a documentation bug — please open an issue or PR.

4. **Bug reports with reproduction steps** and minimal log excerpts.

5. **Companion connectors** that fit the project's pattern (see
   [Adding a companion connector](#adding-a-companion-connector)).

6. **CI/automation improvements** — tests, lint configuration, GitHub
   Actions tuning.

### What we're more cautious about

These contributions may take longer to land or may not be accepted:

- **Major architectural changes** to the core importer. The architecture
  is documented in [`V1_SPEC.md`](V1_SPEC.md) and changes should be
  discussed in an issue first.
- **New required dependencies** in the core importer. Every dep adds
  installation friction. Optional connectors can carry their own deps.
- **Features that belong in OpenCTI itself.** If it's about how OpenCTI
  displays data, manages users, or processes STIX bundles, that's
  upstream's territory. We send our STIX and let OpenCTI do its thing.
- **Persona-aware features.** The core stays generic. If you want
  persona-specific behavior, build it as a companion connector or as
  a custom OpenCTI playbook.

---

## Bug fixes and small changes

For anything small — fixing a typo, a clear bug, a documentation
issue — feel free to open a PR directly. Include:

- A clear PR description of what changed and why
- Reference to any related issue (`fixes #123`)
- Tests if you're changing behavior

For anything larger, please open an issue first to discuss the
approach before writing code. Saves both of our time.

---

## Filing issues

Good issue reports include:

- **What you expected to happen** vs. what actually happened
- **Steps to reproduce** (the more specific the better)
- **Environment**: Ubuntu version, Docker version, T-Pot version,
  tpot2cti version, OpenCTI version
- **Relevant log excerpts** from `docker compose -p tpot2cti logs tpot2cti`
- **What you've already tried**

We don't have formal issue templates yet (this is a young project),
but the above structure will get your issue triaged faster.

For security issues, please **don't open a public issue**. See
[`SECURITY.md`](SECURITY.md) for responsible disclosure.

---

## Development setup

### Prerequisites for development

- Same as runtime: Docker Engine 24+, compose plugin, git
- Python 3.11+ on your host (for running tests outside containers)
- A test T-Pot deployment (or a captured set of T-Pot ES docs to test against)

### Setting up your dev environment

```bash
# Fork tpot2cti on GitHub, then:
git clone https://github.com/YOUR-USERNAME/tpot2cti.git
cd tpot2cti
git remote add upstream https://github.com/<owner>/tpot2cti.git

# Install Python dev dependencies (for running tests outside containers)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

### Running the test suite

```bash
# Lint + format check
make lint

# Unit tests (per-parser, no Docker needed)
make test

# Full integration test (spins up a mock ES, exercises one cycle)
make integration

# Everything
make ci
```

Tests live under `tests/`. Per-parser test fixtures live under
`tests/fixtures/<honeypot>/`. Adding a parser means adding fixtures
AND assertions about what STIX SDOs that parser should produce.

### Running tpot2cti locally against a real T-Pot

```bash
./setup.sh           # configures a full local stack with your real T-Pot
# Make edits in tpot2cti/src/...
docker compose -p tpot2cti up -d --build tpot2cti  # rebuild + restart just the importer
docker compose -p tpot2cti logs -f tpot2cti        # watch it work
```

---

## Adding a parser

This is the most common contribution. T-Pot has 20+ honeypot types
and each one produces a different ES document shape. A parser converts
one shape into normalized STIX.

### Decide whether you need a new parser

First check `tpot2cti/src/parsers/__init__.py` for the existing
dispatch table. If the honeypot's `type` field is already routed to a
parser, you may just need to **improve** an existing parser rather
than write a new one.

If the type isn't routed at all, T-Pot's documents are currently
hitting the [fallback parser](#the-fallback-parser) — which captures
basic info (src_ip, sensor, Sighting, Note with raw doc body) but
doesn't extract honeypot-specific fields. Time to write a dedicated
parser.

### Steps to add a parser

1. **Find or create a representative T-Pot ES document** for the
   honeypot you're targeting. Save it to:

   ```
   tests/fixtures/<honeypot_name>/example.json
   ```

   You can grab one from your own T-Pot:

   ```bash
   curl -s "http://your-tpot:64298/logstash-*/_search?size=1&q=type:Mailoney" \
     | jq '.hits.hits[0]._source' > tests/fixtures/mailoney/example.json
   ```

   Sanitize any IPs / hostnames before committing.

2. **Create the parser module** at
   `tpot2cti/src/parsers/<honeypot_name>.py`:

   ```python
   from .base import BaseParser, ParsedEvent

   class MailoneyParser(BaseParser):
       type_name = "Mailoney"

       def parse(self, doc: dict) -> ParsedEvent | None:
           # Extract fields from doc
           # Return a ParsedEvent with the STIX objects to emit
           ...
   ```

3. **Register it** in `tpot2cti/src/parsers/__init__.py`:

   ```python
   from .mailoney import MailoneyParser
   PARSERS["Mailoney"] = MailoneyParser
   ```

4. **Spec what STIX objects this parser should emit** in
   `docs/PARSERS.md`. Keep the format consistent with existing entries:
   - List the T-Pot doc fields used
   - List the STIX SDOs emitted
   - List the relationships created
   - Note any special behavior (substance filter, etc.)

5. **Write tests** at `tests/test_<honeypot_name>.py`:

   ```python
   import json
   from tpot2cti.src.parsers.mailoney import MailoneyParser

   def test_parses_mailoney_event():
       with open("tests/fixtures/mailoney/example.json") as f:
           doc = json.load(f)

       event = MailoneyParser().parse(doc)

       assert event is not None
       assert event.src_ip == "expected.ip.from.fixture"
       assert any(sdo["type"] == "ipv4-addr" for sdo in event.stix_objects)
       # ...assert each expected SDO type and relationship
   ```

6. **Run the tests** and iterate until passing:

   ```bash
   make test
   ```

7. **Open a PR** with:
   - The parser code
   - The fixture
   - The tests
   - The docs update
   - A brief PR description explaining what T-Pot honeypot type you're
     adding support for, with a link to that honeypot's upstream repo if
     it's a separately-maintained project.

### Parser conventions

- **Be conservative about session correlation.** If the honeypot doesn't
  provide a stable session ID, treat each event as its own thing rather
  than guessing at correlation.
- **Use the substance filter for low-value events.** Empty payloads,
  single-byte probes, dropped connections without data — these are
  often noise. Emit a Sighting only; don't bother with the full SDO
  graph.
- **Never emit STIX you can't validate.** If a STIX field requires a
  specific format (e.g. a CIDR for `ipv4-addr` ranges), validate before
  emitting. Failed validation drops the SDO with a WARNING log.
- **Defensive parsing.** Real-world T-Pot docs sometimes have missing
  or malformed fields. Catch exceptions per-doc, log at DEBUG, return
  `None`, and let the cycle continue.

### The fallback parser

`tpot2cti/src/parsers/fallback.py` catches any T-Pot `type` value not
routed to a dedicated parser. It emits:

- An `IPv4-Addr` for `src_ip` if present
- A `Sighting`
- A `Note` containing the raw doc body

This guarantees zero data gaps. When you add a new dedicated parser,
the fallback parser stops being invoked for that type.

The fallback also logs a WARNING per unrecognized type ("T-Pot has a
new honeypot type `<X>` — consider opening an issue for a dedicated
parser"). This is how we discover what's worth prioritizing next.

---

## Adding a companion connector

The core `tpot2cti` connector is intentionally minimal — T-Pot ES to
OpenCTI STIX, nothing else. Other features (threat-intel enrichment,
sandbox classification, alerting, exports) belong in **companion
connectors** that follow the same pattern.

### Architectural pattern

A companion connector:

1. Lives in its own directory: `tpot2cti-<feature>/`
2. Has its own Dockerfile, entrypoint, and source tree
3. Adds a service entry to the main `docker-compose.yml` under a
   compose profile (so users opt in via `--profile <feature>`)
4. Either reads from T-Pot ES (via the shared SSH tunnel) or reads
   from OpenCTI (or both, or neither — it depends on the feature)
5. Writes to either OpenCTI (via pycti) or to its own local store

### Examples of good companion connectors

These would fit the pattern well:

- **`tpot2cti-malwarebazaar`** — Reads File observables from OpenCTI,
  looks them up in a locally-mirrored MalwareBazaar CSV (with optional
  TLSH fuzzy match), writes back `mb:family:*` labels + a Note per
  classification.

- **`tpot2cti-otx`** — Reads IPv4 observables from OpenCTI, queries
  AlienVault OTX, writes back labels + Notes describing what pulses
  the IP appears in.

- **`tpot2cti-firehol`** — Periodically downloads FireHOL blocklists,
  matches against new IPv4 observables, writes back `firehol:listed`
  labels.

- **`tpot2cti-misp`** — Bidirectional bridge to a MISP instance — emit
  STIX to MISP, pull MISP events back into OpenCTI as Reports.

- **`tpot2cti-discord`** — Posts daily summary webhooks of top attackers
  + top malware families to a Discord channel.

### What does NOT fit the companion pattern

- Anything that modifies OpenCTI's UI (use OpenCTI's playbook engine instead)
- Anything that requires changes to the core importer (open an issue and we'll discuss)
- Anything that requires paid services without a clear free alternative
- Anything that includes its own LLM dependency (these are heavy and slow uptake; revisit post-v1.0)

### Steps to build one

1. **Propose the connector** in an issue first. Even if it's small,
   the discussion catches naming conflicts, design issues, and overlap
   with planned work early.

2. **Scaffold the directory**:

   ```
   tpot2cti-myfeature/
   ├── Dockerfile
   ├── entrypoint.py
   ├── requirements.txt
   └── src/
       ├── main.py
       └── ...
   ```

3. **Add a service to `docker-compose.yml`**:

   ```yaml
   services:
     tpot2cti-myfeature:
       build: ./tpot2cti-myfeature
       container_name: tpot2cti-myfeature
       restart: unless-stopped
       profiles: ["myfeature"]
       networks: [opencti_net]
       environment:
         OPENCTI_URL: http://opencti:8080
         OPENCTI_TOKEN: ${OPENCTI_ADMIN_TOKEN}
         # ... feature-specific env vars
       volumes:
         - ./data/myfeature:/var/lib/tpot2cti-myfeature
   ```

4. **Document it**:
   - Add to the optional-features section of `README.md`
   - Create `docs/CONNECTOR_MYFEATURE.md` with full details (modeled on the existing per-connector handoff docs)
   - Add the user-facing toggle question to `setup.sh`

5. **Test it** end-to-end against a real OpenCTI install.

6. **Open the PR.**

---

## Improving setup or tooling

Setup script, build tools, CI configuration, and developer documentation
are all fair game for improvements. A few specific notes:

- **`setup.sh`** is bash for now. Keep it POSIX-ish where possible.
- **CI** uses GitHub Actions. Keep workflows minimal and fast — most
  developers iterate locally with `make test`.
- **Pre-commit hooks** are optional but encouraged. A `.pre-commit-config.yaml`
  is provided.

---

## Code style

### Python

We follow standard PEP 8 with a few project-specific conventions:

- Format with **`ruff format`** (configured in `pyproject.toml`)
- Lint with **`ruff check`**
- Line length: **100 characters** (slightly more generous than PEP 8's 79)
- Type hints on all public functions and dataclass fields
- Docstrings on all public modules, classes, and functions
- No `from foo import *` ever

### Shell

- Bash (not POSIX sh) — we use bashisms freely
- `set -euo pipefail` at the top of every script
- Indent with 2 spaces (consistent with the docker community)
- Quote variable expansions: `"${VAR}"` not `$VAR`

### Markdown

- 80-column wrap for prose where practical (not enforced)
- Use `[reference-style links][1]` for repeated URLs to keep prose clean
- Inline code with `backticks` for short snippets, fenced blocks with
  language tag (` ```python ` etc.) for longer code

---

## Pull request process

1. **Open an issue first** for anything non-trivial (new parser, new
   feature, architectural change). This catches design issues early.
2. **Fork and branch.** Branch names: `feat/<short-desc>`, `fix/<short-desc>`,
   `docs/<short-desc>`, `parser/<honeypot>`.
3. **Make focused commits.** A PR with 50 unrelated commits will be
   asked to rebase into something reviewable.
4. **Run `make ci` locally** before pushing.
5. **Write a PR description** that explains the change and any
   non-obvious decisions. Reference the issue (`fixes #123`).
6. **Be responsive to review.** Maintainers may suggest changes; aim
   to address them within a week or so.
7. **Squash on merge** is the default for small PRs; large feature PRs
   may keep their commit history. Maintainer's call.

---

## License implications of contributing

This project is licensed under **AGPLv3**. By submitting a contribution,
you agree that your contribution will be licensed under the same terms.

Practical implications:

- **You retain copyright** on your contribution.
- Your contribution will be redistributed under AGPLv3, which means
  anyone using a modified version (including as a SaaS) must publish
  their modifications.
- If your employer claims rights to your code, please get their
  written approval before contributing.
- We don't require a CLA (Contributor License Agreement). The AGPLv3
  license terms are the contribution agreement.

---

## Recognition

Contributors are recognized in:

- The commit history (which is durable and queryable)
- The `CHANGELOG.md` entry for the release that includes their change
- (For substantial contributions) The `CONTRIBUTORS.md` file at the
  root of the repo

We don't do "level" hierarchies, contributor badges, or other
gamification. The work speaks for itself.

---

## Maintainer responsibilities

For transparency, here's what maintainers do:

- **Triage issues** within a reasonable time (target: 1 week for
  acknowledgment, longer for resolution depending on complexity)
- **Review PRs** with constructive feedback
- **Pin OpenCTI / T-Pot versions** when bumping is appropriate
- **Run the test suite** against the canonical T-Pot fleet before
  cutting releases
- **Tag releases** following semantic versioning (`MAJOR.MINOR.PATCH`)
- **Maintain `CHANGELOG.md`**
- **Respond to security reports** privately and promptly

If you'd like to become a maintainer, the path is:
1. Make several substantive contributions
2. Demonstrate good judgment in code review (yes, contributors can
   review other contributors' PRs)
3. Be willing to commit to the maintenance work above
4. Get nominated by an existing maintainer

---

## Questions?

- **General contribution questions**: open a Discussion on GitHub
- **About a specific issue / PR**: comment on that issue / PR
- **About maintainer-level concerns**: contact a maintainer privately

Thanks again for being here. The project is better for every
contribution.
