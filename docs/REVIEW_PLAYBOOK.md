# Review playbook

Standing input for every review round, human or model. Hand this file to the
reviewer along with the diff.

**What this is.** A record of defects that actually occurred in this repo and
the review questions that caught them. Not general advice — every entry below
has a date, a file, and a number.

**What this is not.** A claim that anyone "learns" from it. Model weights do
not change. This file works only because it is loaded into context and read.
If it stops earning its keep (see §4), delete it rather than maintain it.

---

## 1. The recurring defect class

> **The pipeline asserts what it has not established.**

Every output defect found in the week of 2026-08-05 is an instance. The
countermeasures that have actually worked, in order of strength:

1. **Make the wrong call unwriteable**, not merely avoidable. A required
   keyword argument that raises `TypeError` beats a helper someone must
   remember to call. The predecessor reimplemented ensure-or-create 21+ times;
   each bug fix landed in one copy.
2. **Put the gate at the one choke point every path funnels through.**
   `Publisher.publish()` covers five producers including three that never
   touch `tpot2cti/stix/builder.py`. `sensor_hostname` appears 59 times in
   `tpot2cti/stix/builder.py` — patching each was the wrong instinct.
3. **Count and surface every refusal.** A silent drop is indistinguishable
   from an extractor that found nothing. `rejected_urls`,
   `rejected_own_surface_urls`, `type_recoveries`, redaction counts by reason
   all exist for this reason.

---

## 2. Reviewer questions, ranked by what they actually found

Ask these in this order. The top three found the most on 2026-08-05/06.

### Q1. "Do the modified tests still test anything?"
Changing what a test targets while keeping its assertion produces a test that
passes for the wrong reason.

- **Hit:** `test_same_ip_twice_is_not_two_members` keyed on a JA3 that the same
  commit stopped collecting, so `emit_campaigns` returned `[]` trivially.
  Same-IP de-duping went untested and the test still passed.
- **Hit:** `test_genuine_shell_commands_are_untouched` hand-built a session,
  appended to `.commands`, then asserted `.commands` was non-empty. No parser
  ran. It could not fail.
- **Technique that proved it:** mutation testing — copy the new tests onto
  `main` and confirm they FAIL there; or delete the guard the test claims to
  cover and confirm it catches that.
- **Fix pattern:** pair every "must not" assertion with a positive control, so
  an empty result cannot mean "nothing was stored".

### Q2. "What did this NOT fix that the commit message implies it did?"
- **Hit:** ConPot and Mailoney were fixed, and the evidence contract was
  described as done. `build_url`/`build_domain`/`build_process` still had no
  required `evidence=`. Instances fixed, class open.
- **Hit:** `fix/no-campaigns-from-fingerprints` removed 217 bad campaigns'
  generator but left `ssh-key` at `MIN_CAMPAIGN_MEMBERS=2`, so the single
  worst campaign (`mdrfckr`, 489 IPs) survived.

### Q3. "Is the measurement measuring the thing, or a proxy?"
- **Hit:** "zero pipeline-authored ATT&CK mappings" counted `uses` edges.
  `uses` is MITRE's intrusion-set layer and was never the pipeline's to write.
  The pipeline maps via `indicator --indicates--> attack-pattern`, which was
  working. Wrong relationship type, false conclusion.
- **Hit:** a 400-doc sample of `related-to` edges taken in index order gave
  "98% Note→IP". The true distribution was Process 45%, Url 32.5%, Note 17.5%.

### Q4. "Does the config the code reads actually exist in the deployment?"
- **Hit:** `tpot2cti/redact.py` fell back to `OPENCTI_TOKEN`. That name appears in no
  `.env`, no `setup.sh`, no compose file — the deployment writes
  `OPENCTI_ADMIN_TOKEN`. The live fleet silently used the public constant in
  the repo, so every sensor pseudonym was reproducible by anyone. The warning
  even told operators to set the non-existent variable.
- **Check:** grep the deployed `.env` for every variable the new code reads.

### Q5. "Is a document being trusted over the code?"
- **Hit twice, same document.** `docs/EVIDENCE.md` §3.4 under-scoped its own
  blast radius by two orders of magnitude, then named the wrong dominant
  producer of own-surface URLs (blamed Suricata SNI; it was
  `tpot2cti/parsers/h0neytr4p.py:387` → `_build_web_session`).
- **Rule:** a call-site map in a doc is stale the moment it is written. Verify
  against `grep` before acting on one.

### Q6. "What breaks downstream when this stops being emitted?"
- **Near-miss:** a blanket host guard on `build_url` would have silently
  deleted the log4shell salvage graph, which anchors its Sighting/Note/CVE
  objects on the URL id. That is the dangling-anchor defect from
  `fix/output-syntactic-validation`, reintroduced from the other direction.
- **Ask for `file:line`,** not a general answer.

### Q7. "Would an operator SEE this failing?"
- **Hit:** redaction rewrote published text with no log line. A configured net
  that ate half the attacker IPs would look identical to one that matched
  nothing.
- **Hit:** `setup.sh` (repo root) spun 88,404 times on EOF because `read`'s failure was
  ignored and fell through to a `"y"` default.

---

## 3. Operating notes for multi-model review

- **codex's sandbox has no SSH or outbound network.** It can trace code but
  cannot query live data, and it reports "No module named pytest" unless given
  a venv path. To have both models judge the SAME evidence, extract data to a
  local file first and reference it in the prompt.
- **`codex exec` hangs on stdin** unless redirected: `codex exec "$P" < /dev/null`,
  and `2>/dev/null` to suppress a ~1.2 MB model-catalog error blob.
- **Claude subagents build their own venv and do run the suite.** Never treat a
  codex MERGE verdict as test-backed.
- **Put the measured numbers in the prompt.** Reviews that were handed live
  figures disputed the diagnosis; reviews without them only reviewed the plan.
- **Ask explicitly for disagreement.** "Do not just agree with us" changed the
  output materially on 2026-08-06 — it produced the wrong-producer catch.

---

## 4. Does this file earn its keep?

Track, per review round, how many findings came from **review** versus were
**self-caught before review**.

| date | round | review-found | self-caught |
|---|---|---|---|
| 2026-08-05 | 3 branches, 6 reviews | 1 blocker + ~12 should-fix | 2 (dangling ref, tftp scheme) |
| 2026-08-05 | mailoney | 4 (incl. false bare-scan premise) | 1 (stale docstring) |
| 2026-08-06 | redaction ×4 rounds | 4 (containment, visibility, mapped-v6, secret var) | 0 |
| 2026-08-06 | own-surface URLs | 2 (wrong producer, JNDI trap) | 1 (bare-path count) |

Roughly **12:1 against self-catching**. If that ratio does not move over the
next several rounds, this playbook is not working — say so and stop
maintaining it. A file nobody measures is the same defect class it documents.
