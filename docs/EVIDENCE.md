# The evidence contract

> **Status: DESIGN — not yet implemented.**
> Nothing described here exists in code. This is the contract to build
> against. See [`CHANGELOG.md`](../CHANGELOG.md) for what actually ships.

---

## 1. The bug class

Every output defect found in the week of 2026-08-05 is one bug, wearing four
costumes:

> **The pipeline asserts what it has not established.**

| defect | the unestablished assertion |
|---|---|
| ConPot request blobs in `session.commands` | "the attacker RAN this" — they sent it |
| TLS SNI → `Domain-Name` | "this name is attacker infrastructure" — it is *our* name, the one they used to reach us |
| bare request paths → `Url` | "this is a locatable resource" — it names no host |
| `non-200 → not_found` | "the dataset has no record" — we were refused |
| `dst_ip or src_ip` fallback on `resolves-to` | "this name resolves to that address" — fabricated DNS |

None of these is a parsing bug. In every case the parse was correct and the
*claim built on top of it* was not. That is why fixing them one at a time has
not worked: each fix removes one false claim and leaves the mechanism that
produced it. Two independent analyses of the corpus, run 2026-08-05 and held
out of this repo, reached the same conclusion from different directions.

The discriminating question is never *"is this value benign?"* — the same
string can be either. `raw.githubusercontent.com` appears in this corpus as a
genuine dropper host **and** as a benign fetch. A list gets one of them wrong
whichever way it is written. The question is:

> **Did the attacker ADDRESS us by this, or REACH OUT to it?**

That fact is known exactly once: at the moment the builder is called, from
*which parser field fed the call*. It is destroyed immediately afterward. By
the time `Publisher.publish()` sees `{"type":"domain-name","value":"x.com"}`
there is nothing left to tell an SNI from a `wget`. **Information the builder
discards cannot be recovered downstream.** That is the whole argument for
putting the contract at the builder boundary.

---

## 2. Why a free-text `evidence=` field fails

This was the strongest objection raised against the idea, and it is correct:

> If "evidence" is just a string field, developers will fill it with
> "observed in session" and move on.

A contract that accepts prose is a contract that records intentions, not
facts. It also risks the opposite failure — dropping useful low-grade
telemetry because the model has no vocabulary for it.

So the type must be **closed and restrictive**: a fixed enum, each member
declaring exactly which STIX assertions it licenses. Not a description of
where the value came from — a statement of what may therefore be claimed.

---

## 3. The contract

### 3.1 Evidence types

Closed set. A value's type is a property of the **code path**, determined
statically from which parser field fed it — never a runtime guess.

| type | what it is | what it licenses |
|---|---|---|
| `SHELL_COMMAND` | a URL/domain inside a genuine command transcript (Cowrie, Beelzebub, Redis, adbhoney) | **full IoC.** URL + Domain observables, Indicator, substance score, Process SDO |
| `DOWNLOAD_URL_PAIR` | a URL paired with a hash the sensor actually captured | **full IoC** + `url --related-to--> file` |
| `JNDI_PAYLOAD` | a Log4Shell payload recovered by `log4shell.py` | URL **verbatim as evidence** (host may be an unresolved template); the extracted C2 zone is the Domain IoC |
| `TLS_SNI_TO_SENSOR` | the name the client used to reach **us** | **nothing about the name.** Sighting on the attacker IP only |
| `INBOUND_HOST_HEADER` | an HTTP `Host:` header targeting us | as above |
| `CONNECT_AUTHORITY` | a `host:port` request-target — an open-proxy test | `AttackPattern` T1090 Proxy. **No observable for the target** |
| `PROTOCOL_REQUEST` | raw bytes the sensor received (ConPot, Mailoney SMTP verbs) | **Note only.** Never a Process, never command score, never T1059, never URL harvesting |
| `HONEYPOT_RESPONSE` | content **our own** honeypot emitted (Galah LLM responses, template bodies) | **nothing publishable.** It is our text, not theirs |
| `REVERSE_DNS` | a PTR name a third party (InternetDB) reports for an address | **`NOTE` + label only.** Never an observable, never `resolves-to` — see §6 |

The five named in the brief are the load-bearing ones.
`DOWNLOAD_URL_PAIR`, `INBOUND_HOST_HEADER` and `JNDI_PAYLOAD` are additions
required for *closure*: §3.4 maps every existing call site, and a closed set
that does not cover them would force a wrong type at those sites, which is
worse than a list. Each is justified by a specific line, not by symmetry.

### 3.2 Permissible assertions

The declaration is data, not scattered conditionals:

```python
class Assertion(enum.Enum):
    OBSERVABLE      = "observable"       # mint an SCO for this value
    INDICATOR       = "indicator"        # claim it is malicious
    SUBSTANCE_SCORE = "substance-score"  # let it raise _signal_score
    PROCESS         = "process"          # claim something was executed
    TECHNIQUE       = "technique"        # map to ATT&CK
    NOTE            = "note"             # render as evidence prose
    RESOLVES_TO     = "resolves-to"      # assert a DNS fact

_PERMITS: dict[Evidence, frozenset[Assertion]] = {
    Evidence.SHELL_COMMAND:      frozenset({OBSERVABLE, INDICATOR, SUBSTANCE_SCORE,
                                            PROCESS, TECHNIQUE, NOTE}),
    Evidence.DOWNLOAD_URL_PAIR:  frozenset({OBSERVABLE, INDICATOR, SUBSTANCE_SCORE, NOTE}),
    Evidence.JNDI_PAYLOAD:       frozenset({OBSERVABLE, INDICATOR, TECHNIQUE, NOTE}),
    Evidence.TLS_SNI_TO_SENSOR:  frozenset({NOTE}),
    Evidence.INBOUND_HOST_HEADER: frozenset({NOTE}),
    Evidence.CONNECT_AUTHORITY:  frozenset({TECHNIQUE, NOTE}),
    Evidence.PROTOCOL_REQUEST:   frozenset({NOTE}),
    Evidence.HONEYPOT_RESPONSE:  frozenset(),
    Evidence.REVERSE_DNS:        frozenset({NOTE}),
}
```

Read the table as the security property: **`PROCESS` appears exactly once.**
Only a real command transcript can ever claim execution. The ConPot bug
becomes unwriteable rather than fixed.

Note `RESOLVES_TO` is licensed by **no** type in the initial set. That is
deliberate — see §6.

### 3.3 Enforcement — three devices, and not a fourth

**Device 1 — a required keyword, so the wrong call cannot be written.**

```python
def build_domain(self, fqdn, *, evidence: Evidence, session=None): ...
def build_url(self, url, *, evidence: Evidence, session=None): ...
def build_process(self, session, commands, *, evidence: Evidence): ...
```

No default. A new call site that omits it is a `TypeError` at import/test
time, not a silent omission. A reviewer reading a diff sees
`evidence=TLS_SNI_TO_SENSOR` and can challenge it on the spot.

> **Explicitly NOT a `_should_emit()` helper for each builder method to
> call.** That is the 21-copies shape verbatim — the predecessor
> reimplemented ensure-or-create 21+ times, each bug fix landing in one copy.
> Every defect in `silent-zero-work-failure-patterns.md` is "someone added
> module N+1 and did not re-apply the lesson." **Change the signature so the
> wrong call does not compile; do not make the right call available.**

**Device 2 — an import-time completeness assertion.** The pattern already
exists in this codebase at `publisher.py:107-118`, which raises
`AssertionError` at import if the pass-partitioning sets drift from
`KNOWN_STIX_TYPES`. Reuse it: assert that every `Evidence` member appears in
`_PERMITS`. Adding a type without deciding what it licenses is a crash, not a
hole.

**Device 3 — the builder checks the licence, in one place.** Each `build_*`
declares the `Assertion` it makes and consults `_PERMITS` once. A refusal
increments a per-reason counter surfaced in the cycle summary — the mechanism
merged in `fix/output-syntactic-validation`, reused. A silent `return None` is
this codebase's own defect signature.

### 3.4 Every current call site (merged `main`, 2026-08-05)

Closure check. If a site cannot be typed, the set is wrong.

| site | fed by | type | changes today's behaviour? |
|---|---|---|---|
| `builder.py:2122` | `session.domains` from command URLs | `SHELL_COMMAND` | no |
| `builder.py:2248` | `meta["tls_sni"]`, `meta["http_host"]` | `TLS_SNI_TO_SENSOR` / `INBOUND_HOST_HEADER` | **yes — stops minting our own names as IoCs** |
| `builder.py:2824` | `payload["host"]` (log4shell) | `JNDI_PAYLOAD` | no |
| `builder.py:3028` | `session.domains` from download URLs | `DOWNLOAD_URL_PAIR` | no |
| `builder.py:3167` | `_CMD_URL_RE` over `session.commands` | `SHELL_COMMAND` | no — correct only because ConPot no longer poisons `commands` |
| `builder.py:2079/2989/3133` | `build_process(session.commands)` | `SHELL_COMMAND` | no |

The only behavioural change at contract-introduction is line 2248 — which is
the defect. Everything else is annotation. **That is the point:** the contract
is cheap to adopt precisely because most call sites are already honest.

Mailoney is the outstanding one. It appends received SMTP verbs to
`session.commands` (measured live: score 75, T1059, a Process SDO reading
`EHLO\nMAIL\nRCPT\nDATA`). Under the contract it becomes `PROTOCOL_REQUEST`,
which licenses `NOTE` only. Same fix as ConPot, same mechanism, no new code.

---

## 4. Anti-vacuity

A contract nobody can violate may also be a contract that does nothing. Three
checks, all of which must fail loudly if the pipeline stops working entirely:

1. **Every emitted `domain-name` and `url` carries an `evidence:<type>`
   label.** A CI invariant over the fixture corpus asserts it. This is the
   device that stops the other assertions passing vacuously.
2. **Assert the denominator.** Pair every zero-assertion with a positive:
   `assert n_domains_total > 0` before `assert n_inbound_named == 0`. A
   corpus that emits nothing satisfies every "must not emit" test.
3. **Refusal counts in the cycle summary**, per evidence type. A rejection
   rate moving from 3% to 60% must be visible without reading DEBUG logs.

---

## 5. What this deliberately does NOT do

1. **No benign-domain allowlist** — not Tranco, not Umbrella, not enumerated.
   It deletes the best intel (`pages.dev`, `githubusercontent.com`,
   `gsocket.io`) and does not touch the defect. The same string is an IoC in
   one flow and noise in another; only provenance separates them.
2. **No popularity lists for benign filtering**, same argument.
3. **No `_should_emit()` per builder method** — §3.3, Device 1.
4. **No scoring change to express suppression.** The publisher's cross-cycle
   merge keeps `max(score)`, so a score can only ratchet up.
   [`ENRICHMENT.md`](ENRICHMENT.md) §7 is right; suppression is labels and
   non-emission, never a lower number.
5. **No `enrich/lookup.py`.** Out of scope here.
6. **No remediation of already-published objects.** Separate, destructive,
   and it should follow verification rather than precede it.

---

## 6. Reverse DNS — suppress with it, never assert with it

**Decided 2026-08-05: label-only. `ENRICHMENT.md` §7 amended to match.**

This project uses reverse DNS in two unrelated ways, and the contract treats
them differently because their *failure directions* are opposite.

**Use 1 — suppression. Shipped, correct, unaffected.**
[`tpot2cti/rdns.py`](../tpot2cti/rdns.py) does forward-confirmed rDNS to
identify rented scanner infrastructure. Shadowserver, BinaryEdge and
Stretchoid rent cloud ASNs, so ASN/org matching cannot see them — 2,731
addresses on the live fleet, 17 of which were being labelled
`targeted:substantive`. A wrong answer here means we publish **less**. Safe
failure. (This is what
the 2026-08-05 rDNS review covers — it does *not* address use 2.)

**Use 2 — assertion. Specified in ENRICHMENT §7, never built, now refused.**
Promoting InternetDB `hostnames[]` to a `Domain-Name` SCO with a
`resolves-to` edge asserts a DNS fact this pipeline never observed, in a graph
where a Domain-Name carries the implicit predicate *"this name is part of the
reported activity's infrastructure."* A wrong answer here publishes a **false
claim about a third party**. Unsafe failure. Three concrete objections:

1. It is the `dst_ip or src_ip` shape again — a fabricated DNS record, which
   is exactly how Canonical acquired a scored observable.
2. Attacker-IP rDNS is mostly mass-hosting boilerplate (`ec2-*.amazonaws.com`,
   ISP DSL pool names). Publishing those as attacker infrastructure invites a
   consumer to block a cloud provider's PTR range.
3. **PTR records for a netblock are set by whoever owns the netblock** — for
   attacker-owned ranges, the attacker. Unconditional promotion lets an
   attacker choose which name we publish as their infrastructure, including
   someone else's. Forward-confirmation blocks the impersonation half; the
   name is still attacker-chosen.

So `REVERSE_DNS` licenses `NOTE` only. The name stays queryable as a label and
readable as evidence; it never becomes an IoC. This is reversible in the
direction that matters — a label can be promoted later, whereas a published
SCO must be deleted by hand.

`ENRICHMENT.md` §7's other rules — never emit floating edgeless SDOs,
suppression as labels never scores, first-party observation outranks
third-party reputation — are all *reinforced* by this contract, not
contradicted. The last of those is the same principle stated for enrichment
rather than for emission.

---

## 7. Implementation order

Each step is independently shippable and independently verifiable.

1. **`Evidence` + `Assertion` + `_PERMITS` + the import-time assertion.** No
   call sites touched. Pure addition; cannot regress anything.
2. **Thread `evidence=` through `build_domain` / `build_url`.** All five
   domain sites and eight URL sites, annotation only — except `2248`, which
   is the fix. Verify against the live corpus the way the merged branches
   were: predict the delta before deploying, then confirm it.
3. **Delete the `target_ip = event.dst_ip or session.src_ip` fallback**
   (`build_suricata_alert`). It asserts the SNI resolves to the attacker's own
   address. This is the one line that fabricates DNS records about third
   parties and it should go with step 2.
4. **`build_process`.** One `Assertion`, one type licensing it. Fixes Mailoney
   as a side effect of adopting the contract, with no Mailoney-specific code.
5. **CI invariants** (§4), including both positive controls.
6. **Then, and only then**, revisit ENRICHMENT §7 with §6's decision made.

Steps 1–4 are pure emission changes with no dependency on cleanup, so the
corpus stops growing while the rest is decided.

---

## Appendix — the measurement this rests on

Live corpus, 2026-08-05, pre-deploy:

```
72   Domain-Name observables      — 4 parse artifacts, ~19 inbound-named
14238 Url observables             — 2467 bare request paths (17%)
3660 Process observables          — 499 ConPot-attributed, 353 whose
                                    command_line is an HTTP request
```

The four flow shapes that produced them. Sensor-side addresses and operator
persona names are redacted — they are exactly the values §3.1's
`TLS_SNI_TO_SENSOR` and `HONEYPOT_RESPONSE` types exist to keep out of
published output, and this file is in a public repo:

```
<persona-fqdn>      src=<attacker> → dst=<sensor-A>:443   sni='<persona-fqdn>'
azenv.net           src=<attacker> → dst=<sensor-A>:8443  http.url='http://azenv.net/'
pay.xzxwl.cn        src=<attacker> → dst=<sensor-B>:80    http.url='pay.xzxwl.cn:443'
security.ubuntu.com src=<canonical>:80 → dst=<sensor-C>:<ephemeral>  url='/ubuntu/dists/…'
```

Line 1 is an inbound TLS SNI naming one of our own honeypot personas — the
name the client used to reach *us*, published as though it were attacker
infrastructure. Lines 2 and 3 are proxy targets; line 3's `host:port`
request-target form is an HTTP CONNECT authority, i.e. a scanner testing
whether we are an open relay. Line 4 has `src_port=80` and an ephemeral
destination port on our own address — it is the *server* side of our own
`apt` fetch, which is how Canonical's address acquired a scored IPv4-Addr
observable whose description called it an attacker engaging a sensor.

Four shapes, four evidence types, one bug.
