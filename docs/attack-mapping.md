# Behaviour-driven ATT&CK technique mapping

`tpot2cti/attack_mapping.py`

Only two parsers (Suricata via rule metadata, Tanner/web via `attack_type`)
used to emit ATT&CK techniques. But every parser normalises the *same*
substance signals onto `AttackSession`, so we map those uniform signals to
techniques — all 32 honeypots now light up the matrix, each mapping backed by
observed evidence.

## Grouping basis — behaviour only

No signal → no technique. A bare connect with no activity gets nothing (keeps
the ATT&CK view honest — it reflects what attackers *did*, not what protocol
they touched).

| Observed behaviour (`AttackSession`) | Technique |
|---|---|
| `credentials_tried` | T1110 Brute Force (+ T1110.001 Password Guessing if >1) |
| `auth_success` | T1078 Valid Accounts |
| `commands` | T1059 Command & Scripting (+ T1059.004 Unix Shell for shell honeypots) |
| `malware_hashes` / `downloads` | T1105 Ingress Tool Transfer |
| `planted_ssh_keys` | T1098 + T1098.004 SSH Authorized Keys |
| `dst_ports` ≥ 3 | T1595 Active Scanning (+ T1595.001 Scanning IP Blocks) |

`T1059.004` (Unix Shell) is gated to genuine unix-shell honeypots
(`_UNIX_SHELL_TYPES`: Cowrie, Adbhoney, Beelzebub, Router); Redis/SMTP/ConPot
commands get only the generic T1059 parent.

## ATT&CK Navigator merge

`STIXBuilder.build_attack_pattern` sets **`x_mitre_id`** on every technique
pattern. `x_mitre_id` is OpenCTI's merge key for attack-patterns, so our
honeypot-observed pattern resolves **into the canonical ATT&CK technique node**
created by the bundled MITRE connector. Effect:

- the native ATT&CK **Navigator / matrix** reflects real honeypot activity, and
- each technique node lists the attacker IP indicators that exhibited it
  (`indicator --indicates--> attack-pattern`).

## Pipeline wiring

`main.run_cycle` calls `builder.build_session_attack_patterns(session)` for
**every** session, right after the per-session build — uniform across all
parsers. It emits one AttackPattern per technique + an `indicates` edge from
the attacker's IP indicator. Overlaps with a builder's own patterns (e.g. web
T1190, Suricata rule techniques) collapse via deterministic ids.

`attack-pattern` is in the publisher's **foundation** pass, so techniques are
created before the `indicates` edges that reference them.

## Extending

- Add a technique: extend `TECHNIQUES` (id → canonical name) in
  `attack_mapping.py` and the signal logic in `techniques_for_session`.
- `TECHNIQUES` is the single source of truth — the Suricata builder's
  rule-id → name lookup aliases it.
