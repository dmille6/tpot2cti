# Beelzebub parser — LLM-driven SSH/HTTP/TCP honeypot.

Beelzebub is the LLM-powered honeypot ships with T-Pot's `ai` profile.
We run it on port 22 with a hybrid pre-canned command set + LLM
fallback (configured against an Ollama instance running qwen2.5-coder:7b).

Per V1_SPEC.md §5 (parser interface), the parser converts T-Pot ES
docs into normalized `ParsedEvent`s + correlates per session.

Beelzebub emits TWO event flavors per session:
  1. "New SSH attempt"           — auth-time event with username + password
  2. "New SSH Inline Session"    — interactive command execution with
                                    `input` (attacker keystrokes) and
                                    `output` (what we returned).

Logstash adds `type: "Beelzebub"` and `@timestamp` (from the engine's
own `timestamp` ISO string).  Fields the importer relies on:

  Required:  src_ip, @timestamp (logstash) or timestamp (raw)
  Common:    src_port, dest_port (dotted-string in raw log), session,
             username, password, input, output, protocol, status,
             service, client (SSH client version string)

Substance filter:
  - any command execution (input non-empty)              → substantive
  - any credential pair captured                         → substantive
  - more than 2 events in the same session               → substantive
  - bare connect with no auth/command — Beelzebub almost never emits
    these; the "New SSH attempt" event always carries username and
    password (often the empty string), so any successful parse is
    effectively a credential-attempt and routes substantive.
