# Mailoney parser — fake SMTP / spam-relay probe honeypot.

Mailoney emulates an open SMTP relay on port 25 (and friends).  Most
of what it catches is internet-background scanners checking whether
the host will relay spam — EHLO/HELO followed by an immediate QUIT.
The substantive subset is attackers who actually try to push a
message body through (`DATA` with non-empty content) or who probe
authentication with `AUTH LOGIN` / `AUTH PLAIN` credential pairs.

Per V1_SPEC.md §5.10:

  T-Pot doc fields used:
    src_ip, commands (SMTP verbs), data (message body),
    auth_user, auth_pass,
    session_id  (when Mailoney provides one)

  Event correlation:
    Mailoney's behavior re session_id varies by version — some emit a
    per-connection `session_id`, others don't.  We try
    `correlate_by_session_id` first and fall back to
    `correlate_by_window(window=300s)` when no events in the batch
    carry a session_id.  The window mirrors the V0 importer's
    `max_gap_seconds=300` default.

  Substance filter (per docs/LESSONS_LEARNED_FROM_V0.md §2):
    A Mailoney session is substantive iff
      - it issued SMTP commands beyond the no-op set {EHLO, HELO, QUIT}
        (so MAIL FROM, RCPT TO, DATA, VRFY, AUTH, ... count), OR
      - at least one credential pair was captured, OR
      - non-zero DATA-body bytes were observed.
    Pure EHLO/QUIT relay-probes are drive-by noise and get the
    one-Sighting drive-by path.

Per V1_SPEC.md §6 (credentials handling):
    `auth_user` / `auth_pass` pairs are NEVER emitted as User-Account
    SCOs.  They flow into `AttackSession.credentials_tried`; the
    Phase 6 daily Note aggregator consumes that list.
