# Heralding parser — multi-protocol credential capture honeypot.

Heralding listens on a handful of authentication-bearing TCP services
(SSH, Telnet, FTP, POP3, IMAP, SMTP, HTTP-Basic, etc.) and records
every `(username, password)` pair an attacker submits.  Unlike Cowrie
it offers no shell — its sole purpose is harvesting credential-spray
attempts — so the substance signal is dominated by `credentials_tried`
plus the sheer event count of repeated probes on the same session.

Per V1_SPEC.md §5.5:

  T-Pot doc fields used:
    src_ip, dst_port, protocol,
    username, password,
    session_id

  Event correlation:
    Heralding stamps every credential-attempt event with a session_id;
    we group events sharing `(session_id, sensor, src_ip)` via the
    shared `correlate_by_session_id` helper.  This collapses bursty
    multi-attempt probes from the same attacker into a single
    AttackSession whose `credentials_tried` field captures every pair.

  Substance filter (per docs/LESSONS_LEARNED_FROM_V0.md §2):
    A Heralding session is substantive iff
      - it captured at least one credential pair, OR
      - event_count > 2 (more than just open + close — repeated
        protocol-layer probing without a credential is still worth
        the full SDO graph).
    Pure single-touch sessions with no credentials are drive-by noise
    and get the one-Sighting drive-by treatment.

Per V1_SPEC.md §6 (credentials handling):
    Heralding credential pairs are NEVER emitted as User-Account SCOs
    (that would flood OpenCTI with one SCO per attempted password).
    They go into `AttackSession.credentials_tried` as `(username,
    password)` tuples; the Phase 6 daily Note aggregator consumes that
    list to produce one summary Note per attacker per day.
