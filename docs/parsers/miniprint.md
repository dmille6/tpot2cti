# Miniprint parser — line-printer / IPP / PJL honeypot (port 9100).

Miniprint emulates a small networked printer's raw-print interface
(typically port 9100, the JetDirect/RAW protocol).  Most internet
"printer probes" that hit port 9100 are SHODAN-style banner grabs and
opportunistic scans that send nothing meaningful — but every now and
again an attacker tries to push an actual PJL command, a PostScript
program, or a malformed print job.  The substance filter separates
the two.

Per V1_SPEC.md §5.16:

  T-Pot doc fields used:
    src_ip, request_path, request_body

  STIX emitted (later, by the orchestrator):
    IPv4-Addr,
    Sighting,
    (Note with request_path + request_body when substantive)

  Event correlation: each connection to the fake printer is one event.
  We inherit the default one-event-per-session correlator.

Substance filter (per docs/LESSONS_LEARNED_FROM_V0.md §2):

  A Miniprint session is substantive iff any of:

    - request_body has length > 0   (the attacker actually sent bytes)
    - request_path contains print-job control markers:
        * starts with ``@PJL`` (HP Printer Job Language commands)
        * contains ``/printer/`` (IPP-style paths)
        * contains ``%!PS``     (PostScript magic)

  Bare port-9100 SYN-and-close probes get no body and no path of
  interest, so they fall through to the drive-by code path.

Per-session promotions to the AttackSession:

  - ``session.meta``  ← request_path, request_body (truncated),
                        body_length, body_truncated
