# Wordpot parser — fake WordPress honeypot.

Wordpot emulates a WordPress site and captures the HTTP requests
attackers and bots throw at it.  The internet is saturated with
generic web crawlers and vulnerability scanners; the substantive
traffic on a WordPress honeypot is the subset that targets WordPress-
specific surfaces — `/wp-admin`, `/wp-login.php`, `/xmlrpc.php`,
`/wp-config*`, `/wp-content/plugins/*` — i.e. login brute-force,
xmlrpc abuse, config-file disclosure attempts, and plugin enumeration
/ known-CVE plugin probing.

Per V1_SPEC.md §5.18:

  T-Pot doc fields used:
    src_ip, request_path, user_agent

  Event correlation:
    one ES doc → one ParsedEvent → one AttackSession (default
    one-event-per-session correlator).  Wordpot has no native
    multi-request session concept in the T-Pot index — each request
    is its own document.

  STIX emitted:
    - IPv4-Addr
    - URL
    - Sighting
    - AttackPattern("wordpress-recon") if hits /wp-admin, /wp-login.php, etc.

  Substance filter (per LESSONS_LEARNED_FROM_V0.md §2):
    A session is substantive iff request_path matches one of the
    well-known WordPress attack surfaces:
      /wp-admin..., /wp-login.php, /xmlrpc.php, /wp-config*,
      /wp-content/plugins/*
    Anything else (`GET /`, generic 404 spelunking, robots.txt, etc.)
    is drive-by noise.
