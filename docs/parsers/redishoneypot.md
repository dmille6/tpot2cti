# Redishoneypot parser — fake Redis honeypot.

Redishoneypot listens on port 6379 and speaks the Redis RESP protocol
back at clients.  Internet-wide Redis scanners constantly fire `INFO`,
`PING`, and `COMMAND` at every reachable Redis instance to fingerprint
it; that is pure background-radiation reconnaissance and we treat it
as a drive-by.  Substantive sessions are the ones where the client
starts issuing dangerous administrative commands — `CONFIG SET dir`
(write-where), `SLAVEOF` / `REPLICAOF` (replication abuse for RCE),
`EVAL` (Lua sandbox abuse), `MODULE LOAD` (arbitrary module load) and
similar — i.e. the classic Redis-to-RCE attack chains.

Per V1_SPEC.md §5.12:

  T-Pot doc fields used:
    src_ip, commands_received

  Event correlation:
    one ES doc → one ParsedEvent → one AttackSession (default
    one-event-per-session correlator).  T-Pot's Redishoneypot index
    already records the per-connection command list in a single doc,
    so there is nothing to group across docs.

  STIX emitted:
    - IPv4-Addr
    - Sighting
    - Note with attempted commands (e.g. CONFIG SET dir, SLAVEOF, etc.)

  Substance filter (per LESSONS_LEARNED_FROM_V0.md §2):
    A session is substantive iff `commands_received` is non-empty AND
    contains at least one command outside the recon-only set
    {INFO, PING, COMMAND}.  Plain INFO / PING fingerprinting is drive-by;
    anything else — CONFIG, SLAVEOF, EVAL, MODULE LOAD, SET, AUTH probe,
    KEYS *, FLUSHALL, etc. — is substance.
