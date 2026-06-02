# Dionaea parser — binary-catching honeypot (SMB / FTP / HTTP / MS-SQL / MySQL).

Dionaea's whole reason for existing is to *catch the binary*: it accepts a
file drop over one of its emulated services and writes the bytes to disk
under a sha256-derived path.  T-Pot emits one ES document per
connection — and for connections that actually drop a payload the doc
carries the hashes (sha256 / md5 / sha1), the size, and (when the
attacker fetched the binary from somewhere) the download_url.

Per V1_SPEC.md §5.3:

  T-Pot doc fields used:
    src_ip, dst_port, protocol,
    sha256, md5, sha1, size_bytes,
    download_url (if applicable),
    connection_protocol (smbd, ftpd, etc.)

  STIX emitted (later, by the orchestrator):
    IPv4-Addr, StixFile (with all available hashes),
    URL (if download_url present), Indicator(file), Sighting.

  Relationships: same as Cowrie file paths.

  Event correlation: each binary drop / connection is its own event.
  We inherit BaseParser.correlate() (one-event-per-session) — there's
  no Dionaea-wide session id to group on, and each captured connection
  is independently interesting.

Substance filter (per docs/LESSONS_LEARNED_FROM_V0.md §2):

  Dionaea is loud — port-scanners and SMB worms slam port 445 all day
  and most of those connections drop NO bytes at all.  The single signal
  that separates noise from substance is whether we actually *captured a
  binary* (or at least learned of a URL to fetch one from).  We treat a
  session as substantive iff any of:

    - sha256 is present
    - md5 is present
    - sha1 is present
    - download_url is present

  Everything else is a drive-by handshake and gets the minimal Sighting.

The hashes we extract are pushed to ``session.malware_hashes`` as
lowercase hex strings; the download_url goes to ``session.urls``; the
download_url's hostname goes to ``session.domains`` (when it parses as
a hostname rather than a bare IPv4 literal).
