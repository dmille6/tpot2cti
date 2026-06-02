# Fallback parser — handles any T-Pot honeypot type without a dedicated parser.

Per the V0 parser-vs-builder separation rule, this parser stays pure (model-only):
parse() + has_substance() only.  The per-protocol STIX shape lives in
``STIXBuilder.build_fallback_event``.

Per V1_SPEC.md §5.24 (Fallback parser):

    For any `type` value not covered above. Ensures **zero data gaps**.

    T-Pot doc fields used:
      src_ip (if present), dst_port (if present), t-pot_hostname (sensor),
      @timestamp, type (recorded in the Note)

    STIX emitted (by the builder):
      IPv4-Addr (if src_ip present), Sighting (with description), and
      a Note ONLY when src_ip is missing (so the event isn't silently
      lost — per LESSONS §7.1 we no longer emit per-event Notes
      when an IP is available).

    The fallback parser also emits a `WARNING` log line on every
    unrecognized type so operators see "T-Pot has a new honeypot type
    `<type>` — consider opening an issue for a dedicated parser."

Design notes:

* The registry's ``get_parser()`` falls back to this parser whenever a
  doc's ``type`` field has no dedicated handler, by looking up the
  sentinel key ``FALLBACK_KEY`` (``"__fallback__"``).  This parser's
  ``type_name`` is set to that sentinel.

* ``has_substance()`` is always ``True``.  Even an empty Note giving
  operators visibility into "we saw a doc of unknown type" is more
  useful than silently dropping the event.

* The WARNING log is rate-limited via a module-level set so an
  unrecognized type only logs once per process, not once per event.

* ``src_ip`` is optional here.  When missing we still emit (via the
  builder) a Note so the unknown event is visible in OpenCTI even
  without an attacker observable to attach to.
