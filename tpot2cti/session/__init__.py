"""tpot2cti — session correlation helpers.

Session correlation logic lives WITH the parser (per `BaseParser.correlate()`)
because what counts as "the same session" is protocol-specific.  This
package provides reusable helpers parsers can compose:

  - `correlate_by_session_id` — group events sharing a `session_id` from
    the same `(src_ip, sensor)` pair.  Used by Cowrie, Heralding, Mailoney.

  - `one_event_per_session` — the default; one ParsedEvent → one
    AttackSession.  Used by Suricata, ConPot, single-shot probe protocols.

  - `correlate_by_window` — group events from the same `(src_ip, dst_port,
    sensor)` within a time window.  Useful for FATT, Honeytrap when you
    want to dedupe a burst of TCP probes.

Parsers compose these in their `correlate()` override.  See
`docs/LESSONS_LEARNED_FROM_V0.md` §6 for the substance-filter pattern
that runs against the resulting AttackSession.
"""

from .correlator import (
    correlate_by_session_id,
    correlate_by_window,
    one_event_per_session,
)

__all__ = [
    "correlate_by_session_id",
    "correlate_by_window",
    "one_event_per_session",
]
