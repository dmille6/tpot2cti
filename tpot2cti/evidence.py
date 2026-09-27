"""The evidence gate: may this session mint an attacker-IP Indicator?

DR-02 puts the promotion decision at the builder, where the parser that fed
a session is still known (docs/EVIDENCE.md section 1), behind one setting:

    TPOT2CTI_EVIDENCE_GATE = off | shadow | enforce     (default: off)

  * ``off``      the gate is not consulted. Output is byte-identical to the
                 builder before the gate existed.
  * ``shadow``   the gate is consulted and every decision is counted; a
                 refusal is written to one structured log line. Nothing
                 emitted changes.
  * ``enforce``  a refused session mints no IP Indicator, and no edge or
                 object_ref in the bundle points at an Indicator that was
                 withheld and never emitted.

This module is the SINGLE entry point: :func:`decide`. The builder calls it
before each of the five places an attacker-IP Indicator is minted (Cowrie,
Suricata, Honeytrap, fallback, drive-by). It returns accept/refuse plus a
reason, and knows nothing about STIX.

What the gate accepts is DR-01's decision (the evidence classes), not this
one's. DR-01's classes land one at a time:

  * SIP_FRAUD (owner decision 2026-09-27): a SentryPeer session is evidence
    only when it dials an international number (``is_intl_dial``, set by
    parsers/sentrypeer.py for "+", "00", "011", "9011" and "900" prefixes). Any other
    SentryPeer session (REGISTER, OPTIONS, an INVITE to a local number) is
    refused: in ``enforce`` it keeps its observable and Sighting but mints no
    Indicator.
  * Every other session: a STUB that accepts, which is exactly what the code
    emitted before the gate existed.

The class's score, confidence and lifetime (DR-01: 70/60/21 days) are NOT
applied here: scoring moves to the classes with the rest of DR-01 (the
evidence ledger), and until then an accepted session scores as it does today.

See docs/EVIDENCE_GATE.md for the flags, the counters in /health and the
rollout plan.
"""
from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

GATE_OFF = "off"
GATE_SHADOW = "shadow"
GATE_ENFORCE = "enforce"
GATE_MODES = (GATE_OFF, GATE_SHADOW, GATE_ENFORCE)

#: The five Indicator sites in stix/builder.py, one per dual-sighting call.
SITES = ("cowrie", "suricata", "honeytrap", "fallback", "driveby")

#: Reason the stub gives. Named for what it is, so a shadow log or a /health
#: counter can never be mistaken for a real evidence decision.
REASON_STUB_ACCEPT = "stub-accept-all"

#: SIP_FRAUD (DR-01): the parser type whose sessions this class decides, and
#: its two reasons (bounded tokens: they become /health counter keys).
SIP_EVENT_TYPE = "Sentrypeer"
REASON_SIP_FRAUD = "sip-fraud-intl-dial"
REASON_SIP_NO_EVIDENCE = "sip-no-intl-dial"


@dataclass(frozen=True)
class GateDecision:
    """What :func:`decide` returns. ``reason`` is a short, bounded token
    (it becomes a /health counter key), never free text."""
    accept: bool
    reason: str


def decide(session, *, site: str) -> GateDecision:
    """Decide whether ``session`` may mint its attacker-IP Indicator.

    ``site`` is one of :data:`SITES`, the builder method asking.

    SentryPeer sessions are decided by the SIP_FRAUD class
    (:func:`_decide_sip`). Everything else is still the DR-02 STUB: accepted.
    The builder only reaches a site for a session that already passed
    today's gates (``_is_bare_scan`` in main.py for the generic scan paths,
    the dispatch table for the rest), so accepting reproduces today's output.
    """
    if getattr(session, "event_type", None) == SIP_EVENT_TYPE:
        return _decide_sip(session)
    return GateDecision(accept=True, reason=REASON_STUB_ACCEPT)


def _decide_sip(session) -> GateDecision:
    """SIP_FRAUD: evidence when the session, or any event in it, dialled an
    international number. The parser correlates one event per session and
    mirrors the flag onto ``session.meta``; the events are checked too so a
    future multi-event correlator cannot silently drop the evidence."""
    if (getattr(session, "meta", None) or {}).get("is_intl_dial"):
        return GateDecision(accept=True, reason=REASON_SIP_FRAUD)
    for ev in getattr(session, "events", None) or ():
        if (getattr(ev, "meta", None) or {}).get("is_intl_dial"):
            return GateDecision(accept=True, reason=REASON_SIP_FRAUD)
    return GateDecision(accept=False, reason=REASON_SIP_NO_EVIDENCE)


@dataclass
class GateStats:
    """Per-bundle counters for the gate and for dual-sighting sites.

    One instance lives on each STIXBuilder (one per cycle). main.run_cycle
    persists :meth:`to_dict` to the state KV, from where /health reads it.
    """
    mode: str = GATE_OFF
    sightings_decoupled: bool = False
    sighting_grain: str = "legacy"
    #: reason -> count of sessions the gate accepted / refused. Empty in
    #: ``off``, because the gate is not consulted.
    accepted: Counter = field(default_factory=Counter)
    refused: Counter = field(default_factory=Counter)
    #: Refusals that actually withheld an Indicator (``enforce`` only).
    indicators_withheld: int = 0
    #: Dual-sighting site calls, by what they could emit.
    #:   with_indicator     both sighting sides were available
    #:   observable_only    no Indicator; the observable's sighting was
    #:                      emitted because sightings are decoupled
    #:   none               no Indicator and sightings are NOT decoupled,
    #:                      so the session left no sighting at all -- the
    #:                      loss DR-02 forbids before enforcement
    site_calls: Counter = field(default_factory=Counter)
    #: Observable-side Sighting OBJECTS in the bundle (after same-day
    #: folding), split by whether that (sensor, IP, day) also carries an
    #: Indicator-side Sighting in this bundle.
    observable_sightings_with_indicator: int = 0
    observable_sightings_without_indicator: int = 0
    #: References removed because they pointed at a withheld Indicator.
    relationships_dropped: int = 0
    object_refs_dropped: int = 0
    #: Refusals grouped for the log (not persisted, not in /health):
    #: (reason, site, src_ip, sensor, event_type) -> sessions, events,
    #: first_seen, last_seen. One log line per group per bundle, written by
    #: :func:`log_refusals` when the builder finalizes the bundle.
    refusal_groups: dict = field(default_factory=dict)

    def record(self, decision: GateDecision) -> None:
        (self.accepted if decision.accept else self.refused)[decision.reason] += 1

    def record_refusal(self, decision: GateDecision, session, *, site: str) -> None:
        key = (decision.reason, site, getattr(session, "src_ip", None),
               getattr(session, "sensor_hostname", None),
               getattr(session, "event_type", None))
        g = self.refusal_groups.setdefault(
            key, {"sessions": 0, "events": 0, "first_seen": None, "last_seen": None})
        g["sessions"] += 1
        g["events"] += int(getattr(session, "event_count", 0) or 0)
        for attr, pick in (("first_seen", min), ("last_seen", max)):
            v = getattr(session, attr, None)
            if v is not None:
                g[attr] = v if g[attr] is None else pick(g[attr], v)

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "sightings_decoupled": self.sightings_decoupled,
            "sighting_grain": self.sighting_grain,
            "accepted": dict(sorted(self.accepted.items())),
            "refused": dict(sorted(self.refused.items())),
            "accepted_total": sum(self.accepted.values()),
            "refused_total": sum(self.refused.values()),
            "indicators_withheld": self.indicators_withheld,
            "site_calls": {k: self.site_calls.get(k, 0)
                           for k in ("with_indicator", "observable_only", "none")},
            "observable_sightings": {
                "with_indicator": self.observable_sightings_with_indicator,
                "without_indicator": self.observable_sightings_without_indicator,
            },
            "relationships_dropped": self.relationships_dropped,
            "object_refs_dropped": self.object_refs_dropped,
        }


def log_refusals(mode: str, stats: GateStats) -> int:
    """One structured line per refusal GROUP of this bundle: (reason, site,
    src_ip, sensor, event_type), with how many sessions and events it
    covers. Accepts are only counted. Per-session lines were ~28k a day for
    SentryPeer REGISTERs alone (DR-01 M7); a group keeps everything the
    shadow analysis joins on (the address, sensor, reason) at a line per
    address per cycle. Clears the groups, so a second call logs nothing.

    The message is ``evidence_gate `` followed by a JSON object, so the
    JSON log formatter's ``message`` field can be parsed with
    ``jq -r '.message | select(startswith("evidence_gate ")) | .[14:] | fromjson'``.
    ``action`` is ``would-refuse`` in shadow and ``refused`` in enforce.
    Returns the number of lines written.
    """
    groups, stats.refusal_groups = stats.refusal_groups, {}
    for (reason, site, src_ip, sensor, event_type), g in sorted(
            groups.items(), key=lambda kv: tuple(str(x) for x in kv[0])):
        payload = {
            "action": "refused" if mode == GATE_ENFORCE else "would-refuse",
            "mode": mode,
            "reason": reason,
            "site": site,
            "src_ip": src_ip,
            "sensor": sensor,
            "event_type": event_type,
            "sessions": g["sessions"],
            "events": g["events"],
            "first_seen": g["first_seen"].isoformat() if g["first_seen"] is not None else None,
            "last_seen": g["last_seen"].isoformat() if g["last_seen"] is not None else None,
        }
        logger.info("evidence_gate %s", json.dumps(payload, sort_keys=True, default=str))
    return len(groups)


#: The flags whose combination defines one counting period.
_TOTALS_FLAGS = ("mode", "sightings_decoupled", "sighting_grain")


def merge_totals(totals: Optional[dict], cycle: dict, *, now_iso: str) -> dict:
    """Add one cycle's :meth:`GateStats.to_dict` into running totals.

    Totals exist so an hourly sampler (the DR-02 M3 measurement) sees every
    cycle, not one in four. Only the additive counters are summed.

    They RESTART, with ``since = now_iso``, when (mode, sightings_decoupled,
    sighting_grain) differ from the stored ones -- a shadow window must not
    carry the off-mode cycles before it -- and when there are none yet.
    main.run_cycle calls this only after a successful publish, so a failed
    cycle retried over the same window is counted once.
    """
    if not totals or any(totals.get(k) != cycle.get(k) for k in _TOTALS_FLAGS):
        totals = {"since": now_iso}
    t = dict(totals)
    t["cycles"] = int(t.get("cycles", 0)) + 1
    for key in ("accepted", "refused", "site_calls", "observable_sightings"):
        merged = dict(t.get(key) or {})
        for k, v in (cycle.get(key) or {}).items():
            merged[k] = int(merged.get(k, 0)) + int(v)
        t[key] = dict(sorted(merged.items()))
    for key in ("accepted_total", "refused_total", "indicators_withheld",
                "relationships_dropped", "object_refs_dropped"):
        t[key] = int(t.get(key, 0)) + int(cycle.get(key, 0))
    for key in _TOTALS_FLAGS:
        t[key] = cycle.get(key)
    return t
