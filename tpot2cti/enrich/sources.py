"""Bulk blocklist sources — declarative registry plus a fast CIDR matcher.

**Why one file instead of `sources/firehol.py`, `sources/spamhaus.py`, …** as
`docs/ENRICHMENT.md` §folder-layout originally sketched: each source differs
only in a URL, a parse mode, and a label. Splitting that into five modules
would produce five near-identical files — the duplication this project keeps
warning about — for no isolation benefit, since they share one fetch path and
one matcher. Adding a source here is one table entry.

Every source is **free and requires no signup**. That property is the point of
Lane A: a downloaded list matched locally costs zero per-object API calls, so
it scales to any number of observables. Verified reachable without
authentication on 2026-08-05.
"""
from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

class CidrSet:
    """Membership test for a set of IPv4 networks, bucketed by first octet.

    A linear scan is 14,700 attackers × 4,584 networks ≈ 67M comparisons per
    cycle. Bucketing by the leading octet cuts that by ~2 orders of magnitude
    while staying obvious enough to audit — networks shorter than /8 are added
    to every octet they span, so a `224.0.0.0/3` still matches correctly.
    """

    __slots__ = ("_buckets", "_count")

    def __init__(self, networks: Iterable[ipaddress.IPv4Network]) -> None:
        self._buckets: dict[int, list] = {}
        self._count = 0
        for net in networks:
            self._count += 1
            first, last = int(net.network_address), int(net.broadcast_address)
            for octet in range(first >> 24, (last >> 24) + 1):
                self._buckets.setdefault(octet, []).append(net)

    def __len__(self) -> int:
        return self._count

    def __contains__(self, ip) -> bool:
        if getattr(ip, "version", None) != 4:
            return False
        for net in self._buckets.get(int(ip) >> 24, ()):
            if ip in net:
                return True
        return False


# ---------------------------------------------------------------------------
# Parsers — each returns (cidr_set, extra) where extra carries per-source data
# ---------------------------------------------------------------------------

def _parse_netset(text: str) -> tuple[CidrSet, dict]:
    """FireHOL `.netset` / Spamhaus DROP / plain IP lists.

    Comment markers differ between these feeds (`#` for FireHOL, `;` for
    Spamhaus) and DROP appends `; SBL……` after the CIDR, so take the first
    whitespace token of any line that is not a comment.
    """
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        try:
            net = ipaddress.ip_network(line.split()[0], strict=False)
        except ValueError:
            continue
        if net.version == 4:
            nets.append(net)
    return CidrSet(nets), {}


def _parse_feodo(text: str) -> tuple[CidrSet, dict]:
    """Feodo Tracker C2 JSON.

    **Only `status: "online"` entries are matched.** Feodo retains long-dead
    infrastructure — measured 2026-08-05: 5 entries total, 4 of them offline,
    the oldest last seen in March. Publishing a decommissioned host as an
    active botnet C2 is precisely the kind of unqualified claim that got the
    predecessor's abuse.ch key banned, and it would be attached to a *Malware*
    SDO, which is the highest-confidence assertion this module can make.
    """
    try:
        entries = json.loads(text)
    except (ValueError, TypeError):
        raise SourceParseError("feodo: response was not valid JSON")
    if not isinstance(entries, list):
        raise SourceParseError(f"feodo: expected a JSON list, got {type(entries).__name__}")
    # A renamed `status` or `ip_address` field yields zero online C2s and would
    # pass silently, because this feed legitimately can be near-empty and so
    # carries no min_entries floor. Check the SHAPE instead of the count.
    if entries and not any(isinstance(e, dict) and "ip_address" in e for e in entries):
        raise SourceParseError(
            "feodo: no entry has an 'ip_address' field — the feed schema has "
            "changed. Refusing to report zero C2s as a clean result."
        )
    nets, families = [], {}
    for e in entries:
        if not isinstance(e, dict) or str(e.get("status", "")).lower() != "online":
            continue
        try:
            addr = ipaddress.ip_address(str(e.get("ip_address", "")).strip())
        except ValueError:
            continue
        if addr.version != 4:
            continue
        nets.append(ipaddress.ip_network(addr))
        fam = (e.get("malware") or "").strip()
        if fam:
            families[str(addr)] = fam
    return CidrSet(nets), {"families": families}


class SourceParseError(RuntimeError):
    """A source downloaded but could not be parsed.

    Distinct from an empty list: "parsed fine, matched nothing" and "the feed
    changed shape under us" must not look the same, or a silently-broken parser
    reads as a quiet internet.
    """


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Source:
    key: str
    url: str
    label: str
    parse: Callable[[str], tuple[CidrSet, dict]]
    #: What a hit asserts, in one line. Not written to the graph — observables
    #: carry labels only — but logged at startup so an operator can see what
    #: each enabled source is claiming on their behalf, and reused verbatim in
    #: docs/enrich/blocklists.md.
    meaning: str
    #: Sanity floor. A feed that suddenly parses to fewer entries than this has
    #: almost certainly changed shape or started serving an error page, and
    #: must not be allowed to silently un-label the world.
    min_entries: int = 1
    promotes_malware: bool = False


SOURCES: tuple[Source, ...] = (
    Source(
        key="firehol",
        url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        label="blocklist:firehol-level1",
        parse=_parse_netset,
        meaning="listed on FireHOL level 1 (aggregated high-confidence blocklists)",
        min_entries=1000,
    ),
    Source(
        key="spamhaus",
        url="https://www.spamhaus.org/drop/drop.txt",
        label="blocklist:spamhaus-drop",
        parse=_parse_netset,
        meaning="inside a Spamhaus DROP netblock (hijacked or wholly malicious allocation)",
        min_entries=500,
    ),
    Source(
        key="tor",
        url="https://check.torproject.org/torbulkexitlist",
        label="tor:exit-node",
        parse=_parse_netset,
        meaning="a published Tor exit node",
        min_entries=200,
    ),
    Source(
        key="feodo",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        label="blocklist:feodo-c2",
        parse=_parse_feodo,
        meaning="an ONLINE botnet C2 on abuse.ch Feodo Tracker",
        # Feodo is nearly empty (1 online entry on 2026-08-05) and legitimately
        # can be zero, so it gets no floor — its risk is the opposite one,
        # handled by only matching status=online.
        min_entries=0,
        promotes_malware=True,
    ),
)

SOURCES_BY_KEY = {s.key: s for s in SOURCES}


def selected_sources(spec: str) -> list[Source]:
    """Resolve a comma-separated source list, rejecting unknown names loudly.

    A typo in `ENRICH_BLOCKLIST_SOURCES` must not silently disable a feed —
    that is a configuration-shaped silent zero-work bug.
    """
    keys = [k.strip().lower() for k in (spec or "").split(",") if k.strip()]
    unknown = [k for k in keys if k not in SOURCES_BY_KEY]
    if unknown:
        raise ValueError(
            f"unknown blocklist source(s): {', '.join(unknown)}. "
            f"Known: {', '.join(sorted(SOURCES_BY_KEY))}"
        )
    return [SOURCES_BY_KEY[k] for k in keys]
