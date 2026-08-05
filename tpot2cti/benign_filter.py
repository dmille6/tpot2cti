"""tpot2cti — benign-scanner allowlist filter.

Drops events from known internet-wide research scanners (Google,
Censys, Shodan, Shadowserver, Internet Archive, etc.) at parse time.
No Indicator, no observable, no Sighting — these aren't attackers and
we don't want to pollute the threat intel with claims that they are.

The allowlist is loaded from `tpot2cti/data/benign_scanners.yaml` (or
a path passed explicitly). Matching is OR-of:
    - integer ASN match (`event.src_asn in vendor.asns`)
    - case-insensitive substring match on the org name
      (any keyword from `vendor.org_keywords` is in `event.src_as_org`)

Per the user decision documented in the first-live-install postmortem:
"we can't blanket report google as malicious that's silly".

This is NOT an enrichment connector — it's a static config file
shipped in the repo. A future enrichment connector (FireHOL allowlist
sync, see the PoC's `tsec_fhol_*.py`) can layer dynamic allowlists on
top, but v1 keeps it simple and local.
"""

from __future__ import annotations

import logging
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

import yaml

from tpot2cti.parsers.base import ParsedEvent
from tpot2cti.rdns import suffix_matches

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScannerRule:
    """One entry from benign_scanners.yaml."""
    vendor: str                       # e.g. "google", "censys"
    asns: frozenset[int]              # ASNs that identify this scanner
    org_keywords: tuple[str, ...]     # lowercase keyword substrings
    #: Forward-confirmed reverse-DNS suffixes. Needed because scanners rent
    #: infrastructure: Shadowserver appears as Hurricane Electric, BinaryEdge
    #: as DigitalOcean, Stretchoid as Microsoft — so ASN and org can never
    #: match them. See tpot2cti/rdns.py for why the confirmation is mandatory.
    rdns_suffixes: tuple[str, ...] = ()


@dataclass
class FilterStats:
    """Per-cycle counters surfaced in the cycle summary log."""
    total_filtered: int = 0
    by_vendor: Counter[str] = field(default_factory=Counter)

    #: A bounded sample of what was dropped, so a deletion is inspectable
    #: after the fact. Dropping happens BEFORE OpenCTI and before
    #: attacker_activity, so without this the only evidence an address was
    #: removed is a per-vendor count — the same argument this codebase already
    #: makes for query_excluded.
    samples: list = field(default_factory=list)
    MAX_SAMPLES: int = 25

    def record_sample(self, ip: str, name: str, vendor: str) -> None:
        if len(self.samples) < self.MAX_SAMPLES:
            self.samples.append({"ip": ip, "name": name, "vendor": vendor})

    def record(self, vendor: str) -> None:
        """Increment the total-filtered counter and per-vendor breakdown.

        Called once per event the filter drops; the caller passes the
        matched vendor slug (``"censys"``, ``"shadowserver"``, etc.).
        """
        self.total_filtered += 1
        self.by_vendor[vendor] += 1

    def to_log_dict(self) -> dict:
        """Render counters in the shape the cycle summary log expects.

        Returns ``{"total": int, "by_vendor": {vendor: count}}``. The
        per-vendor map is a plain dict (not Counter) for JSON-friendly
        emission via the structured-log formatter.
        """
        return {
            "total": self.total_filtered,
            "by_vendor": dict(self.by_vendor),
            "samples": list(self.samples),
        }


# ---------------------------------------------------------------------------
# Default yaml path resolution
# ---------------------------------------------------------------------------

DEFAULT_YAML_PATH = Path(__file__).parent / "data" / "benign_scanners.yaml"

#: Env var to point at an alternate yaml (useful for ops who want their
#: own allowlist without forking the repo).
ENV_YAML_PATH = "TPOT2CTI_BENIGN_SCANNERS_YAML"

#: New rDNS resolutions allowed per cycle. Each costs up to two blocking DNS
#: operations (PTR, then forward confirmation), so this bounds the worst-case
#: ingest stall: 500 x 2 x 1.0s timeout = ~17 min absolute worst case, against
#: a typical ~1,100 new addresses/day and a measured peak of 3,118. Cache hits
#: are free and never spend budget, so in steady state almost nothing does.
DEFAULT_RDNS_BUDGET = int(os.environ.get("TPOT2CTI_BENIGN_RDNS_BUDGET", "2000"))

#: The REAL bound: cumulative wall-clock seconds of DNS per cycle. Per-lookup
#: timeouts are not honoured by the system resolver (a 1 ms setting still
#: allowed a 58 ms lookup; 87 of 600 live addresses exceeded 1 s, max 11.5 s),
#: so a count budget alone bounds nothing. 60 s is ~1% of a 2 h cycle, and
#: overshoot is at most one in-flight lookup.
DEFAULT_RDNS_TIME_BUDGET = float(
    os.environ.get("TPOT2CTI_BENIGN_RDNS_TIME_BUDGET", "60"))


# ---------------------------------------------------------------------------
# Filter
# ---------------------------------------------------------------------------

class BenignScannerFilter:
    """Stateless allowlist matcher; safe to call from the cycle loop."""

    def __init__(self, rules: list[ScannerRule], resolver=None):
        self._rules = rules
        # Reverse-DNS path. Optional: with no resolver the filter behaves
        # exactly as before, matching on ASN/org only.
        self._resolver = resolver
        self._rdns_rules = [r for r in rules if r.rdns_suffixes]
        #: Remaining NEW resolutions allowed this cycle. Each miss costs up to
        #: two blocking DNS operations (PTR, then forward confirmation), so an
        #: unbounded filter facing a burst of new addresses — the measured peak
        #: is 3,118/day — could stall ingest for tens of minutes. Cached
        #: addresses are free and never consume budget.
        # Non-zero default so a filter nobody called begin_cycle() on still
        # works. Defaulting to 0 would make a forgotten call a silent no-op —
        # the filter would quietly stop catching scanners with nothing to show
        # for it, which is the failure shape this codebase keeps hitting.
        # Exhaustion is never silent either: rdns_skipped_budget is reported.
        self._rdns_budget = DEFAULT_RDNS_BUDGET
        self._rdns_time_budget = DEFAULT_RDNS_TIME_BUDGET
        self._rdns_elapsed = 0.0
        self.rdns_skipped_budget = 0
        # Precompute an ASN → vendor lookup for the fast path.
        self._asn_to_vendor: dict[int, str] = {}
        for r in rules:
            for asn in r.asns:
                # Last write wins on conflict; log so the operator notices.
                if asn in self._asn_to_vendor and self._asn_to_vendor[asn] != r.vendor:
                    logger.warning(
                        f"benign-scanner: ASN {asn} listed under both "
                        f"{self._asn_to_vendor[asn]!r} and {r.vendor!r}; "
                        f"using {r.vendor!r}"
                    )
                self._asn_to_vendor[asn] = r.vendor

    def begin_cycle(self, budget: int,
                    time_budget: float = DEFAULT_RDNS_TIME_BUDGET) -> None:
        """Reset the per-cycle rDNS budgets and the skip counter."""
        self._rdns_budget = max(0, int(budget))
        self._rdns_time_budget = max(0.0, float(time_budget))
        self._rdns_elapsed = 0.0
        self.rdns_skipped_budget = 0
        if self._resolver is not None and hasattr(self._resolver, "reset_stats"):
            self._resolver.reset_stats()

    @classmethod
    def from_yaml(cls, path: Optional[Path | str] = None,
                  resolver=None) -> "BenignScannerFilter":
        """Load rules from yaml. Returns an empty filter if file missing."""
        # Resolution order: explicit arg > env var > shipped default.
        if path is None:
            env_override = os.environ.get(ENV_YAML_PATH)
            if env_override:
                path = Path(env_override)
            else:
                path = DEFAULT_YAML_PATH
        else:
            path = Path(path)

        if not path.exists():
            logger.warning(
                f"benign_scanners.yaml not found at {path}; filter disabled "
                f"(every event treated as potentially-malicious)"
            )
            return cls([], resolver=resolver)

        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(
                f"failed to parse benign_scanners.yaml at {path}: {e}; "
                f"filter disabled"
            )
            return cls([], resolver=resolver)

        rules: list[ScannerRule] = []
        for vendor, body in (doc.get("scanners") or {}).items():
            asns = frozenset(int(a) for a in (body.get("asns") or []))
            org_keywords = tuple(
                str(kw).lower() for kw in (body.get("org_keywords") or [])
            )
            rdns_suffixes = tuple(
                str(s).lower().rstrip(".").lstrip(".")
                for s in (body.get("rdns_suffixes") or [])
            )
            rules.append(ScannerRule(
                vendor=str(vendor),
                asns=asns,
                org_keywords=org_keywords,
                rdns_suffixes=rdns_suffixes,
            ))
        logger.info(
            f"benign-scanner filter loaded {len(rules)} vendor rule(s) "
            f"from {path}: {sorted(r.vendor for r in rules)}"
        )
        return cls(rules, resolver=resolver)

    def match(self, event: ParsedEvent) -> Optional[str]:
        """Return the vendor name if the event is from a benign scanner, else None.

        Cheap: O(rules) per event, with the ASN fast path being a dict
        lookup. The org-keyword fallback only runs when the ASN didn't
        match — keeps the hot path tight.
        """
        # Fast path: ASN match
        if event.src_asn is not None:
            vendor = self._asn_to_vendor.get(event.src_asn)
            if vendor:
                return vendor
        # Slow path: case-insensitive substring on org name.
        # NOTE: an empty org must NOT short-circuit the function — it only
        # skips this loop. Returning here would mean any event whose GeoIP
        # enrichment lacks an org never reaches the rDNS path at all, which is
        # exactly the population rDNS exists to serve.
        org = (event.src_as_org or "").lower()
        if org:
            for rule in self._rules:
                for kw in rule.org_keywords:
                    if kw in org:
                        return rule.vendor

        # Slowest path: forward-confirmed reverse DNS. Only reached when ASN
        # and org both failed, which is the case for every scanner running on
        # rented infrastructure — i.e. the ones the other two paths cannot see.
        return self._match_rdns(event)

    def _match_rdns(self, event: ParsedEvent) -> Optional[str]:
        if self._resolver is None or not self._rdns_rules:
            return None
        # Already-resolved addresses cost nothing, so check the cache before
        # spending budget: a busy scanner must not exhaust it on repeat visits.
        cached = getattr(self._resolver, "cached_name_for", None)
        if cached is not None:
            hit, known = cached(event.src_ip)
            if known:
                return self._vendor_for(hit)
        # Time the calls HERE rather than reading an attribute off the
        # resolver: `getattr(resolver, "elapsed", 0.0)` would silently return
        # 0.0 for any resolver that does not expose it, disabling the only real
        # stall bound with no error and no signal. The filter owns the budget,
        # so the filter measures it.
        if self._rdns_budget <= 0 or self._rdns_elapsed >= self._rdns_time_budget:
            # Fail OPEN: out of budget means "we do not know", so the event is
            # kept. Under-filtering is visible and fixable; dropping a real
            # attacker because a resolver was slow is data loss.
            self.rdns_skipped_budget += 1
            return None
        self._rdns_budget -= 1
        started = time.monotonic()
        try:
            name = self._resolver.name_for(event.src_ip)
        except Exception:
            # An injected or misbehaving resolver must never break ingest.
            return None
        finally:
            self._rdns_elapsed += time.monotonic() - started
        return self._vendor_for(name)

    def _vendor_for(self, name: Optional[str]) -> Optional[str]:
        if not name:
            return None
        for rule in self._rdns_rules:
            for suffix in rule.rdns_suffixes:
                if suffix_matches(name, suffix):
                    return rule.vendor
        return None

    def __len__(self) -> int:
        """Number of vendor rules currently loaded."""
        return len(self._rules)


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    f = BenignScannerFilter.from_yaml()
    assert len(f) >= 5, f"expected at least 5 vendors loaded, got {len(f)}"

    def mk(ip: str, asn: Optional[int] = None, org: str = "") -> ParsedEvent:
        return ParsedEvent(
            src_ip=ip,
            timestamp=datetime.now(timezone.utc),
            sensor_hostname="node1",
            event_type="Suricata",
            src_asn=asn,
            src_as_org=org,
        )

    # ── 1. Google by ASN ──────────────────────────────────────────────
    ev = mk("34.68.34.67", asn=15169, org="Google LLC")
    m = f.match(ev)
    assert m == "google", f"expected 'google', got {m!r}"
    print(f"OK: google by ASN 15169 → {m!r}")

    # ── 2. Google Cloud by ASN ────────────────────────────────────────
    ev = mk("35.0.0.1", asn=396982, org="Google Cloud Platform")
    m = f.match(ev)
    assert m == "google", f"expected 'google', got {m!r}"
    print(f"OK: google-cloud by ASN 396982 → {m!r}")

    # ── 3. Censys by ASN ──────────────────────────────────────────────
    ev = mk("167.94.138.5", asn=398324, org="Censys, Inc.")
    m = f.match(ev)
    assert m == "censys", f"expected 'censys', got {m!r}"
    print(f"OK: censys by ASN 398324 → {m!r}")

    # ── 4. Org-name match (ASN unknown, org keyword present) ──────────
    ev = mk("1.2.3.4", asn=99999, org="Shodan LLC")
    m = f.match(ev)
    assert m == "shodan", f"expected 'shodan', got {m!r}"
    print(f"OK: shodan by org keyword → {m!r}")

    # ── 5. Random attacker — not in any allowlist ─────────────────────
    ev = mk("198.51.100.42", asn=12345, org="Some Russian ISP")
    m = f.match(ev)
    assert m is None, f"expected None, got {m!r}"
    print(f"OK: random attacker → not filtered")

    # ── 6. Missing ASN + org (e.g. malformed T-Pot doc) ───────────────
    ev = mk("203.0.113.1")
    m = f.match(ev)
    assert m is None
    print(f"OK: no asn/org → not filtered")

    # ── 7. Shadowserver org-name match ────────────────────────────────
    ev = mk("184.105.139.1", asn=33038, org="The Shadowserver Foundation")
    m = f.match(ev)
    assert m == "shadowserver", f"expected 'shadowserver', got {m!r}"
    print(f"OK: shadowserver → {m!r}")

    # ── 8. Empty filter (no yaml) ─────────────────────────────────────
    f_empty = BenignScannerFilter([])
    assert f_empty.match(mk("34.68.34.67", asn=15169, org="Google")) is None
    print(f"OK: empty filter matches nothing")

    # ── 9. Stats ──────────────────────────────────────────────────────
    stats = FilterStats()
    stats.record("google")
    stats.record("google")
    stats.record("censys")
    assert stats.total_filtered == 3
    assert stats.by_vendor["google"] == 2
    assert stats.by_vendor["censys"] == 1
    print(f"OK: stats {stats.to_log_dict()}")

    print("\nOK")
