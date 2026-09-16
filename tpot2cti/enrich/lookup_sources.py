"""Lane B source registry — one table entry per per-object lookup source.

Same shape as `enrich/sources.py` does for Lane A, and for the same reason:
sources differ only in a URL, a normaliser, a label prefix and a tier, so
splitting them into modules would produce near-identical files. Add a source
here, not a framework — docs/ENRICHMENT.md §10 ("add sources, not frameworks").

TIERS (docs/ENRICHMENT.md §4). The governing principle is that the no-signup
path requires ZERO configuration:

    0  no signup, works out of the box       internetdb, circl
    1  free, requires a free signup key      abusech, abuseipdb
    2  paid, strictly optional               vt

A Tier 1/2 source with no credential configured disables itself with one log
line at startup. It must never fail a cycle — that is what makes "works out of
the box" true rather than aspirational.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

logger = logging.getLogger(__name__)

DAY = 86400


class LookupError_(RuntimeError):
    """Provider call failed. Never cached as a verdict — see ledger.record_error."""


# ---------------------------------------------------------------------------
# Fetchers — each returns a NORMALISED minimal verdict, never the vendor blob
# ---------------------------------------------------------------------------

#: Providers reject urllib's default `Python-urllib/3.x`. Measured 2026-08-26:
#: InternetDB returned HTTP 403 on 500/500 calls with the default agent and 200
#: with any real one. Identify honestly — a free service answering us is owed
#: knowing who is asking.
USER_AGENT = os.environ.get(
    "ENRICH_LOOKUP_USER_AGENT",
    "tpot2cti/1.0 (+honeypot threat-intel; contact via repo)")


def _get_json(url: str, *, timeout: int, headers: Optional[dict] = None) -> Optional[dict]:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None                      # a real "not found", not an error
        raise LookupError_(f"HTTP {e.code}") from e
    except Exception as e:                   # noqa: BLE001
        raise LookupError_(str(e)[:200]) from e


def fetch_internetdb(value: str, *, timeout: int, credential: Optional[str]) -> Optional[dict]:
    """Shodan InternetDB — free, no key, no rate limit published.

    Normalised to the four fields we actually use. `hostnames` is carried but
    is LABEL-ONLY downstream: a PTR name is a third-party assertion about
    naming, not a first-party observation (ENRICHMENT.md §7 / EVIDENCE.md §6).
    """
    raw = _get_json(f"https://internetdb.shodan.io/{value}", timeout=timeout)
    if raw is None:
        return None
    return {
        "ports": sorted({int(p) for p in (raw.get("ports") or []) if str(p).isdigit()})[:40],
        "tags": sorted({str(t)[:40] for t in (raw.get("tags") or [])})[:20],
        "cpes": sorted({str(c)[:80] for c in (raw.get("cpes") or [])})[:20],
        "vulns": sorted({str(v).upper() for v in (raw.get("vulns") or [])
                         if str(v).upper().startswith("CVE-")})[:40],
        "hostnames": sorted({str(h)[:120] for h in (raw.get("hostnames") or [])})[:10],
    }


def fetch_circl_hashlookup(value: str, *, timeout: int, credential: Optional[str]) -> Optional[dict]:
    """CIRCL hashlookup — free, no auth. Known-GOOD suppression (NSRL et al).

    A hit means the file is known-good, so this SUPPRESSES rather than accuses.
    Expressed as a label, never as a lowered score: the publisher keeps the
    maximum score across cycles, so scores only ratchet up and an export gate
    must read labels (ENRICHMENT.md §7 hard rules).
    """
    raw = _get_json(f"https://hashlookup.circl.lu/lookup/sha256/{value}",
                    timeout=timeout)
    if raw is None:
        return None
    if raw.get("message") and not raw.get("FileName"):
        return None
    return {
        "known_good": True,
        "source": str(raw.get("source") or raw.get("db") or "hashlookup")[:60],
        "file_name": str(raw.get("FileName") or "")[:120],
        "trust": raw.get("hashlookup:trust"),
    }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LookupSource:
    key: str
    tier: int
    obs_type: str                       # 'ipv4' | 'sha256'
    label_prefix: str                   # the namespace this source OWNS (§8)
    fetch: Callable[..., Optional[dict]]
    #: TTL asymmetry is the point (§6): a negative answer must expire faster
    #: than a positive one, because unknown->known is the transition we want.
    ttl_found: int
    ttl_not_found: int
    credential_env: Optional[str] = None
    daily_budget: int = 0               # 0 = unmetered (no published limit)
    meaning: str = ""

    @property
    def enabled(self) -> bool:
        """Tier 1/2 sources self-disable when their credential is absent."""
        if self.credential_env is None:
            return True
        return bool(os.environ.get(self.credential_env, "").strip())

    @property
    def credential(self) -> Optional[str]:
        if not self.credential_env:
            return None
        return os.environ.get(self.credential_env, "").strip() or None


SOURCES: tuple[LookupSource, ...] = (
    LookupSource(
        key="internetdb", tier=0, obs_type="ipv4", label_prefix="shodan:",
        fetch=fetch_internetdb,
        # An address's exposed surface drifts as it is reassigned or patched.
        ttl_found=14 * DAY, ttl_not_found=3 * DAY,
        meaning="open ports, CPEs, scanner tag and CVEs Shodan already observed",
    ),
    LookupSource(
        key="circl", tier=0, obs_type="sha256", label_prefix="hashlookup:",
        fetch=fetch_circl_hashlookup,
        # Known-good membership does not change; not-found is the interesting
        # transition, so it expires fast.
        ttl_found=180 * DAY, ttl_not_found=2 * DAY,
        meaning="known-good file suppression (NSRL and friends)",
    ),
)

SOURCES_BY_KEY = {s.key: s for s in SOURCES}
#: Tier-0 only. Deliberately the default: `ENRICH_LOOKUP_SOURCES` unset must
#: yield a working install with no credentials at all.
DEFAULT_SOURCES = ",".join(s.key for s in SOURCES if s.tier == 0)


def selected_sources(spec: str) -> list[LookupSource]:
    """Resolve a comma-separated spec, dropping credential-less Tier 1/2.

    An UNKNOWN name is a hard error, matching Lane A: a typo must not silently
    disable a source and leave the operator believing it runs.
    """
    out: list[LookupSource] = []
    for raw in (spec or "").split(","):
        key = raw.strip()
        if not key:
            continue
        src = SOURCES_BY_KEY.get(key)
        if src is None:
            raise ValueError(
                f"unknown lookup source {key!r}; known: "
                f"{', '.join(sorted(SOURCES_BY_KEY))}")
        if not src.enabled:
            logger.warning(
                "lookup: %s is tier %d and %s is not set — disabling this source "
                "for the run. This is not an error; the no-signup path is "
                "expected to run without it.", src.key, src.tier, src.credential_env)
            continue
        out.append(src)
    return out


def is_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(str(value)), ipaddress.IPv4Address)
    except ValueError:
        return False
