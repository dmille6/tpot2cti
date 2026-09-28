"""Our own attack surface: the persona domains the sensors answer to.

**Why this exists.** The sensors wear public personas: each one answers to a
registered domain and a spread of subdomains, and scanners enumerate those
subdomains by the thousand. Every such request used to come back out of the
pipeline as a Url observable (`https://<sub>.<persona-domain>/<path>`), and
the enrichment connectors then sent each one to external reputation services.
Measured on the v2 corpus on 2026-09-28: 158,128 of 178,022 Url observables
(88.8%) named a persona domain, all but a few thousand minted from the
inbound `Host` header, and every one of them was a GTI lookup and a GTI Note.

`redact.SensorRedactor` already refuses sensor ADDRESSES and sensor
HOSTNAMES. It cannot refuse persona domains, because a persona domain is not
a single name: it is a zone. This module is that zone predicate.

**Configuration: one source.** ``TPOT2CTI_OWN_DOMAINS`` is a comma-separated
list of domain roots, read from the deployment's ``.env`` beside
``TPOT_HONEYPOT_IPS`` and ``TPOT2CTI_SENSOR_HOSTNAMES`` (the other two halves
of the own-surface configuration). A root covers itself and every subdomain.
The list is deliberately NOT shipped in this repository: this repository is
public, and a list of persona domains in it would publish exactly what the
guard exists to protect. An empty list is logged loudly at startup and shown
as ``domains_configured: 0`` in ``/health``.

**Matching is exact-or-subdomain, after canonicalisation.** A host matches
root ``r`` iff ``host == r`` or ``host.endswith("." + r)``, after both sides
are lower-cased, stripped of a trailing dot and a port, and converted to their
IDNA A-label (punycode) form. There is deliberately no substring, prefix or
brand matching: ``<root>-evil.example``, ``evil<root>``, ``<root>.evil.example``
and Unicode look-alikes are someone else's infrastructure and stay publishable.
"""
from __future__ import annotations

import ipaddress
import logging
import os
from typing import Iterable, Mapping, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

#: Env var holding the comma-separated persona domain roots.
ENV_OWN_DOMAINS = "TPOT2CTI_OWN_DOMAINS"

#: Refusal reasons. Stable tokens: they are counter keys in the cycle
#: summary and /health, so renaming one silently resets a dashboard.
REASON_PERSONA_DOMAIN = "persona-domain"
REASON_SENSOR_ADDRESS = "sensor-address"
REASON_SENSOR_HOSTNAME = "sensor-hostname"


def canon_host(host: Optional[str]) -> str:
    """Canonical form of a host for comparison, or "" if there is none.

    Lower-case, no trailing dot, no port, no IPv6 brackets, IDNA A-label.
    Accepts a bare host (``Db1.Example.COM.``), a host with a port
    (``db1.example.com:8443``) or a bracketed IPv6 literal (``[::1]:80``).
    Never raises: a label IDNA refuses (too long, forbidden code point) is
    compared in its lower-cased form, which can only fail to match a root
    that is itself valid IDNA — a miss, never a false refusal.
    """
    if not host:
        return ""
    h = str(host).strip()
    if not h:
        return ""
    if h.startswith("["):                       # [v6] or [v6]:port
        end = h.find("]")
        h = h[1:end] if end > 0 else h[1:]
    elif h.count(":") == 1:                     # name:port or v4:port
        h = h.split(":", 1)[0]
    # (two or more colons, unbracketed: a bare IPv6 literal — leave it)
    h = h.strip().rstrip(".").lower()
    if not h:
        return ""
    if any(ord(c) > 127 for c in h):
        try:
            h = h.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            pass
    return h


def _parse_roots(values: Iterable[str]) -> tuple[frozenset, list]:
    roots: set[str] = set()
    bad: list[str] = []
    for raw in values:
        r = canon_host(raw.lstrip("*").lstrip("."))  # tolerate "*.example.com"
        if not r or "." not in r:
            # A bare label ("com", "local") would own a whole TLD.
            if raw.strip():
                bad.append(raw.strip())
            continue
        try:
            ipaddress.ip_address(r)
            bad.append(raw.strip())                   # addresses go in TPOT_HONEYPOT_IPS
            continue
        except ValueError:
            pass
        roots.add(r)
    return frozenset(roots), bad


class OwnSurface:
    """Predicate over hosts/URLs: is this OUR surface?

    Combines the persona domain roots with the sensor identity the redactor
    already carries (addresses, networks, hostnames), so one call answers the
    whole question and one reason token says which half answered it.
    """

    def __init__(self, domains: Iterable[str] = (), *, redactor=None) -> None:
        self.roots, self.invalid_entries = _parse_roots(domains)
        self._redactor = redactor
        # Longest-first is irrelevant for suffix tests; a sorted tuple just
        # makes logs and /health stable.
        self._roots_sorted = tuple(sorted(self.roots))

    # ── host level ──────────────────────────────────────────────────────
    def domain_root(self, host: Optional[str]) -> Optional[str]:
        """The configured root `host` falls under, or None."""
        h = canon_host(host)
        if not h:
            return None
        for r in self._roots_sorted:
            if h == r or h.endswith("." + r):
                return r
        return None

    def host_reason(self, host: Optional[str]) -> Optional[str]:
        """Why `host` is our own surface, or None if it is not."""
        h = canon_host(host)
        if not h:
            return None
        if self.domain_root(h) is not None:
            return REASON_PERSONA_DOMAIN
        red = self._redactor
        if red is not None:
            try:
                if red.is_sensor_host(h):
                    try:
                        ipaddress.ip_address(h)
                        return REASON_SENSOR_ADDRESS
                    except ValueError:
                        return REASON_SENSOR_HOSTNAME
            except Exception:           # pragma: no cover — never break a caller
                return None
        return None

    def is_own_host(self, host: Optional[str]) -> bool:
        return self.host_reason(host) is not None

    # ── URL level ───────────────────────────────────────────────────────
    def url_reason(self, url: Optional[str]) -> Optional[str]:
        """Why `url`'s host is our own surface, or None.

        Scheme-less values (bare request paths) have no host and are never
        own-surface here — `valid_url` refuses them on its own grounds.
        """
        if not url:
            return None
        try:
            parts = urlsplit(str(url).strip())
            host = parts.hostname
        except ValueError:
            return None
        return self.host_reason(host)

    def is_own_url(self, url: Optional[str]) -> bool:
        return self.url_reason(url) is not None

    def is_own_value(self, value) -> bool:
        """URL-or-host, for rendering filters over mixed sample lists."""
        v = str(value or "").strip()
        if "://" in v:
            return self.is_own_url(v)
        return self.is_own_host(v)

    def summary(self) -> dict:
        """Non-sensitive shape for /health: counts only, never the roots."""
        return {
            "domains_configured": len(self.roots),
            "invalid_entries": len(self.invalid_entries),
        }


def from_env(env: Optional[Mapping[str, str]] = None, *, redactor=None) -> OwnSurface:
    """Build the predicate from the deployment's configuration.

    `redactor` defaults to `redact.from_env(env)` so sensor addresses and
    hostnames come from the same variables the publisher redacts with.
    Pass ``redactor=False`` for a domains-only predicate (the builder asks
    its own redactor the sensor half of the question).
    """
    e = env if env is not None else os.environ
    raw = [x for x in (e.get(ENV_OWN_DOMAINS) or "").split(",") if x.strip()]
    if redactor is False:
        redactor = None
    elif redactor is None:
        try:
            from tpot2cti.redact import from_env as _redactor_from_env
            redactor = _redactor_from_env(e)
        except Exception:               # pragma: no cover — never break startup
            redactor = None
    own = OwnSurface(raw, redactor=redactor)
    if own.invalid_entries:
        logger.warning(
            f"{ENV_OWN_DOMAINS}: ignored {len(own.invalid_entries)} entr(y/ies) "
            f"that are not domain roots (bare labels or IP addresses; "
            f"addresses belong in TPOT_HONEYPOT_IPS)"
        )
    return own


#: Flags whose combination defines one counting period for the totals.
_TOTALS_FLAGS = ("domains_configured", "inbound_request_observables")


def cycle_stats(builder) -> dict:
    """One cycle's own-surface counters, in the /health shape.

    ``refused``: own-surface refusals by "<url|domain>:<reason>".
    ``inbound_suppressed``: inbound request targets not emitted, by kind.
    Never raises — a counter must not fail a cycle.
    """
    try:
        own = getattr(builder, "_own_surface", None)
        refused = dict(sorted((getattr(builder, "own_surface_refused", {}) or {}).items()))
        suppressed = dict(sorted(
            (getattr(builder, "inbound_request_suppressed", {}) or {}).items()))
        return {
            "domains_configured": len(own.roots) if own is not None else 0,
            "inbound_request_observables": bool(
                getattr(builder, "_inbound_requests_enabled", False)),
            "refused": refused,
            "refused_total": sum(refused.values()),
            "inbound_suppressed": suppressed,
            "inbound_suppressed_total": sum(suppressed.values()),
        }
    except Exception as e:              # pragma: no cover — defensive
        return {"error": str(e)}


def merge_totals(totals: Optional[dict], cycle: dict, *, now_iso: str) -> dict:
    """Add one cycle's :func:`cycle_stats` into running totals.

    Same contract as ``evidence.merge_totals``: called only after a
    successful publish (a retried window is counted once), and RESTARTED
    with ``since = now_iso`` when the configuration that defines the period
    changes — a different number of roots, or the legacy switch flipped.
    """
    if not totals or any(totals.get(k) != cycle.get(k) for k in _TOTALS_FLAGS):
        totals = {"since": now_iso}
    t = dict(totals)
    t["cycles"] = int(t.get("cycles", 0)) + 1
    for key in ("refused", "inbound_suppressed"):
        merged = dict(t.get(key) or {})
        for k, v in (cycle.get(key) or {}).items():
            merged[k] = int(merged.get(k, 0)) + int(v)
        t[key] = dict(sorted(merged.items()))
    for key in ("refused_total", "inbound_suppressed_total"):
        t[key] = int(t.get(key, 0)) + int(cycle.get(key, 0))
    for key in _TOTALS_FLAGS:
        t[key] = cycle.get(key)
    return t


_DEFAULT: Optional[OwnSurface] = None


def default() -> OwnSurface:
    """Process-wide instance from the environment, built on first use."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = from_env()
        if not _DEFAULT.roots:
            logger.warning(
                f"own-surface: {ENV_OWN_DOMAINS} is empty — persona-domain "
                f"URLs and domains will NOT be refused. Set it in .env beside "
                f"TPOT2CTI_SENSOR_HOSTNAMES."
            )
        else:
            logger.info(
                f"own-surface: {len(_DEFAULT.roots)} persona domain root(s) "
                f"configured"
            )
    return _DEFAULT


def set_default(own: Optional[OwnSurface]) -> None:
    """Replace (or with None, reset) the process-wide instance. For tests."""
    global _DEFAULT
    _DEFAULT = own


__all__ = [
    "ENV_OWN_DOMAINS",
    "OwnSurface",
    "REASON_PERSONA_DOMAIN",
    "REASON_SENSOR_ADDRESS",
    "REASON_SENSOR_HOSTNAME",
    "canon_host",
    "cycle_stats",
    "default",
    "from_env",
    "merge_totals",
    "set_default",
]
