"""Forward-confirmed reverse DNS, for identifying rented scanner infrastructure.

**Why this exists.** `benign_filter` matches research scanners by ASN and AS-org
name. That worked when scanners ran on their own netblocks and does not work
now, because they rent: Shadowserver's scanners appear as Hurricane Electric
(AS6939), BinaryEdge's as DigitalOcean (AS14061), Stretchoid's as Microsoft
(AS8075). All three vendors were already named in `benign_scanners.yaml` and
were structurally unmatchable — measured on the live fleet, 17 addresses were
being labelled `targeted:substantive`, the label that means "this one got in,
share it as real intelligence". Shadowserver is a nonprofit.

Reverse DNS is the only thing that identifies them.

**Why a bare PTR lookup would be a security hole.** PTR records are controlled
by whoever holds the address block — an attacker can simply publish
`scan-99.shadowserver.io` for their own host and be allowlisted straight out of
the intelligence they would otherwise appear in. Adding naive rDNS matching to
an allowlist creates an opt-out that anyone can use.

So every match is **forward-confirmed**: the PTR name is resolved back, and the
result must contain the original address. An attacker can claim any name, but
cannot make `shadowserver.io` resolve to their host.

**Failure is treated as "not a scanner".** A DNS timeout, SERVFAIL or an
exhausted budget means the event is KEPT. Keeping a Shadowserver record is a
cosmetic problem; dropping a real attacker because a resolver blipped is data
loss, and this project's failures are all data loss.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import time
from typing import Optional

logger = logging.getLogger(__name__)

#: Seconds to wait on a single DNS operation. Deliberately short: this runs
#: inside the ingest loop, and a slow resolver must never stall a cycle.
DEFAULT_TIMEOUT = 1.0

#: A confirmed name is stable — infrastructure keeps its PTR for a long time.
DEFAULT_TTL = 7 * 24 * 3600

#: A miss is cached far more briefly: an address with no PTR today may get one,
#: and a resolver failure must not be remembered as a fact for a week.
DEFAULT_NEGATIVE_TTL = 3600

#: Hard ceiling on cached entries, so a high-churn fleet cannot grow this
#: without bound. Evicts oldest-expiring first.
DEFAULT_MAX_ENTRIES = 100_000


class ForwardConfirmedRDNS:
    """Resolve an address to a *verified* reverse name, with caching.

    Not thread-safe by design — CORE's ingest loop is single-threaded, and a
    lock here would sit in the hot path for no benefit.
    """

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        ttl: int = DEFAULT_TTL,
        negative_ttl: int = DEFAULT_NEGATIVE_TTL,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        resolver=None,
        forward_resolver=None,
    ) -> None:
        self._timeout = float(timeout)
        self._ttl = int(ttl)
        self._negative_ttl = int(negative_ttl)
        self._max_entries = int(max_entries)
        # Injected for tests — the real ones hit the network.
        self._reverse = resolver or self._default_reverse
        self._forward = forward_resolver or self._default_forward
        self._cache: dict[str, tuple[Optional[str], float]] = {}
        self.lookups = 0
        self.confirmed = 0
        self.rejected_unconfirmed = 0
        self.errors = 0

    # -- resolution ------------------------------------------------------

    def _default_reverse(self, ip: str) -> Optional[str]:
        socket.setdefaulttimeout(self._timeout)
        return socket.gethostbyaddr(ip)[0]

    def _default_forward(self, name: str) -> list[str]:
        socket.setdefaulttimeout(self._timeout)
        infos = socket.getaddrinfo(name, None)
        return [i[4][0] for i in infos]

    def name_for(self, ip: str) -> Optional[str]:
        """Return the forward-confirmed reverse name, or None.

        None covers every uncertain case — no PTR, forward lookup disagrees,
        resolver error, malformed address. Callers must treat None as "not a
        known scanner" and keep the event.
        """
        now = time.monotonic()
        hit = self._cache.get(ip)
        if hit is not None and hit[1] > now:
            return hit[0]

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None

        self.lookups += 1
        name: Optional[str] = None
        try:
            raw = self._reverse(ip)
            if raw:
                candidate = str(raw).rstrip(".").lower()
                # THE forward confirmation. Without this the PTR is a claim by
                # the address holder, not evidence.
                addrs = {str(a) for a in (self._forward(candidate) or [])}
                if ip in addrs:
                    name = candidate
                    self.confirmed += 1
                else:
                    self.rejected_unconfirmed += 1
                    logger.debug(
                        "rdns: %s claims PTR %r but it forward-resolves to %s "
                        "— not confirmed, treating as unknown",
                        ip, candidate, sorted(addrs)[:4],
                    )
        except Exception:
            # socket.herror / gaierror / timeout — all "we do not know".
            self.errors += 1

        ttl = self._ttl if name else self._negative_ttl
        self._remember(ip, name, now + ttl)
        return name

    def _remember(self, ip: str, name: Optional[str], expires: float) -> None:
        if len(self._cache) >= self._max_entries:
            # Drop the entries closest to expiry. Cheap enough at this size and
            # far simpler to reason about than an LRU.
            for k, _ in sorted(self._cache.items(), key=lambda kv: kv[1][1])[
                    : max(1, self._max_entries // 10)]:
                self._cache.pop(k, None)
        self._cache[ip] = (name, expires)

    # -- introspection ---------------------------------------------------

    def stats(self) -> dict:
        return {
            "lookups": self.lookups,
            "confirmed": self.confirmed,
            "rejected_unconfirmed": self.rejected_unconfirmed,
            "errors": self.errors,
            "cached": len(self._cache),
        }

    def reset_stats(self) -> None:
        self.lookups = self.confirmed = 0
        self.rejected_unconfirmed = self.errors = 0


def suffix_matches(name: str, suffix: str) -> bool:
    """True if `name` is `suffix` or a subdomain of it.

    Label-boundary aware on purpose: a plain `endswith` would let
    `evil-shadowserver.io` match a `shadowserver.io` rule, which is exactly the
    kind of near-miss an attacker would register.
    """
    name = (name or "").rstrip(".").lower()
    suffix = (suffix or "").rstrip(".").lower().lstrip(".")
    if not name or not suffix:
        return False
    return name == suffix or name.endswith("." + suffix)
