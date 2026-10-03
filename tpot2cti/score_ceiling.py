"""A score CEILING for addresses whose activity is not attributable to them.

WHY
---
Two populations reached meaningful scores in v2 (audit 2026-10-03):

* **Research scanners.** 66 live Indicators labelled ``scanner:*`` (by the
  ICS research-scanner heuristic, ``ics.session_labels``) had score >= 50.
  The label says "census, not attack"; the score said "worth acting on".
* **CDN edges.** 36 live Indicators inside Cloudflare's published ranges
  had score >= 50. An edge address is the CDN relaying someone else's
  request (Workers, proxied origins, WARP egress); blocking it blocks every
  tenant behind it, and it says nothing about who sent the traffic.

Neither is dropped: the observable, the Sighting and the labels stay, so the
activity remains countable and searchable. Only the score is capped, so no
score-gated consumer (enrichment at > 50, feeds at >= 50/80) acts on it.

WHERE
-----
In the publisher, AFTER the cross-cycle merge (publisher.py Step 0). That
merge keeps max(score) per id across cycles, which is exactly why the
builder could never lower a score ("a score can only ever ratchet UP",
builder._ip_score). Applied after it, and recorded into object_max_state as
the capped value, the ceiling holds across cycles. The merge also unions
the persisted labels first, so a ``scanner:*`` label seen in ANY earlier
cycle still caps the address.

Every emission path (core, malware ingest, noisefloor, blocklists) publishes
through Publisher.publish, so none can bypass it -- the same reasoning as
the sensor redactor (redact.py).

WHAT
----
* Indicators with an ``ipv4-addr``/``ipv6-addr`` value pattern, and
  ``ipv4-addr``/``ipv6-addr`` observables, are capped at
  ``TPOT2CTI_SCORE_CEILING`` (default 25) when:
    - their labels (``labels`` or ``x_opencti_labels``) contain one
      starting with ``scanner:``; or
    - the address is inside a range in ``data/edge_networks.yaml``.
* An edge address also gains the label ``edge-network:<provider>``.
* Nothing is ever RAISED; an object already at or below the ceiling is
  untouched, byte for byte.

The edge list follows benign_scanners.yaml's rule: only ranges a provider
PUBLISHES for its edge, never a cloud provider's tenant space. Attackers rent
cloud VMs; they do not get Cloudflare's anycast edge addresses.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

DEFAULT_EDGE_PATH = Path(__file__).parent / "data" / "edge_networks.yaml"
ENV_CEILING = "TPOT2CTI_SCORE_CEILING"
ENV_EDGE_PATH = "TPOT2CTI_EDGE_NETWORKS_FILE"
DEFAULT_CEILING = 25
SCANNER_PREFIX = "scanner:"
EDGE_LABEL_PREFIX = "edge-network:"

_IP_PATTERN = re.compile(r"^\[\s*(ipv4-addr|ipv6-addr):value\s*=\s*'([^']+)'\s*\]$")


class ScoreCeilingError(ValueError):
    """The ceiling or the edge list is invalid. Raised at startup: a typo
    must stop the process, not silently disable the cap."""


def load_edge_networks(path: Optional[Path | str] = None) -> list[tuple[str, object]]:
    """``[(provider, ip_network)]`` from the YAML. Strict: a missing file, an
    empty list, or ANY unparsable or host-bit-set entry raises."""
    p = Path(path) if path else DEFAULT_EDGE_PATH
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except OSError as e:
        raise ScoreCeilingError(f"edge network list unreadable: {p} ({e})") from e
    providers = (doc or {}).get("providers") or {}
    if not isinstance(providers, dict) or not providers:
        raise ScoreCeilingError(f"edge network list has no providers: {p}")
    out: list[tuple[str, object]] = []
    for name, entry in providers.items():
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", str(name)):
            raise ScoreCeilingError(f"invalid provider name {name!r} in {p}")
        cidrs = (entry or {}).get("cidrs") or []
        if not cidrs:
            raise ScoreCeilingError(f"provider {name!r} has no cidrs in {p}")
        for c in cidrs:
            try:
                out.append((str(name), ipaddress.ip_network(str(c), strict=True)))
            except ValueError as e:
                raise ScoreCeilingError(f"invalid CIDR {c!r} for {name!r} in {p}: {e}") from e
    return out


@dataclass
class ScoreCeiling:
    ceiling: int = DEFAULT_CEILING
    networks: list = field(default_factory=list)
    #: Per-publish counters: "scanner" / "edge:<provider>" -> objects capped.
    counts: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.ceiling, int) or not 0 <= self.ceiling <= 100:
            raise ScoreCeilingError(f"score ceiling must be 0-100; got {self.ceiling!r}")

    @classmethod
    def from_env(cls, env: Optional[dict] = None) -> "ScoreCeiling":
        env = os.environ if env is None else env
        raw = str(env.get(ENV_CEILING, "") or "").split("#", 1)[0].strip()
        try:
            ceiling = int(raw) if raw else DEFAULT_CEILING
        except ValueError as e:
            raise ScoreCeilingError(f"{ENV_CEILING} must be an integer 0-100; got {raw!r}") from e
        path = str(env.get(ENV_EDGE_PATH, "") or "").strip() or None
        return cls(ceiling=ceiling, networks=load_edge_networks(path))

    def begin(self) -> None:
        self.counts = {}

    def edge_provider(self, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        try:
            addr = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return None
        for name, net in self.networks:
            if addr.version == net.version and addr in net:
                return name
        return None

    @staticmethod
    def address_of(obj: dict) -> Optional[str]:
        t = obj.get("type")
        if t in ("ipv4-addr", "ipv6-addr"):
            return obj.get("value")
        if t == "indicator":
            m = _IP_PATTERN.match(str(obj.get("pattern") or "").strip())
            return m.group(2) if m else None
        return None

    def reason(self, obj: dict) -> Optional[str]:
        """Why ``obj`` is capped ("scanner", "edge:<provider>"), or None."""
        addr = self.address_of(obj)
        if addr is None:
            return None
        provider = self.edge_provider(addr)
        if provider:
            return f"edge:{provider}"
        labels = list(obj.get("labels") or []) + list(obj.get("x_opencti_labels") or [])
        if any(str(l).startswith(SCANNER_PREFIX) for l in labels):
            return "scanner"
        return None

    def apply(self, obj: dict) -> Optional[str]:
        """Cap ``obj`` in place. Returns the reason when it changed anything."""
        why = self.reason(obj)
        if why is None:
            return None
        changed = False
        score = obj.get("x_opencti_score")
        if isinstance(score, int) and score > self.ceiling:
            obj["x_opencti_score"] = self.ceiling
            changed = True
        if why.startswith("edge:"):
            label = EDGE_LABEL_PREFIX + why.split(":", 1)[1]
            key = "labels" if obj.get("type") == "indicator" else "x_opencti_labels"
            cur = list(obj.get(key) or [])
            if label not in cur:
                obj[key] = sorted(set(cur) | {label})
                changed = True
        if changed:
            self.counts[why] = self.counts.get(why, 0) + 1
            return why
        return None


def from_env() -> ScoreCeiling:
    return ScoreCeiling.from_env()
