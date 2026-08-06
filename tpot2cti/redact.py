"""Sensor-identity redaction — the last thing that happens before publish.

**Why this is one function and not 59 edits.**

`sensor_hostname` appears 59 times in `stix/builder.py` alone, plus the
rendering module and the attacker-profile builder. Patching each site is the
21-copies shape this codebase has been burned by repeatedly: the fix lands in
one copy, module N+1 is added later without it, and the leak returns silently.

So redaction runs once, in `Publisher.publish()`, over every object on its way
out. Every emission path funnels through there — CORE (`main.py`), the malware
ingest, noisefloor, blocklists and selftest — including the three that never
touch `stix/builder.py` at all. A new producer cannot forget to call it,
because it does not call it; the publisher does.

**What leaks, measured on the live corpus 2026-08-05:** 1,034 Notes and 4,442
Sighting descriptions embed a sensor-side public IP, and every parser-labelled
object carries a `sensor:<hostname>` label. These are shareable STIX objects.
Publishing them hands an adversary the fleet's sensor addresses, which get
null-routed or fed garbage — the honeypot's value depends on not being
identifiable as one.

**Pseudonyms, not deletion.** Correlation across objects is the whole point of
the graph, so a sensor keeps a stable identity — it just stops being a routable
one. `sensor-<8 hex>` is derived by HMAC from the hostname under a per-
deployment secret, so it is stable within a deployment, distinct across
deployments, and not reversible by an outside reader who lacks the secret.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from typing import Any, Iterable, Optional

#: Fields whose free text is rendered for humans and therefore leaks.
_TEXT_FIELDS = (
    "description", "x_opencti_description", "content", "abstract", "name",
)


def _pseudonym(hostname: str, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), hostname.lower().encode("utf-8"),
                      hashlib.sha256).hexdigest()
    return f"sensor-{digest[:8]}"


class SensorRedactor:
    """Replaces sensor hostnames and own addresses in outbound objects."""

    def __init__(self, hostnames: Iterable[str], addresses: Iterable[str],
                 *, secret: str) -> None:
        self._secret = secret or "tpot2cti-default-redaction-secret"
        self._names = {h.lower(): _pseudonym(h, self._secret)
                       for h in hostnames if h}
        self._addrs: dict[str, str] = {}
        for a in addresses:
            a = (a or "").strip()
            if not a:
                continue
            try:                       # a bare address
                ipaddress.ip_address(a)
                self._addrs[a] = "<sensor-address>"
            except ValueError:
                try:                   # ...or a whole net
                    net = ipaddress.ip_network(a, strict=False)
                    self._addrs[str(net)] = "<sensor-net>"
                except ValueError:
                    continue
        # Longest-first so a /24 net string never half-matches an address.
        keys = sorted({**self._names, **self._addrs}, key=len, reverse=True)
        self._pattern = (
            re.compile("|".join(re.escape(k) for k in keys), re.IGNORECASE)
            if keys else None
        )
        self._repl = {**self._names, **self._addrs}
        self.redactions = 0

    def _sub_text(self, value: str) -> str:
        if not self._pattern:
            return value

        def _one(m: re.Match) -> str:
            self.redactions += 1
            return self._repl.get(m.group(0).lower(),
                                  self._repl.get(m.group(0), "<redacted>"))
        return self._pattern.sub(_one, value)

    def redact(self, obj: dict) -> dict:
        """Return `obj` with sensor identity removed. Mutates a shallow copy."""
        out = dict(obj)
        for field in _TEXT_FIELDS:
            v = out.get(field)
            if isinstance(v, str) and v:
                out[field] = self._sub_text(v)

        labels = out.get("x_opencti_labels")
        if isinstance(labels, list):
            new = []
            for lbl in labels:
                if isinstance(lbl, str) and lbl.lower().startswith("sensor:"):
                    host = lbl.split(":", 1)[1].strip().lower()
                    self.redactions += 1
                    # Pseudonymise on the fly for hostnames not in the
                    # configured list. Deriving it here rather than emitting
                    # "<redacted>" keeps per-sensor correlation working even
                    # when the operator has not enumerated every sensor —
                    # the label is the one place we can always recover the
                    # hostname from the object itself.
                    new.append("sensor:" + self._names.setdefault(
                        host, _pseudonym(host, self._secret)))
                else:
                    new.append(lbl)
            out["x_opencti_labels"] = sorted(set(new))
        return out

    def redact_all(self, objects: list[dict]) -> list[dict]:
        return [self.redact(o) for o in objects]


def from_env(env: Optional[dict] = None) -> SensorRedactor:
    """Build a redactor from the deployment's own configuration.

    `Publisher` calls this when no redactor is passed, so redaction is on by
    default and a producer has to work to disable it. Sensor hostnames are
    also learned on the fly from `sensor:<host>` labels (see `redact`), so an
    unconfigured deployment still pseudonymises labels — but only the
    configured values can be scrubbed from free-text descriptions, which is
    why TPOT2CTI_SENSOR_HOSTNAMES is worth setting.
    """
    import os
    e = env if env is not None else os.environ

    def _split(key: str) -> list[str]:
        return [x.strip() for x in (e.get(key) or "").split(",") if x.strip()]

    return SensorRedactor(
        hostnames=_split("TPOT2CTI_SENSOR_HOSTNAMES"),
        addresses=_split("TPOT_HONEYPOT_IPS") + _split("TPOT2CTI_EXCLUDED_SRC_NETS"),
        secret=(e.get("TPOT2CTI_REDACTION_SECRET")
                or e.get("OPENCTI_TOKEN") or "tpot2cti-default-redaction-secret"),
    )
