"""tpot2cti — shared-IoC Campaign grouping.

A single scanning IP is a data point; the *same concrete artifact* turning up
from many IPs is intelligence. When two or more distinct attacker IPs deliver
the same malware, plant the same SSH key, or present the same client
fingerprint (HASSH / JA3), they're almost certainly the same actor or toolkit.
This module rolls those into a first-class STIX **Campaign** node so OpenCTI
shows one coordinated operation instead of N disconnected indicators.

Why this needs state (cf. attacker_profile.py):
  The second IP sharing an artifact almost always arrives in a LATER cycle than
  the first. A single cycle can't see the sharing on its own, so every
  observation is logged to the ``campaign_artifacts`` SQLite table. Once an
  artifact_key is shared by >= ``MIN_CAMPAIGN_MEMBERS`` distinct IPs, the
  Campaign materialises and every member IP's indicator gets an
  ``indicates -> campaign`` edge. Deterministic Campaign UUID5 (keyed off the
  artifact) means the node merges across all cycles in OpenCTI — the wave
  accumulates over time under one node.

Grouping basis (operator choice, 2026-06-03): **shared concrete IoC only** —
the tight, defensible signal. NOT behavioural "everyone scanning cPanel"
buckets (too loose: unrelated bots share targets).

STIX shape per materialised campaign:
  * Campaign SDO (name / objective / first_seen / last_seen / labels)
  * indicator(ip) --indicates--> campaign      (one per member IP)
  * campaign --related-to--> <artifact SCO>     (File or Cryptographic-Key)

See docs/campaigns.md for the full write-up.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Optional

from tpot2cti.parsers.base import AttackSession
from tpot2cti.state import CycleState
from tpot2cti.stix.builder import STIXBuilder
from tpot2cti.stix_ids import (
    generate_campaign_id,
    generate_cryptographic_key_id,
    generate_file_id,
    attacker_ip_indicator_id,
)

logger = logging.getLogger(__name__)

#: A Campaign only materialises once this many DISTINCT source IPs share one
#: concrete artifact. Two is the floor for "coordinated" — a single IP with a
#: unique malware drop is just one drop, not a campaign.
MIN_CAMPAIGN_MEMBERS = 2

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Per-artifact-type campaign metadata. ``value`` is the full artifact (shown in
# the description for analyst pivoting); ``n`` is the distinct-IP count.
_CAMPAIGN_DEFS: dict[str, dict] = {
    "malware": {
        "name": "Shared malware payload — {display}",
        "objective": "Distribute a common malware payload across multiple hosts",
        "labels": ["shared-ioc", "shared-malware"],
        "describe": (
            "{n} distinct source IPs delivered the same file (sha256 {value}) "
            "to the honeypot grid — a coordinated distribution campaign or "
            "shared toolkit."
        ),
    },
    "ssh-key": {
        "name": "Shared SSH key implant — {display}",
        "objective": "Maintain persistent SSH access via a common authorized_keys implant",
        "labels": ["shared-ioc", "shared-ssh-key"],
        "describe": (
            "{n} distinct source IPs planted the same SSH public key "
            "(SHA256 fp {value}) into authorized_keys — the same actor or "
            "botnet maintaining cross-host persistence."
        ),
    },
    "hassh": {
        "name": "Shared SSH client fingerprint — {display}",
        "objective": "Common SSH client tooling across distributed sources",
        "labels": ["shared-ioc", "shared-fingerprint", "hassh"],
        "describe": (
            "{n} distinct source IPs presented the identical SSH client "
            "fingerprint (HASSH {value}) — the same automation / tool driving "
            "the connections."
        ),
    },
    "ja3": {
        "name": "Shared TLS client fingerprint — {display}",
        "objective": "Common TLS client tooling across distributed sources",
        "labels": ["shared-ioc", "shared-fingerprint", "ja3"],
        "describe": (
            "{n} distinct source IPs presented the identical TLS client "
            "fingerprint (JA3 {value}) — the same client toolkit."
        ),
    },
}


def extract_artifacts(session: AttackSession) -> list[dict]:
    """Pull the concrete, shareable IoCs out of a session.

    Returns a list of ``{type, value, key, display}`` dicts. ``key`` is the
    cross-IP grouping key; ``value`` is also what seeds the artifact's SCO id
    (so the campaign can link to the exact File / Cryptographic-Key the
    per-session builders already emit). Empty when the session carries no
    shareable artifact or no src_ip.
    """
    out: list[dict] = []
    if not session.src_ip:
        return out

    for sha in (session.malware_hashes or []):
        sha = (sha or "").strip().lower()
        if not _SHA256_RE.match(sha):
            continue
        out.append({
            "type": "malware", "value": sha, "key": f"malware:{sha}",
            "display": f"sha256:{sha[:12]}…",
        })

    for key_info in (session.planted_ssh_keys or []):
        fp = (key_info.get("fingerprint") or "").strip()
        if not fp:
            continue
        out.append({
            "type": "ssh-key", "value": fp, "key": f"sshkey:{fp}",
            "display": f"SSH fp {fp[:12]}…",
        })

    # HASSH / JA3 use the raw value verbatim — it must match the seed the
    # builder feeds generate_cryptographic_key_id() so the edge resolves.
    if session.hassh:
        h = session.hassh.strip()
        if h:
            out.append({
                "type": "hassh", "value": h, "key": f"hassh:{h}",
                "display": f"HASSH {h[:12]}…",
            })
    if session.ja3:
        j = session.ja3.strip()
        if j:
            out.append({
                "type": "ja3", "value": j, "key": f"ja3:{j}",
                "display": f"JA3 {j[:12]}…",
            })
    return out


def record_session_artifacts(state: CycleState, session: AttackSession) -> list[str]:
    """Log a session's artifacts to ``campaign_artifacts``.

    Returns the list of artifact_keys touched this cycle (the candidate set
    ``emit_campaigns`` re-checks for threshold crossings). Defensive: never
    raises into the cycle loop.
    """
    keys: list[str] = []
    try:
        artifacts = extract_artifacts(session)
    except Exception as e:  # pragma: no cover — defensive
        logger.debug(f"campaigns.extract_artifacts raised (ignored): {e}")
        return keys
    if not artifacts:
        return keys
    seen_iso = (
        session.last_seen.isoformat() if session.last_seen
        else datetime.now(timezone.utc).isoformat()
    )
    for a in artifacts:
        try:
            state.record_campaign_artifact(
                artifact_key=a["key"], src_ip=session.src_ip,
                artifact_type=a["type"], artifact_value=a["value"],
                display=a["display"], seen_iso=seen_iso,
            )
            keys.append(a["key"])
        except Exception as e:  # pragma: no cover — defensive
            logger.debug(f"campaigns.record_campaign_artifact raised (ignored): {e}")
    return keys


def _sco_id_for(artifact_type: str, value: str) -> Optional[str]:
    """Deterministic SCO id for the artifact behind a campaign."""
    if artifact_type == "malware":
        return generate_file_id(value)
    if artifact_type in ("ssh-key", "hassh", "ja3"):
        return generate_cryptographic_key_id(value)
    return None


def emit_campaigns(
    state: CycleState, builder: STIXBuilder, cycle_keys: list[str]
) -> list[dict]:
    """Materialise / extend Campaigns for artifacts that crossed the
    ``MIN_CAMPAIGN_MEMBERS`` threshold this cycle.

    For each candidate artifact_key shared by >= 2 distinct IPs with at least
    one not-yet-published member, emits the Campaign SDO, an
    ``indicator -> indicates -> campaign`` edge per pending member, and a
    ``campaign -> related-to -> artifact-SCO`` edge. Idempotent via
    deterministic ids; ``emitted`` gating keeps popular artifacts from
    re-emitting every member every cycle.
    """
    out: list[dict] = []
    for key in sorted(set(cycle_keys)):
        try:
            rows = state.get_campaign_artifact_rows(key)
        except Exception as e:  # pragma: no cover — defensive
            logger.debug(f"campaigns.get_campaign_artifact_rows raised (ignored): {e}")
            continue
        if not rows:
            continue
        distinct_ips = {r["src_ip"] for r in rows}
        if len(distinct_ips) < MIN_CAMPAIGN_MEMBERS:
            continue
        pending = [r for r in rows if not r["emitted"]]
        if not pending:
            continue  # threshold met but nothing new to attach

        a_type = rows[0]["artifact_type"]
        defn = _CAMPAIGN_DEFS.get(a_type)
        if defn is None:
            continue
        value = rows[0]["artifact_value"]
        display = rows[0]["display"]
        first_seen = min(r["first_seen"] for r in rows)
        last_seen = max(r["last_seen"] for r in rows)

        camp = builder.build_campaign(
            artifact_key=key,
            name=defn["name"].format(display=display),
            description=defn["describe"].format(value=value, n=len(distinct_ips)),
            objective=defn["objective"],
            first_seen=first_seen,
            last_seen=last_seen,
            labels=defn["labels"],
        )
        # camp_id is deterministic, so edges resolve even if build_campaign
        # deduped the SDO to None (already emitted earlier in this bundle).
        camp_id = generate_campaign_id(key)
        if camp:
            out.append(camp)

        # Campaign → the concrete artifact SCO (File / Cryptographic-Key).
        if (sco_id := _sco_id_for(a_type, value)):
            if rel := builder.build_relationship(
                camp_id, "related-to", sco_id,
                description=f"Shared artifact defining this campaign: {display}",
            ):
                out.append(rel)

        # indicator(ip) → indicates → campaign, for each pending member.
        for r in pending:
            ind_id = attacker_ip_indicator_id(r["src_ip"])
            if rel := builder.build_relationship(
                ind_id, "indicates", camp_id,
                description=(
                    f"{r['src_ip']} attributed to this campaign via shared "
                    f"{a_type} {display}"
                ),
            ):
                out.append(rel)

        try:
            state.mark_campaign_members_emitted(key, [r["src_ip"] for r in pending])
        except Exception as e:  # pragma: no cover — defensive
            logger.debug(f"campaigns.mark_campaign_members_emitted raised (ignored): {e}")

        logger.info(
            f"campaign materialised: {key} — {len(distinct_ips)} IP(s), "
            f"+{len(pending)} new edge(s)"
        )
    return out
