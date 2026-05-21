"""Credential extraction from T-Pot ES documents.

Per V1_SPEC §8.1: filter on ``type in {Cowrie, Heralding, Mailoney,
SentryPeer}``, extract ``(username, password, sensor, src_ip,
timestamp)``. Skip any document missing one of those fields.

T-Pot's logstash maps the username/password into different field names
per honeypot:

  Cowrie     ->  ``username`` + ``password``
  Heralding  ->  ``username`` + ``password`` (also under ``user`` /
                 ``passwd`` in older builds)
  Mailoney   ->  ``username`` + ``password``
  SentryPeer ->  ``source_user`` + ``source_password`` (it's a SIP
                 honeypot, fields are named differently)

We try the well-known fields and fall through to the cross-cutting
schema in V1_SPEC Appendix A.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CredentialEvent:
    username: str
    password: str
    sensor: str
    src_ip: str
    timestamp: datetime


def _parse_ts(value: Any) -> datetime | None:
    """Parse an ES ``@timestamp`` string into an aware UTC datetime."""
    if not value:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        # ES returns ISO 8601 like "2026-05-21T12:34:56.789Z" or
        # "...+00:00". Python's fromisoformat doesn't accept "Z" before
        # 3.11; we substitute it.
        s = value.replace("Z", "+00:00")
        try:
            ts = datetime.fromisoformat(s)
        except ValueError:
            return None
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts
    return None


def _pick_field(doc: dict[str, Any], *names: str) -> str | None:
    """Return the first non-empty string value for any of ``names``."""
    for n in names:
        v = doc.get(n)
        if isinstance(v, str) and v:
            return v
    return None


def extract_credential(doc: dict[str, Any]) -> CredentialEvent | None:
    """Try to extract a CredentialEvent from one ES ``_source`` dict.

    Returns ``None`` if the doc is the wrong type, the doc lacks one
    of the required fields, or any value fails validation. The caller
    logs DEBUG and continues — per V1_SPEC §8.1 error-handling policy.
    """
    honeypot_type = doc.get("type")
    if not isinstance(honeypot_type, str):
        return None

    username = _pick_field(doc, "username", "user", "source_user")
    password = _pick_field(doc, "password", "passwd", "source_password")
    sensor = _pick_field(doc, "sensor", "t-pot_hostname", "host")
    src_ip = _pick_field(doc, "src_ip", "src_addr", "source_ip", "remote_addr")
    timestamp = _parse_ts(doc.get("@timestamp") or doc.get("timestamp"))

    missing = []
    if not username: missing.append("username")
    if password is None: missing.append("password")  # empty string IS valid
    if not sensor: missing.append("sensor")
    if not src_ip: missing.append("src_ip")
    if not timestamp: missing.append("timestamp")
    if missing:
        logger.debug("extract_credential: skipping %s doc missing %s", honeypot_type, missing)
        return None

    return CredentialEvent(
        username=username,
        password=password or "",
        sensor=sensor,
        src_ip=src_ip,
        timestamp=timestamp,
    )
