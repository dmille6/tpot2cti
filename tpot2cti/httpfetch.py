"""Shared HTTP fetch for enrichment sources, with one rule enforced by type.

**"We were refused" must never be recorded as "the dataset has no answer."**

That distinction is the whole point of this module. Shodan's InternetDB returns
**403 to Python's default `User-Agent`** (`Python-urllib/3.x`) and 200 to any
real one — measured, first 100 addresses all 403. A per-object lookup that maps
"non-200 → not_found" would therefore record 100% not-found, publish nothing,
advance its cursor and report healthy. One omitted header, and the module is
this project's signature failure mode in its purest form.

The failure is invisible precisely because "not found" is a *legitimate,
expected, common* answer — roughly half of Shodan lookups genuinely miss. There
is no anomaly to notice.

So callers do not get a status code to interpret. They get an `Outcome`, and
only `Outcome.ABSENT` means "this source has no record". Everything else —
refusal, throttling, server error, transport failure — is explicitly *not* an
answer, must not be cached as one, and must not advance any cursor as though
work completed.
"""
from __future__ import annotations

import enum
import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)

#: A real, identifying User-Agent. NOT cosmetic: the default urllib UA is
#: refused outright by at least one source we depend on, and being identifiable
#: is also the courteous thing when querying volunteer-run infrastructure.
USER_AGENT = "tpot2cti/2.0 (+https://github.com/dmille6/tpot2cti)"

DEFAULT_TIMEOUT = 20.0


class Outcome(enum.Enum):
    """What a fetch actually established.

    Only ABSENT is an answer about the *data*. The rest are statements about
    the *request*, and conflating the two is the bug this type exists to make
    impossible.
    """

    OK = "ok"                    #: 200 with a usable body
    ABSENT = "absent"            #: 404 — the source genuinely has no record
    REFUSED = "refused"          #: 401/403 — auth, UA, or policy rejection
    THROTTLED = "throttled"      #: 429 — slow down, try later
    UNAVAILABLE = "unavailable"  #: 5xx — the source is broken, not us
    TRANSPORT = "transport"      #: DNS/TCP/TLS/timeout — never reached them

    @property
    def is_answer(self) -> bool:
        """True only when the source actually told us something about the data."""
        return self in (Outcome.OK, Outcome.ABSENT)


@dataclass(frozen=True)
class FetchResult:
    outcome: Outcome
    status: Optional[int] = None
    body: Optional[bytes] = None
    detail: str = ""

    @property
    def is_answer(self) -> bool:
        return self.outcome.is_answer

    def json(self) -> Any:
        """Parsed body, or None. A body that will not parse is NOT an answer —
        callers should check `is_answer` first; this returning None on garbage
        is a convenience, not permission to treat it as absence."""
        if self.outcome is not Outcome.OK or not self.body:
            return None
        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return None


_STATUS_MAP = {
    404: Outcome.ABSENT,
    401: Outcome.REFUSED,
    403: Outcome.REFUSED,
    429: Outcome.THROTTLED,
}


def fetch(url: str, *, timeout: float = DEFAULT_TIMEOUT,
          headers: Optional[dict] = None, opener=None) -> FetchResult:
    """GET `url`, classifying the result so refusal cannot pass as absence."""
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    _open = opener or urllib.request.urlopen
    try:
        with _open(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or getattr(resp, "code", None)
            body = resp.read()
            if status == 200:
                return FetchResult(Outcome.OK, status, body)
            mapped = _STATUS_MAP.get(status)
            if mapped is not None:
                return FetchResult(mapped, status, None, f"HTTP {status}")
            if status and 500 <= status < 600:
                return FetchResult(Outcome.UNAVAILABLE, status, None, f"HTTP {status}")
            # Any other 2xx/3xx that is not a plain 200: not an error, but not
            # something to parse as data either.
            return FetchResult(Outcome.UNAVAILABLE, status, None,
                               f"unexpected HTTP {status}")
    except urllib.error.HTTPError as exc:
        status = exc.code
        mapped = _STATUS_MAP.get(status)
        if mapped is Outcome.REFUSED:
            # Loud, because the most likely cause is a request-side mistake we
            # can fix — and because silently recording it as "no data" is
            # exactly the failure this module exists to prevent.
            logger.error(
                "fetch REFUSED by %s (HTTP %s). This is NOT 'no data': check the "
                "User-Agent and any credentials. Recording it as absence would "
                "publish nothing while reporting healthy.", url, status)
        if mapped is not None:
            return FetchResult(mapped, status, None, f"HTTP {status}")
        if 500 <= status < 600:
            return FetchResult(Outcome.UNAVAILABLE, status, None, f"HTTP {status}")
        return FetchResult(Outcome.UNAVAILABLE, status, None, f"HTTP {status}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return FetchResult(Outcome.TRANSPORT, None, None, str(exc))
