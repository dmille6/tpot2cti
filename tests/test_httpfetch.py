"""The one rule: a refusal must never be recorded as an absence."""
from __future__ import annotations

import json
import urllib.error

import pytest

from tpot2cti.httpfetch import USER_AGENT, FetchResult, Outcome, fetch


class _Resp:
    def __init__(self, status, body=b""):
        self.status, self._body = status, body
    def read(self): return self._body
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _opener(result, capture=None):
    def _open(req, timeout=None):
        if capture is not None:
            capture.append(req)
        if isinstance(result, Exception):
            raise result
        return result
    return _open


# ── the distinction that matters ─────────────────────────────────────────

@pytest.mark.parametrize("status,expected", [
    (200, Outcome.OK),
    (404, Outcome.ABSENT),
    (401, Outcome.REFUSED),
    (403, Outcome.REFUSED),
    (429, Outcome.THROTTLED),
    (500, Outcome.UNAVAILABLE),
    (503, Outcome.UNAVAILABLE),
])
def test_status_codes_classify_into_answers_and_non_answers(status, expected):
    r = fetch("http://x", opener=_opener(_Resp(status, b"{}")))
    assert r.outcome is expected


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_a_non_answer_is_never_an_answer(status):
    """The load-bearing assertion. Shodan's InternetDB returns 403 to Python's
    default User-Agent — measured, the first 100 addresses were all 403. A
    lookup mapping 'non-200 -> not_found' would record 100% not-found, publish
    nothing, advance its cursor and report healthy. `is_answer` is what makes
    that mistake impossible to write by accident."""
    r = fetch("http://x", opener=_opener(_Resp(status)))
    assert r.is_answer is False
    assert r.outcome is not Outcome.ABSENT


def test_only_absent_and_ok_are_answers():
    assert Outcome.ABSENT.is_answer and Outcome.OK.is_answer
    for o in (Outcome.REFUSED, Outcome.THROTTLED, Outcome.UNAVAILABLE,
              Outcome.TRANSPORT):
        assert not o.is_answer, f"{o} must not count as data"


def test_httperror_is_classified_the_same_as_a_status(caplog):
    """urllib raises for 4xx/5xx rather than returning them, so both paths must
    classify identically or the meaning depends on how the library felt."""
    exc = urllib.error.HTTPError("http://x", 403, "Forbidden", {}, None)
    r = fetch("http://x", opener=_opener(exc))
    assert r.outcome is Outcome.REFUSED and not r.is_answer


def test_a_refusal_is_logged_loudly(caplog):
    """The most likely cause is a request-side mistake we can fix, and silence
    here is what lets it run for weeks."""
    import logging
    exc = urllib.error.HTTPError("http://x", 403, "Forbidden", {}, None)
    with caplog.at_level(logging.ERROR):
        fetch("http://x", opener=_opener(exc))
    assert any("REFUSED" in r.message for r in caplog.records)


# ── transport ────────────────────────────────────────────────────────────

def test_transport_failure_is_not_absence():
    r = fetch("http://x", opener=_opener(urllib.error.URLError("dns dead")))
    assert r.outcome is Outcome.TRANSPORT and not r.is_answer


# ── the header that caused all this ──────────────────────────────────────

def test_a_real_user_agent_is_always_sent():
    """The default urllib UA is refused outright by a source we depend on."""
    seen = []
    fetch("http://x", opener=_opener(_Resp(200, b"{}"), capture=seen))
    ua = seen[0].get_header("User-agent")
    assert ua == USER_AGENT
    assert "urllib" not in ua.lower() and "python" not in ua.lower()


def test_callers_may_override_headers_without_losing_the_user_agent():
    seen = []
    fetch("http://x", headers={"X-Key": "abc"},
          opener=_opener(_Resp(200, b"{}"), capture=seen))
    assert seen[0].get_header("X-key") == "abc"
    assert seen[0].get_header("User-agent") == USER_AGENT


# ── body handling ────────────────────────────────────────────────────────

def test_json_parses_only_on_ok():
    ok = fetch("http://x", opener=_opener(_Resp(200, json.dumps({"a": 1}).encode())))
    assert ok.json() == {"a": 1}
    absent = fetch("http://x", opener=_opener(_Resp(404)))
    assert absent.json() is None


def test_an_unparseable_body_is_not_silently_absence():
    """A 200 carrying garbage is a source problem, not 'no record'. json()
    returning None is a convenience — is_answer still says we got a reply, and
    the caller must not translate that into absence."""
    r = fetch("http://x", opener=_opener(_Resp(200, b"<html>rate limited</html>")))
    assert r.outcome is Outcome.OK and r.json() is None
    assert r.outcome is not Outcome.ABSENT
