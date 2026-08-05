"""The one rule: a refusal must never be recorded as an absence."""
from __future__ import annotations

import json
import urllib.error

import pytest

from tpot2cti.httpfetch import (
    USER_AGENT, FetchResult, MalformedBody, Outcome, fetch,
)


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


def test_an_unparseable_body_raises_rather_than_looking_like_absence():
    """A 200 carrying garbage is a source problem, not 'no record'.

    json() used to return None here, which made None ambiguous across FOUR
    meanings — genuine absence, empty body, unparseable body, literal null.
    The docstring told callers not to read that as absence, but the obvious
    idiom (`if r.json() is None: mark_not_found()`) did precisely that. A
    prose warning is not a type; this raises instead."""
    r = fetch("http://x", opener=_opener(_Resp(200, b"<html>rate limited</html>")))
    assert r.outcome is Outcome.OK and r.outcome is not Outcome.ABSENT
    with pytest.raises(MalformedBody):
        r.json()


def test_the_four_meanings_of_none_are_now_distinguishable():
    """Only genuine absence may return None from json()."""
    absent = fetch("http://x", opener=_opener(_Resp(404)))
    assert absent.outcome is Outcome.ABSENT
    assert absent.json() is None            # the ONLY None

    for body in (b"", b"<html>nope</html>"):
        r = fetch("http://x", opener=_opener(_Resp(200, body)))
        with pytest.raises(MalformedBody):
            r.json()

    # A literal JSON null is a real answer of "null", not an absence.
    r = fetch("http://x", opener=_opener(_Resp(200, b"null")))
    assert r.json() is None and r.outcome is Outcome.OK
    # ...distinguishable from absence by the outcome, which is the point.
    assert r.outcome is not Outcome.ABSENT


def test_json_on_a_refusal_raises_rather_than_returning_none():
    r = fetch("http://x", opener=_opener(_Resp(403)))
    assert r.outcome is Outcome.REFUSED
    with pytest.raises(MalformedBody):
        r.json()


# ── the mapping must be TOTAL ────────────────────────────────────────────

def test_a_truncated_body_is_transport_not_an_escaped_exception():
    """http.client.HTTPException is neither OSError nor ValueError. A server
    promising Content-Length: 1000 and closing after 5 bytes raises
    IncompleteRead out of resp.read(); it used to escape fetch() entirely,
    sail past refresh_lists' per-source isolation, and kill the whole cycle.
    A truncated feed download is not an exotic input."""
    import http.client
    exc = http.client.IncompleteRead(b"12345", 995)
    r = fetch("http://x", opener=_opener(exc))
    assert r.outcome is Outcome.TRANSPORT
    assert not r.is_answer


@pytest.mark.parametrize("exc", [
    __import__("http.client", fromlist=["x"]).BadStatusLine("oops"),
    __import__("http.client", fromlist=["x"]).LineTooLong("header line"),
    __import__("http.client", fromlist=["x"]).RemoteDisconnected("closed"),
])
def test_no_http_client_exception_escapes(exc):
    r = fetch("http://x", opener=_opener(exc))
    assert r.outcome is Outcome.TRANSPORT and not r.is_answer


def test_an_unforeseen_exception_is_transport_never_absence():
    """The backstop. A new urllib exception class must not silently become
    'the source has no record'."""
    class Weird(Exception):
        pass
    r = fetch("http://x", opener=_opener(Weird("something new")))
    assert r.outcome is Outcome.TRANSPORT
    assert r.outcome is not Outcome.ABSENT and not r.is_answer


def test_a_malformed_url_does_not_escape():
    """Request() raises ValueError('unknown url type') and used to be
    constructed outside the try."""
    r = fetch("not-a-url")
    assert r.outcome is Outcome.TRANSPORT and not r.is_answer


def test_absent_is_reachable_from_exactly_one_place():
    """The load-bearing invariant, asserted directly over the whole surface."""
    import http.client
    statuses = [200, 201, 204, 206, 301, 304, 400, 401, 403, 410, 418, 429,
                451, 500, 503, 999, None]
    for s in statuses:
        r = fetch("http://x", opener=_opener(_Resp(s, b"{}")))
        if s == 404:
            continue
        assert r.outcome is not Outcome.ABSENT, f"status {s} became ABSENT"
    for exc in (urllib.error.URLError("dns"), OSError("reset"),
                http.client.IncompleteRead(b"", 1), ValueError("bad"),
                urllib.error.HTTPError("http://x", 500, "e", {}, None)):
        r = fetch("http://x", opener=_opener(exc))
        assert r.outcome is not Outcome.ABSENT, f"{type(exc).__name__} became ABSENT"
    # positive control: 404 really does still reach it
    assert fetch("http://x", opener=_opener(_Resp(404))).outcome is Outcome.ABSENT


def test_a_refusal_logs_loudly_on_the_non_raising_path_too(caplog):
    """The loud log lived only in the `except HTTPError` branch, so an opener
    returning 403 instead of raising was classified REFUSED in silence."""
    import logging
    with caplog.at_level(logging.ERROR):
        r = fetch("http://x", opener=_opener(_Resp(403)))
    assert r.outcome is Outcome.REFUSED
    assert any("REFUSED" in rec.message for rec in caplog.records)


def test_the_timeout_actually_reaches_the_opener():
    """Nothing asserted this, so deleting `timeout=timeout` left all tests
    green — while a missing timeout hangs the entire pipeline."""
    seen = {}
    def _open(req, timeout=None):
        seen["timeout"] = timeout
        return _Resp(200, b"{}")
    fetch("http://x", timeout=7.5, opener=_open)
    assert seen["timeout"] == 7.5
