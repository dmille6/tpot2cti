"""Suricata alert-only query scope, and the accounting that makes it safe.

A query-side exclusion removes documents before any parser or counter sees
them. That is precisely the shape of this project's defining failure — data
that vanishes with nothing to show it ever existed — so the exclusion is only
acceptable while it is (a) provably equivalent to what the parser already
discards, and (b) counted.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tpot2cti.es_client import TpotESClient
from tpot2cti.parsers import dispatch
from tpot2cti.parsers.suricata import SuricataParser

S = datetime(2026, 8, 5, tzinfo=timezone.utc)
E = datetime(2026, 8, 5, 1, tzinfo=timezone.utc)


def _clauses(**kw):
    q = TpotESClient._build_query(S, E, kw.pop("ignore_types", None), **kw)
    return q["bool"].get("must_not", [])


def test_the_exclusion_is_off_unless_asked_for():
    assert _clauses() == []


def test_it_excludes_only_suricata_docs_lacking_an_alert():
    """Must not touch any other sensor, and must not exclude Suricata docs that
    DO have an alert — that would delete the detections we actually want."""
    mn = _clauses(suricata_alert_only=True)
    assert len(mn) == 1
    inner = mn[0]["bool"]
    assert inner["must"] == [{"term": {"type.keyword": "Suricata"}}]
    assert inner["must_not"] == [{"exists": {"field": "alert"}}]


def test_it_composes_with_ignore_types():
    mn = _clauses(ignore_types=["P0f"], suricata_alert_only=True)
    assert {"terms": {"type.keyword": ["P0f"]}} in mn
    assert any("bool" in c for c in mn)


def test_type_uses_the_keyword_subfield():
    """`type` is analyzed text in T-Pot's mapping — a term query on the bare
    field silently matches nothing, which once let 5,132 P0f docs/window
    through an ignore_types filter that looked correct."""
    inner = _clauses(suricata_alert_only=True)[0]["bool"]
    assert "type.keyword" in str(inner["must"])


# ── the equivalence this filter depends on ───────────────────────────────

def _doc(**kw):
    d = {"type": "Suricata", "src_ip": "198.51.100.21",
         "@timestamp": "2026-08-05T00:00:00.000Z", "t-pot_hostname": "sensor01"}
    d.update(kw)
    return d


@pytest.mark.parametrize("doc", [
    _doc(),                                   # no alert key at all
    _doc(event_type="flow", flow={"pkts": 2}),
    _doc(event_type="tls", tls={"ja3": {"hash": "abc"}}),
    _doc(event_type="fileinfo", fileinfo={"sha256": "a" * 64}),
    _doc(event_type="http", http={"url": "/x"}),
    _doc(alert={}),                           # present but empty dict
    _doc(alert=[]),                           # present but empty list
])
def test_every_doc_the_query_would_exclude_is_one_the_parser_already_drops(doc):
    """THE load-bearing invariant. If the parser ever starts extracting value
    from a doc with no `alert` — Suricata's `tls` JA3s were measured to have
    ZERO overlap with FATT's, so this is a live possibility — then the query
    filter must widen in the same change or that intelligence silently never
    arrives. This test fails the moment those diverge."""
    # Through dispatch(), NOT SuricataParser().parse(). The pipeline resolves
    # the parser from the registry, so a second parser registered for
    # "Suricata" would diverge from a directly-instantiated one while a test
    # calling the class stayed green — the guard has to watch the path the
    # data actually takes.
    assert dispatch(doc) is None, (
        "the pipeline now extracts something from a doc the ES query excludes "
        "— widen or remove suricata_alert_only in this same change"
    )


def test_the_guard_watches_the_registry_not_just_the_class():
    """Demonstrates the hole the previous version had: swapping the registered
    Suricata parser must break the guard. If it does not, the guard is
    watching a class nobody calls."""
    import tpot2cti.parsers as P

    class _Greedy(SuricataParser):
        def parse(self, doc):            # pretends to have learned tls/flow
            return "something"

    original = P.get_parser("Suricata")
    P.register(_Greedy())
    try:
        assert dispatch(_doc(event_type="tls")) is not None, \
            "registry swap did not take effect — this test proves nothing"
    finally:
        P.register(original)
    assert dispatch(_doc(event_type="tls")) is None


def test_a_malformed_alert_still_reaches_the_parser():
    """ES can only test EXISTENCE; the parser requires `alert` to be a dict.
    A doc with a non-dict `alert` is therefore NOT excluded by the query, and
    must remain visible as parser `unparsed` rather than disappearing."""
    mn = _clauses(suricata_alert_only=True)[0]["bool"]
    assert mn["must_not"] == [{"exists": {"field": "alert"}}]
    assert dispatch(_doc(alert="not-a-dict")) is None


def test_a_real_alert_is_untouched_by_both():
    doc = _doc(alert={"signature": "ET SCAN Zmap User-Agent (Inbound)",
                      "signature_id": 1, "category": "x", "severity": 2},
               src_port=4444, dest_port=22, dest_ip="192.0.2.3", proto="TCP")
    assert dispatch(doc) is not None
