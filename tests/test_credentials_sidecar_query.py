"""Regression: the credentials sidecar must query `type.keyword`.

The sidecar (`tpot2cti-credentials/`) silently collected ZERO credentials for
weeks because it filtered on the analyzed `type` field with capitalized values
("Cowrie", …), which matches nothing. Its own smoke test used a FakeES that
ignored the query, so the bug was invisible. This test loads the sidecar's
dependency-free query builder directly and pins the field name.
"""
from __future__ import annotations

import importlib.util
from datetime import datetime, timezone
from pathlib import Path

_QUERY_PY = (
    Path(__file__).resolve().parent.parent
    / "tpot2cti-credentials" / "query.py"
)


def _load_build_query():
    spec = importlib.util.spec_from_file_location("_creds_sidecar_query", _QUERY_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_credential_query


def test_credential_query_uses_type_keyword():
    build = _load_build_query()
    start = datetime(2026, 8, 4, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 8, 4, 1, 0, tzinfo=timezone.utc)
    q = build(["Cowrie", "Heralding", "Mailoney", "Sentrypeer"], start, end)

    terms = [m for m in q["bool"]["must"] if "terms" in m]
    assert terms, "query must have a terms filter for the honeypot type"
    type_terms = terms[0]["terms"]
    # The whole point: keyed on `type.keyword`, NOT the analyzed `type`.
    assert "type.keyword" in type_terms, (
        f"credential sidecar must filter on `type.keyword` (analyzed `type` "
        f"matches nothing for capitalized values); got {list(type_terms)}"
    )
    assert "type" not in type_terms
    assert type_terms["type.keyword"] == ["Cowrie", "Heralding", "Mailoney", "Sentrypeer"]
