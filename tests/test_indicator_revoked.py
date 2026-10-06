"""Attacker-IP indicators carry revoked=false so a re-sighting un-revokes them
(OpenCTI decay manager disabled 2026-10-06; our valid_until governs)."""
from __future__ import annotations

from tests.test_cowrie_url_hosts import _build, _session


def test_attacker_ip_indicator_is_explicitly_not_revoked_and_has_validity():
    objs = _build(_session(["uname -a"]))
    inds = [o for o in objs if o["type"] == "indicator" and "ipv4-addr:value = '1.2.3.4'" in o.get("pattern", "")]
    assert inds, "attacker IP indicator missing"
    assert inds[0]["revoked"] is False
    assert inds[0]["valid_until"] > inds[0]["valid_from"]
