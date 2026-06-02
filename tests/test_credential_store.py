"""CredentialStore — bulk credential attempts stay in SQLite, not OpenCTI.

Pins the aggregation behavior the per-IP Note relies on: repeat pairs
collapse onto counters (a 10k-attempt bruteforce ≠ 10k rows), success is
tracked, and get_ip_credentials() returns one row per (pair, service, port)
for the attacker IP.
"""

from __future__ import annotations

from tpot2cti.credential_store import CredentialStore


def _store(tmp_path):
    return CredentialStore(str(tmp_path / "creds.db"))


def test_repeat_pairs_collapse_to_counters(tmp_path):
    s = _store(tmp_path)
    n = 400                                    # stand-in for a 10k+ bruteforce
    # NOTE: per-attempt commit is slow at scale — the cycle wiring will
    # batch writes in one transaction (see docs/credential-store.md TODO).
    for _ in range(n):
        s.record_attempt("root", "toor", attacker_ip="1.2.3.4",
                         honeypot_name="node1", honeypot_type="Cowrie",
                         service="ssh", port=22)
    rows = s.get_ip_credentials("1.2.3.4")
    assert len(rows) == 1                      # one row, not n
    assert rows[0]["attempts"] == n
    assert rows[0]["succeeded"] is False


def test_success_flagged(tmp_path):
    s = _store(tmp_path)
    s.record_attempt("admin", "wrong", attacker_ip="5.6.7.8",
                     honeypot_name="n", honeypot_type="Cowrie",
                     service="ssh", port=22, success=False)
    s.record_attempt("admin", "letmein", attacker_ip="5.6.7.8",
                     honeypot_name="n", honeypot_type="Cowrie",
                     service="ssh", port=22, success=True)
    rows = {(r["username"], r["password"]): r for r in s.get_ip_credentials("5.6.7.8")}
    assert rows[("admin", "wrong")]["succeeded"] is False
    assert rows[("admin", "letmein")]["succeeded"] is True


def test_separates_by_ip(tmp_path):
    s = _store(tmp_path)
    s.record_attempt("root", "a", attacker_ip="1.1.1.1", honeypot_name="n",
                     honeypot_type="Cowrie", service="ssh", port=22)
    s.record_attempt("root", "b", attacker_ip="2.2.2.2", honeypot_name="n",
                     honeypot_type="Cowrie", service="ssh", port=22)
    assert len(s.get_ip_credentials("1.1.1.1")) == 1
    assert len(s.get_ip_credentials("2.2.2.2")) == 1
    assert s.get_ip_credentials("9.9.9.9") == []


def test_empty_password_handled(tmp_path):
    s = _store(tmp_path)
    s.record_attempt("guest", "", attacker_ip="3.3.3.3", honeypot_name="n",
                     honeypot_type="Heralding", service="vnc", port=5900)
    rows = s.get_ip_credentials("3.3.3.3")
    assert len(rows) == 1 and rows[0]["password"] == ""
