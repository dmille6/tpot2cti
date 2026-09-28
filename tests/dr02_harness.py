"""Deterministic bundle harness for the DR-02 evidence-gate tests.

Not a test module (no ``test_`` prefix): it builds two bundles from fixed
inputs so a flag state can be compared BYTE FOR BYTE against the output the
code produced before the gate existed.

  * ``cycle_bundle`` drives one real ``run_cycle`` over every sanitized
    fixture in ``tests/fixtures/real`` (src_ip remapped to routable space,
    exactly as ``test_run_cycle_integration`` does), with a fake ES whose
    ``daily_event_counts`` returns one authoritative count, and a capturing
    publisher.
  * ``direct_bundle`` calls the five builder methods that carry a
    ``build_dual_sighting`` call site (Cowrie, Suricata, Honeytrap, fallback,
    drive-by) directly, so a site the cycle's ``_is_bare_scan`` gate would
    skip (Honeytrap with no payload, the fallback) is still exercised.

``tests/fixtures/dr02/golden_digests.json`` holds the SHA-256 (and object
count) of both bundles as serialized by :func:`serialize`, produced by
``PYTHONPATH=. python -m tests.dr02_harness --write`` on a clean checkout of
origin/main 71e47ec, BEFORE any DR-02 code existed. Digests, not the
bundles themselves: the cycle remaps fixture addresses into routable space
(the self-filter drops documentation ranges), and routable addresses may
not be committed under tests/fixtures (test_fixture_sanitisation).

To see WHAT differs after a mismatch, write both bundles out and diff:
``python -m tests.dr02_harness --dump DIR`` here and on origin/main.
Regenerate the digests only when an intended output change lands, and say
so in the commit.
"""
from __future__ import annotations

import copy
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from tpot2cti.parsers.base import _smoketest_env

_smoketest_env()

import tpot2cti.parsers as P  # noqa: E402
from tpot2cti.config import load_config  # noqa: E402
from tpot2cti.main import run_cycle  # noqa: E402
from tpot2cti.state import CycleState  # noqa: E402
from tpot2cti.stix.builder import STIXBuilder  # noqa: E402

REAL = Path(__file__).parent / "fixtures" / "real"
GOLDEN_DIR = Path(__file__).parent / "fixtures" / "dr02"
GOLDEN_DIGESTS = GOLDEN_DIR / "golden_digests.json"

FIXED_NOW = datetime(2026, 3, 11, 0, 0, tzinfo=timezone.utc)
FIXED_ISO = FIXED_NOW.isoformat()

#: The one (src_ip, sensor, day) the fake ES reports an authoritative daily
#: count for: the fixture address with Cowrie AND Suricata on sensor03.
AUTH_ORIG_IP = "203.0.113.6"
AUTH_COUNT = 4242


def public_ip(n: int) -> str:
    """Same mapping as test_run_cycle_integration._public_ip."""
    return f"45.9.{(n // 254) % 254}.{(n % 254) + 1}"


def load_cycle_docs() -> tuple[list[dict], dict[str, str]]:
    """Every real fixture doc, src_ip remapped to a stable public address."""
    ip_map: dict[str, str] = {}
    docs: list[dict] = []
    for path in sorted(REAL.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            orig = d.get("src_ip")
            if orig:
                if orig not in ip_map:
                    ip_map[orig] = public_ip(len(ip_map))
                d["src_ip"] = ip_map[orig]
            docs.append(d)
    return docs, ip_map


class FakeES:
    """The three calls run_cycle makes, with the index pattern recorded."""

    def __init__(self, docs: list[dict], daily: dict):
        self._docs = docs
        self._daily = daily
        self.stream_patterns: list[str] = []
        self.count_patterns: list[str] = []
        self.daily_patterns: list[str] = []

    def stream_events(self, start, end, **kwargs):
        self.stream_patterns.append(kwargs.get("index_pattern"))
        yield from self._docs

    def count_events(self, start, end, **kwargs):
        self.count_patterns.append(kwargs.get("index_pattern"))
        return len(self._docs)

    def daily_event_counts(self, day_start, upper, index_pattern="logstash-*",
                           ignore_types=None, **kwargs):
        self.daily_patterns.append(index_pattern)
        return dict(self._daily)


class CapturingPublisher:
    def __init__(self):
        self.objects: list[dict] = []

    def publish(self, objects, cycle_id=None):
        self.objects = list(objects)
        return SimpleNamespace(cycle_id=cycle_id, pass_counts={}, errors=[])


#: The goldens predate the own-surface provenance split (2026-09-28), which
#: deliberately stops emitting inbound request targets. The harness pins the
#: legacy switch ON so DR-02's byte-identity contract stays checkable
#: against the same golden; tests/test_own_surface_personas.py compares
#: the default (switch off) against this legacy bundle by subtraction. Pass
#: {LEGACY_INBOUND: "false"} to get today's default.
LEGACY_INBOUND = "TPOT2CTI_INBOUND_REQUEST_OBSERVABLES"


def make_cfg(env_overrides: dict | None = None):
    env = dict(os.environ)
    for k in list(env):
        # A stray flag in the developer's shell must not leak into a golden.
        if k.startswith("TPOT2CTI_EVIDENCE") or k.startswith("TPOT2CTI_SIGHTING") \
                or k == "TPOT2CTI_COUNTS_INDEX_PATTERN" or k == LEGACY_INBOUND:
            env.pop(k)
    env[LEGACY_INBOUND] = "true"
    env.update(env_overrides or {})
    return load_config(env_dict=env)


def _fixed_builder(cfg):
    b = STIXBuilder(cfg)
    b._now_iso = FIXED_ISO
    return b


def cycle_bundle(tmp_dir: Path, env_overrides: dict | None = None):
    """Run one cycle; return (objects, summary, fake_es, state)."""
    cfg = make_cfg(env_overrides)
    docs, ip_map = load_cycle_docs()
    daily = {(ip_map[AUTH_ORIG_IP], "sensor03", "2026-03-07"): AUTH_COUNT}
    es = FakeES(docs, daily)
    state = CycleState(db_path=Path(tmp_dir) / "state.db")
    pub = CapturingPublisher()
    summary = run_cycle(cfg, state, es, lambda: _fixed_builder(cfg), pub,
                        now=FIXED_NOW)
    return pub.objects, summary, es, state


# ---------------------------------------------------------------------------
# Direct builder calls: one session per dual-sighting call site
# ---------------------------------------------------------------------------

DIRECT_IP = "45.10.0.1"      # Cowrie + Suricata + drive-by, same sensor/day
DIRECT_IP_HT = "45.10.0.2"   # Honeytrap
DIRECT_IP_FB = "45.10.0.3"   # fallback
DIRECT_IP_V6 = "2a01:4f8::1"  # drive-by over IPv6
DIRECT_SENSOR = "sensorA"
DIRECT_DAY = "2026-03-07"


def _first_doc(name: str, pred=lambda d: True) -> dict:
    for line in (REAL / name).read_text(encoding="utf-8").splitlines():
        if line.strip():
            d = json.loads(line)
            if pred(d):
                return d
    raise AssertionError(f"no matching doc in {name}")


def _retarget(doc: dict, ip: str, hhmm: str, day: str = DIRECT_DAY) -> dict:
    d = copy.deepcopy(doc)
    d["src_ip"] = ip
    d["t-pot_hostname"] = DIRECT_SENSOR
    d["@timestamp"] = f"{day}T{hhmm}:00.000Z"
    return d


def _sessions(type_name: str, docs: list[dict]):
    parser = P.get_parser(type_name)
    evs = [e for e in (parser.parse(d) for d in docs) if e is not None]
    assert evs, f"{type_name}: fixture produced no events"
    return parser.correlate(evs)


def direct_sessions() -> list[tuple[str, object]]:
    """(builder method, session) pairs, in build order."""
    out: list[tuple[str, object]] = []
    cowrie_docs = [json.loads(l) for l in
                   (REAL / "cowrie.jsonl").read_text(encoding="utf-8").splitlines()
                   if l.strip()]
    # The rich 8-event Cowrie session, moved to DIRECT_IP.
    rich = [d for d in cowrie_docs if d.get("src_ip") == "203.0.113.6"]
    rich = [_retarget(d, DIRECT_IP, f"10:{i:02d}") for i, d in enumerate(rich)]
    for s in _sessions("Cowrie", rich):
        out.append(("build_cowrie_session", s))
    # The same address the next day (a second day bucket).
    nxt = [_retarget(d, DIRECT_IP, f"09:{i:02d}", day="2026-03-08")
           for i, d in enumerate([d for d in cowrie_docs
                                  if d.get("src_ip") == "203.0.113.6"])]
    for s in _sessions("Cowrie", nxt):
        out.append(("build_cowrie_session", s))
    sur = _first_doc("suricata.jsonl", lambda d: d.get("alert"))
    for s in _sessions("Suricata", [_retarget(sur, DIRECT_IP, "11:00")]):
        out.append(("build_suricata_alert", s))
    ht = _first_doc("honeytrap.jsonl")
    for s in _sessions("Honeytrap", [_retarget(ht, DIRECT_IP_HT, "12:00")]):
        out.append(("build_honeytrap_probe", s))
    fb = _retarget(_first_doc("heralding.jsonl"), DIRECT_IP_FB, "13:00")
    fb["type"] = "Xyzpot"
    for s in _sessions("__fallback__", [fb]):
        out.append(("build_fallback_event", s))
    her = _first_doc("heralding.jsonl")
    for s in _sessions("Heralding", [_retarget(her, DIRECT_IP, "14:00")]):
        out.append(("build_driveby_session", s))
    for s in _sessions("Heralding", [_retarget(her, DIRECT_IP_V6, "15:00")]):
        out.append(("build_driveby_session", s))
    return out


def direct_bundle(env_overrides: dict | None = None, *, builder=None):
    """Build every direct session through its dual-sighting site."""
    cfg = make_cfg(env_overrides)
    b = builder or _fixed_builder(cfg)
    b.daily_event_counts = {(DIRECT_IP_HT, DIRECT_SENSOR, DIRECT_DAY): 77}
    objs: list[dict] = []
    for method, session in direct_sessions():
        with b.session_context(session):
            objs.extend(getattr(b, method)(session))
    return objs, b


def serialize(objs: list[dict]) -> bytes:
    """Order-preserving, key-order-preserving: what the publisher receives."""
    return json.dumps(objs, ensure_ascii=False).encode("utf-8")


def digest(objs: list[dict]) -> dict:
    import hashlib
    raw = serialize(objs)
    return {"sha256": hashlib.sha256(raw).hexdigest(), "objects": len(objs),
            "bytes": len(raw)}


def golden() -> dict:
    return json.loads(GOLDEN_DIGESTS.read_text(encoding="utf-8"))


def _default_bundles() -> tuple[list[dict], list[dict]]:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        objs, *_ = cycle_bundle(Path(td))
    d_objs, _ = direct_bundle()
    return objs, d_objs


def _write_goldens(source: str) -> None:
    objs, d_objs = _default_bundles()
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    GOLDEN_DIGESTS.write_text(json.dumps({
        "generated_from": source,
        "cycle": digest(objs),
        "direct": digest(d_objs),
    }, indent=2) + "\n", encoding="utf-8")
    print(GOLDEN_DIGESTS.read_text())


def _dump(out_dir: str) -> None:
    objs, d_objs = _default_bundles()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "cycle_bundle.json").write_bytes(serialize(objs))
    (out / "direct_bundle.json").write_bytes(serialize(d_objs))
    print(json.dumps({"cycle": digest(objs), "direct": digest(d_objs)}, indent=2))


if __name__ == "__main__":
    if "--write" in sys.argv:
        src = sys.argv[sys.argv.index("--write") + 1] \
            if len(sys.argv) > sys.argv.index("--write") + 1 else "unspecified"
        _write_goldens(src)
    elif "--dump" in sys.argv:
        _dump(sys.argv[sys.argv.index("--dump") + 1])
    else:
        print("usage: python -m tests.dr02_harness --write SOURCE | --dump DIR")
