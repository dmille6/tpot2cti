"""Every deduping builder must be reachable through an `_emit_*` wrapper.

WHY THIS IS A TEST AND NOT A REVIEW CHECKLIST
---------------------------------------------
`_dedup` returns None for "already emitted in this bundle". `build_*` methods
also return None for "never emit this". A caller writing `if obj:` conflates
them and silently drops every later session's edge to a shared node.

That defect has now been found three separate times, each time by someone
reading code and noticing:

  PR #43  Process only.
  PR #44  eight more types, found by working a review's list.
  this    three more (cryptographic-key, attacker SSH key, IP indicator) that
          the list did not contain.

Each round was believed complete when it landed. Reviewing harder is clearly
not what closes this — the sites nobody lists are exactly the ones nobody
finds. So the question "is the sweep complete?" is asked here, mechanically,
against the AST, and a new deduping builder that nobody wrapped fails the
build instead of quietly losing edges in production.

Adding a builder to ALLOWED is a deliberate act that costs you a written
reason. That is the point.
"""
from __future__ import annotations

import ast
import pathlib

BUILDER = pathlib.Path(__file__).resolve().parents[1] / "tpot2cti" / "stix" / "builder.py"

#: Deduping builders that legitimately have no `_emit_*` wrapper.
#: Key = method name, value = why. Both are read by a human in review.
ALLOWED = {
    # Relationships and Sightings ARE the edges. Dedup here means "this exact
    # edge is already in the bundle", which is genuinely nothing to add --
    # there is no second endpoint whose per-session identity is being lost.
    "build_relationship": "the edge itself; a duplicate edge is nothing to add",
    "build_sighting": "same — the sighting IS the observation",

    # Nodes whose every inbound edge is IDENTICAL across the sessions that
    # share them. IPv4 -> Country is the same triple no matter which session
    # produced it, so build_relationship dedups it anyway and the second
    # session's 'loss' is not a loss. Re-check this claim if any of these ever
    # gain a per-session property on the EDGE (a timestamp, a count, a sensor).
    "build_country_location": "IP->country edge is identical across sessions",
    "build_city_location": "IP->city edge is identical across sessions",
    "build_autonomous_system": "IP->ASN edge is identical across sessions",
    "build_sensor_identity": "sensor edges are per-sensor, not per-session",

    # Ids are already per-session or per-IP-per-period, so two calls in one
    # bundle mean genuinely the same object, not two attackers sharing one.
    "build_session_note": "id is per-session; a duplicate is the same session",
    "build_ip_credential_note": "id is per-IP rolling note; upsert by design",
    "build_campaign": "id is per-artifact; membership is on the edges",
}


def _dedup_builders_and_wrappers():
    tree = ast.parse(BUILDER.read_text())
    cls = next(n for n in tree.body
               if isinstance(n, ast.ClassDef) and n.name == "STIXBuilder")
    dedupers, wrappers = set(), set()
    for fn in cls.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        if fn.name.startswith("_emit_"):
            wrappers.add(fn.name)
        calls = {n.func.attr for n in ast.walk(fn)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        if "_dedup" in calls and fn.name.startswith("build_"):
            dedupers.add(fn.name)
    return dedupers, wrappers


def test_every_deduping_builder_is_wrapped_or_explicitly_excused():
    dedupers, wrappers = _dedup_builders_and_wrappers()
    assert dedupers, "guard: found no deduping builders — the AST walk is broken"

    unwrapped = {
        b for b in dedupers
        if b not in ALLOWED and f"_emit_{b[len('build_'):]}" not in wrappers
    }
    assert not unwrapped, (
        "these builders go through _dedup but have no _emit_* wrapper and no "
        f"entry in ALLOWED: {sorted(unwrapped)}\n\n"
        "A caller doing `obj = self.build_x(...)` then `if obj:` will silently "
        "drop the per-session edge for every session after the first that "
        "shares this node. Either add an _emit_x wrapper (see _emit_node), or "
        "add it to ALLOWED with a reason it cannot lose an edge."
    )


def test_the_allowlist_has_no_stale_entries():
    """An excuse for a builder that no longer dedups is a lie left in the file."""
    dedupers, _ = _dedup_builders_and_wrappers()
    stale = set(ALLOWED) - dedupers
    assert not stale, (
        f"ALLOWED excuses builders that no longer go through _dedup: "
        f"{sorted(stale)} — delete the entries"
    )


def test_every_wrapper_wraps_something_real():
    """A wrapper whose builder was renamed anchors on nothing."""
    dedupers, wrappers = _dedup_builders_and_wrappers()
    # _emit_node is the primitive, not a typed wrapper.
    typed = {w for w in wrappers if w != "_emit_node"}
    orphans = {w for w in typed if f"build_{w[len('_emit_'):]}" not in dedupers}
    assert not orphans, (
        f"these _emit_* wrappers have no matching deduping build_*: "
        f"{sorted(orphans)}"
    )
