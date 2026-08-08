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
  round 3 three more (cryptographic-key, attacker SSH key, IP indicator) that
          the list did not contain — found by sweeping the file.
  round 4 four more (country, city, ASN, ipv4) — round 3 had EXCUSED the geo
          nodes in this very file on the false claim that their inbound edges
          are identical across sessions. They are not: the edge source is the
          attacker's IP, so different attackers in one country produce
          different edges to a shared node, which is precisely the defect.

Each round was believed complete when it landed. Reviewing harder is clearly
not what closes this — the sites nobody lists are exactly the ones nobody
finds. So the question "is the sweep complete?" is asked here, mechanically,
against the AST, and a new deduping builder that nobody wrapped fails the
build instead of quietly losing edges in production.

Round 4 also broke the first version of THIS test, in two ways worth keeping
in mind before trusting it:

  * It looked for a literal `self._dedup(...)` call, so it missed builders
    that dedup through a helper — build_ipv4 returns
    _build_ip_observable(...), which is what dedups. The walk below follows
    RETURN values through helpers instead.
  * An allowlist entry is a claim about behaviour, and a wrong one is worse
    than no test: it tells the next reader the question was already asked and
    answered. Every entry states what would have to change for it to stop
    being true.

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

    # Sensor identity: sightings reference the DETERMINISTIC sensor id
    # directly rather than the returned object, so nothing is gated on it.
    # Stops being true if any caller starts doing `if sensor:` before an edge.
    "build_sensor_identity": "callers use the deterministic id, not the object",

    # The attacker's OWN address. Every edge out of build_attacker_context is
    # keyed on this same IP (located-at country/city, belongs-to ASN), so a
    # duplicate really is the identical set of edges and build_relationship
    # dedups them. Contrast build_ipv4 / build_referenced_ipv4, which describe
    # an address the attacker POINTED AT — there the other endpoint varies per
    # session, which is why those are wrapped. Stops being true if
    # build_attacker_context ever emits an edge whose other end is
    # per-session (a sighting, a timestamped edge, a sensor).
    "build_ip_observable": "attacker's own IP; all its edges are IP-keyed",

    # No callers. Kept because build_ip_indicator handles v6 attackers and a
    # v6 observable will be wanted; wrap it the moment it gains a caller.
    "build_ipv6": "no callers today",

    # Ids are already per-session or per-IP-per-period, so two calls in one
    # bundle mean genuinely the same object, not two attackers sharing one.
    "build_session_note": "id is per-session; a duplicate is the same session",
    "build_ip_credential_note": "id is per-IP rolling note; upsert by design",
    "build_campaign": "id is per-artifact; membership is on the edges",
}


def _dedup_builders_and_wrappers():
    """(builders whose RETURN value is deduped, _emit_* wrappers).

    "Returns a deduped object" is the property that matters — not "calls
    _dedup somewhere". A builder that merely calls another builder internally
    (every session builder does) is not itself ambiguous; a builder that
    RETURNS what _dedup returned is. Following return values through helpers
    is what catches build_ipv4 -> _build_ip_observable -> _dedup, which a
    direct-call check misses.
    """
    tree = ast.parse(BUILDER.read_text())
    cls = next(n for n in tree.body
               if isinstance(n, ast.ClassDef) and n.name == "STIXBuilder")
    fns = {f.name: f for f in cls.body if isinstance(f, ast.FunctionDef)}

    def returns_deduped(name, seen=None):
        seen = seen if seen is not None else set()
        if name in seen or name not in fns:
            return False
        seen.add(name)
        for node in ast.walk(fns[name]):
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            v = node.value
            if isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute):
                if v.func.attr == "_dedup":
                    return True
                if returns_deduped(v.func.attr, seen):
                    return True
        return False

    dedupers = {n for n in fns if n.startswith("build_") and returns_deduped(n)}
    wrappers = {n for n in fns if n.startswith("_emit_")}
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
