"""Robust env-var parsing helpers.

Ported from /home/mike/poc/tsec-tpot-connectors/shared/tsec_env.py — see
PoC LESSONS_LEARNED §38 (the "docker --env-file inline-comment footgun")
for the motivating bug.

Why this exists
---------------
The lazy pattern `os.environ.get("X", "false").lower() == "true"` is
fragile under two real-world inputs that are common in our setup
flow:

1. **Inline `#` comments in `.env` lines.** Docker's `--env-file`
   parser does NOT strip `#`-comments. A line like

       TPOT2CTI_DRY_RUN=true   # set during smoke tests

   becomes the literal value ``"true   # set during smoke tests"``,
   which fails the `.lower() == "true"` check and silently does the
   wrong thing. `set -a; source .env` strips comments correctly, but
   any `docker run --env-file` invocation does not.

2. **Operator-typed values that don't match exactly "true" / "false":**
   ``True``, ``TRUE``, ``yes``, ``Yes``, ``1``, ``on``, etc.

`truthy_env()` is permissive on both axes: it strips inline `#`
comments, trims whitespace, lowercases, and accepts any of
``{true, 1, yes, on, y, t}``.

Usage
-----
::

    from tpot2cti.env import truthy_env, falsey_env

    if truthy_env("TPOT2CTI_DRY_RUN", default=False):
        ...

    if falsey_env("TPOT2CTI_PUBLISH_ENABLED", default=True):
        ...   # negated default: disabled only on explicit false
"""

from __future__ import annotations

import os
from typing import Optional


_TRUTHY = frozenset({"true", "1", "yes", "on", "y", "t"})
_FALSY = frozenset({"false", "0", "no", "off", "n", "f"})
# Note: the empty string is INTENTIONALLY not in _FALSY. `FOO=` (empty
# value) is treated as "unset" and falls back to the caller's default.
# This avoids the subtle case where an operator clears a var via
# `unset FOO; FOO=` expecting the default to kick in, and instead gets
# a hard False.


def truthy_env(name: str, default: bool = False) -> bool:
    """Parse an env var as a boolean, robust to whitespace + inline `#`.

    Args:
        name:    The environment variable name.
        default: Returned if the var is unset, empty, or unrecognized.

    Returns:
        True  if value ∈ {true, 1, yes, on, y, t} (case + space insensitive,
              after stripping any trailing ``# ...`` comment)
        False if value ∈ {false, 0, no, off, n, f}    (likewise)
        ``default`` otherwise
    """
    return truthy_str(os.environ.get(name), default)


def falsey_env(name: str, default: bool = True) -> bool:
    """Negated form of :func:`truthy_env` — useful for kill-switch reads
    where the natural language is "X disabled = True, X enabled = False"."""
    return not truthy_env(name, default=not default)


def truthy_str(raw: Optional[str], default: bool) -> bool:
    """Pure-function form for testing without env-var side effects.

    Strips a trailing ``# <comment>`` if present, then lowercases +
    trims whitespace before matching against the truthy/falsy sets.
    """
    if raw is None:
        return default
    # Strip inline `# comment` (PoC LESSONS §38 footgun).
    s = raw.split("#", 1)[0].strip().lower()
    if s in _TRUTHY:
        return True
    if s in _FALSY:
        return False
    return default


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Truthy values
    assert truthy_str("true", False) is True
    assert truthy_str("TRUE", False) is True
    assert truthy_str("1", False) is True
    assert truthy_str("yes", False) is True
    assert truthy_str("on", False) is True
    assert truthy_str("y", False) is True
    assert truthy_str("t", False) is True
    # Falsy
    assert truthy_str("false", True) is False
    assert truthy_str("0", True) is False
    assert truthy_str("no", True) is False
    assert truthy_str("off", True) is False
    # Whitespace
    assert truthy_str("  true  ", False) is True
    assert truthy_str("\tfalse\n", True) is False
    # Inline comment stripping (the PoC bug)
    assert truthy_str("true   # master switch", False) is True
    assert truthy_str("false  # disabled for soak", True) is False
    assert truthy_str("1 # numeric", False) is True
    # Empty / unset → default
    assert truthy_str("", True) is True
    assert truthy_str(None, True) is True
    assert truthy_str("", False) is False
    # Garbage → default
    assert truthy_str("maybe", True) is True
    assert truthy_str("maybe", False) is False
    # falsey_env semantics (the convenience wrapper)
    os.environ["FOO"] = "true"
    assert falsey_env("FOO", default=True) is False
    os.environ["FOO"] = "false"
    assert falsey_env("FOO", default=True) is True
    os.environ.pop("FOO", None)
    assert falsey_env("FOO", default=True) is True
    print("OK")
