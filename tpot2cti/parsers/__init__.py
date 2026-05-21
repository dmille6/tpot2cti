"""tpot2cti — parser registry.

Per V1_SPEC.md §3 (cycle behavior, step 2):

    2. Dispatch each doc to the right parser
       - by `type` field (Cowrie, Suricata, ConPot...)
       - unrecognized types → fallback parser

This module owns the dispatch.  Parsers self-register when their
module is imported by being subclasses of BaseParser with a non-empty
`type_name`.  The fallback parser handles anything unknown so we never
silently lose data — see V1_SPEC §5.24.

Usage:

    from tpot2cti.parsers import get_parser, dispatch

    # Get a specific parser by T-Pot type name
    p = get_parser("Cowrie")

    # Or dispatch a raw doc directly to the right parser
    event = dispatch(doc)
"""

from __future__ import annotations

import logging
from typing import Iterator, Optional

from .base import AttackSession, BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

# Map from T-Pot type_name → parser instance.  Populated by register().
_PARSERS: dict[str, BaseParser] = {}

# Sentinel for "no specific parser matched" — populated by the fallback
# parser at import time.
FALLBACK_KEY = "__fallback__"


def register(parser: BaseParser) -> None:
    """Register a parser instance under its `type_name`.

    Idempotent — re-registering the same type replaces the old instance.
    Subclasses of BaseParser typically call `register(MyParser())` at
    module bottom; or the parsers package's __init__ imports them
    explicitly and registers from there.
    """
    name = parser.type_name
    if not name:
        raise ValueError(
            f"Parser {type(parser).__name__} has no type_name; "
            f"subclasses MUST set type_name to T-Pot's `type` value."
        )
    if name in _PARSERS:
        logger.debug(f"re-registering parser for {name!r}")
    _PARSERS[name] = parser
    logger.debug(f"registered parser {type(parser).__name__} for type={name!r}")


def get_parser(type_name: str) -> Optional[BaseParser]:
    """Return the parser for a T-Pot `type` value, or the fallback.

    Returns None only if no fallback is registered (which is a setup
    bug — fallback registration is mandatory).
    """
    if type_name in _PARSERS:
        return _PARSERS[type_name]
    fb = _PARSERS.get(FALLBACK_KEY)
    if fb is None:
        logger.error(
            f"No parser for type={type_name!r} and no fallback registered. "
            f"This is a setup bug — register a FallbackParser at startup."
        )
    return fb


def registered_types() -> list[str]:
    """Return the list of T-Pot type_names that have dedicated parsers,
    excluding the fallback sentinel."""
    return sorted(k for k in _PARSERS.keys() if k != FALLBACK_KEY)


def dispatch(doc: dict) -> Optional[ParsedEvent]:
    """One-stop helper: pick the parser for a doc, run parse(), return
    the ParsedEvent (or None if the doc was malformed / skipped).

    Convenience for the importer's main loop.
    """
    type_name = doc.get("type") or ""
    parser = get_parser(str(type_name))
    if parser is None:
        return None
    try:
        return parser.parse(doc)
    except Exception as e:
        # Per V1_SPEC §7: "Parser exception on a single doc → caught +
        # logged at DEBUG; doc is skipped; cycle continues"
        logger.debug(
            f"parser {type(parser).__name__} raised on doc "
            f"_id={doc.get('_id')!r} type={type_name!r}: {e}"
        )
        return None


def parse_batch(docs: Iterator[dict]) -> Iterator[ParsedEvent]:
    """Parse an iterable of docs, yielding ParsedEvents (skipping None)."""
    for doc in docs:
        event = dispatch(doc)
        if event is not None:
            yield event


# ---------------------------------------------------------------------------
# Auto-import all parser modules so they self-register on package import
# ---------------------------------------------------------------------------

def _auto_register() -> None:
    """Import every sibling .py module that defines a parser, so the
    `register()` calls at the bottom of each parser module fire.

    This avoids forcing the importer's main loop to import each parser
    by name — just `import tpot2cti.parsers` and the registry is
    populated.
    """
    import importlib
    import pkgutil

    # Import every module in this package except base and __init__
    package_path = __path__  # noqa: F821 — provided by package __init__
    for mod_info in pkgutil.iter_modules(package_path):
        name = mod_info.name
        if name in ("base", "__init__"):
            continue
        try:
            importlib.import_module(f"{__name__}.{name}")
        except Exception as e:
            logger.warning(f"failed to auto-import parser module {name}: {e}")


# Trigger auto-registration at package import time.  Individual parser
# modules call `register(MyParser())` at their bottom.
_auto_register()


__all__ = [
    "AttackSession",
    "BaseParser",
    "FALLBACK_KEY",
    "ParsedEvent",
    "dispatch",
    "get_parser",
    "parse_batch",
    "register",
    "registered_types",
]
