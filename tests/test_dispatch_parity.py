"""Dispatch-parity guard — the single most important test in this scaffold.

Three lookup tables MUST agree on the set of T-Pot honeypot types:

  - ``tpot2cti.parsers._PARSERS`` — what we can actually parse
  - ``tpot2cti.stix.builder._PARSER_LABEL_VOCAB`` — Indicator/Observable
    labels for the OpenCTI UI
  - ``tpot2cti.stix.builder._INDICATOR_NAME_TEMPLATES`` — Indicator names
    rendered on the Indicator detail page

When the parser registry adds a row that label_vocab/name_templates
miss, the new parser's emissions land at the generic "Honeypot Attacker"
fallback name (commit 42fde6a — 40 fallback indicators bug).  Operators
can't filter, search, or pivot on parser type from the UI.

This test would have caught 42fde6a.  Keep it loud and assertive.
"""

from __future__ import annotations

import tpot2cti.parsers as P
from tpot2cti.stix.builder import (
    _INDICATOR_NAME_TEMPLATES,
    _PARSER_LABEL_VOCAB,
)


def _registry_types() -> set[str]:
    return set(P.registered_types()) | {P.FALLBACK_KEY}


def test_label_vocab_covers_every_registered_parser():
    """Every parser in the registry has a row in _PARSER_LABEL_VOCAB.

    Drift here means new honeypots get tagged with bare type-names
    lowercased — losing the protocol-family slug analysts filter on.
    """
    missing = _registry_types() - set(_PARSER_LABEL_VOCAB)
    assert not missing, (
        f"_PARSER_LABEL_VOCAB is missing rows for: {sorted(missing)}.  "
        f"Add (parser-slug, protocol-family) tuples in stix/builder.py."
    )


def test_indicator_name_templates_cover_every_registered_parser():
    """Every parser in the registry has a row in _INDICATOR_NAME_TEMPLATES.

    Drift here is the 42fde6a regression: new parsers' indicators get
    named "Honeypot Attacker - <ip>" instead of "Cowrie SSH/Telnet
    Attack - <ip>".  Caught here BEFORE the bundle is built.
    """
    missing = _registry_types() - set(_INDICATOR_NAME_TEMPLATES)
    assert not missing, (
        f"_INDICATOR_NAME_TEMPLATES is missing rows for: {sorted(missing)}.  "
        f"Add a template in stix/builder.py — see commit 42fde6a."
    )


def test_label_vocab_and_name_templates_are_in_sync():
    """The two tables MUST list the same parser keys.

    They are added together at parser-registration time and they MUST
    stay together.  A diff here means either was edited without the
    other.
    """
    vocab = set(_PARSER_LABEL_VOCAB)
    templates = set(_INDICATOR_NAME_TEMPLATES)
    assert vocab == templates, (
        f"_PARSER_LABEL_VOCAB vs _INDICATOR_NAME_TEMPLATES drift: "
        f"only-in-vocab={sorted(vocab - templates)}, "
        f"only-in-templates={sorted(templates - vocab)}"
    )


def test_no_extraneous_rows_in_label_vocab():
    """A row in label_vocab with no matching parser is dead code — flag it."""
    extra = set(_PARSER_LABEL_VOCAB) - _registry_types()
    assert not extra, (
        f"_PARSER_LABEL_VOCAB has stale rows with no matching parser: "
        f"{sorted(extra)}.  Either land the parser or remove the row."
    )
