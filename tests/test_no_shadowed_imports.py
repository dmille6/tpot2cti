"""No function-local import may shadow a module-level name.

This caused a ~5 hour v2 ingest outage on 2026-08-30. A
`from tpot2cti.log import restore_logging` was added inside an `if` block in
main(), and Python treats a name assigned ANYWHERE in a function as local to
the WHOLE function -- so the pre-existing `restore_logging()` call twenty
lines earlier became an unbound local and the connector crash-looped on
startup.

The cruel part: it only fired when the feature flag was OFF, because then
the shadowing import never executed and the name was never bound. The
"safe" default was the broken path.

All 1,010 tests passed throughout, because none of them exercise main()'s
startup. This is the cheap static check that would have caught it.
"""
from __future__ import annotations

import ast
import os

SRC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "tpot2cti")


def _module_level_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                names.add(a.asname or a.name.split(".")[0])
    return names


def _shadowing_imports(path: str):
    tree = ast.parse(open(path).read())
    top = _module_level_names(tree)
    bad = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for a in node.names:
                    nm = a.asname or a.name.split(".")[0]
                    if nm in top:
                        bad.append((fn.name, nm, node.lineno))
    return bad


def test_no_local_import_shadows_a_module_level_name():
    offenders = []
    for f in sorted(os.listdir(SRC_DIR)):
        if not f.endswith(".py"):
            continue
        for fn, nm, line in _shadowing_imports(os.path.join(SRC_DIR, f)):
            offenders.append(f"{f}:{line} function {fn}() re-imports {nm!r}")
    assert not offenders, (
        "a function-local import of a module-level name makes that name local "
        "to the WHOLE function, so any earlier use becomes an unbound local:\n  "
        + "\n  ".join(offenders)
    )


def test_the_specific_regression_is_gone():
    """restore_logging must be imported once, at module scope."""
    src = open(os.path.join(SRC_DIR, "main.py")).read()
    tree = ast.parse(src)
    top = _module_level_names(tree)
    assert "restore_logging" in top, "it belongs at module scope"
    assert not any(nm == "restore_logging"
                   for _, nm, _ in _shadowing_imports(os.path.join(SRC_DIR, "main.py"))), (
        "restore_logging is re-imported inside a function again — this is the "
        "exact shape that crash-looped the connector for 5 hours"
    )
