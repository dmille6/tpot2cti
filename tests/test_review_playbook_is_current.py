"""The playbook must not become the thing it warns about.

`docs/REVIEW_PLAYBOOK.md` §2 Q5 records that a document was trusted over the
code twice — `docs/EVIDENCE.md` §3.4 named a call site that had moved. A
playbook full of stale `file.py` references would be the same defect, so the
files it names are checked to still exist.

Deliberately checks FILES, not line numbers: line numbers churn on every edit
and a test that fails for cosmetic reasons gets deleted or muted, which is
worse than no test.
"""
from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
PLAYBOOK = REPO / "docs" / "REVIEW_PLAYBOOK.md"

# Bare filenames referenced in prose that are not repo paths.
# `.env` is not tracked. `setup.sh` IS a real repo file and used to be
# ignored here — codex caught that the playbook cites it as a concrete defect
# (the 88,404-iteration EOF loop), so the reference must be checked.
_IGNORE = {"main.py", ".env"}


def _referenced_paths() -> set[str]:
    text = PLAYBOOK.read_text()
    found = set()
    for m in re.finditer(r"`([A-Za-z0-9_./-]+\.(?:py|md|sh))(?::\d+)?`", text):
        p = m.group(1)
        if p.split("/")[-1] in _IGNORE and "/" not in p:
            continue
        found.add(p)
    return found


def test_the_playbook_exists_and_is_substantive():
    assert PLAYBOOK.exists()
    assert len(PLAYBOOK.read_text()) > 2000, "playbook has been gutted"


def test_every_file_the_playbook_names_still_exists():
    """A stale reference means the playbook is describing a codebase that no
    longer exists — exactly what it accuses docs/EVIDENCE.md of."""
    missing = []
    for rel in sorted(_referenced_paths()):
        candidates = [REPO / rel, REPO / "tpot2cti" / rel, REPO / "tests" / rel]
        if not any(c.exists() for c in candidates):
            missing.append(rel)
    assert not missing, f"playbook names files that no longer exist: {missing}"


def test_contributing_links_the_playbook():
    """A playbook nobody is pointed at is the defect class it documents."""
    c = (REPO / "docs" / "CONTRIBUTING.md").read_text()
    assert "REVIEW_PLAYBOOK" in c, "CONTRIBUTING.md no longer links the playbook"


def test_every_ranked_question_is_still_present():
    """The questions are ranked by what they actually found. Silently dropping
    one loses the evidence for why it is there."""
    text = PLAYBOOK.read_text()
    for q in ("Q1.", "Q2.", "Q3.", "Q4.", "Q5.", "Q6.", "Q7.", "Q8."):
        assert f"### {q}" in text, f"{q} was dropped from the playbook"


def test_the_admission_rule_survives():
    """Without it the file grows until nobody reads it."""
    assert "Admission rule" in PLAYBOOK.read_text()


def test_the_scoreboard_is_still_present():
    """Section 4 is the part that decides whether this file earns its keep. If
    it is dropped, the playbook becomes an unfalsifiable claim."""
    text = PLAYBOOK.read_text()
    assert "new-class" in text and "self-caught" in text, (
        "the finding-class scoreboard was removed — without it there is no "
        "way to tell whether the playbook works"
    )
    assert "Failure looks like" in text, (
        "the failure condition was removed, making the playbook an "
        "unfalsifiable claim"
    )
