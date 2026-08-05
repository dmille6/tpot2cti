"""Fixtures must not leak real infrastructure — including inside base64.

This repo is public. Fixtures are real captured documents, sanitised to the
TEST-NET convention (RFC 5737) before being committed.

The sanitisation procedure had a systematic hole: it rewrote plaintext IP
fields and never looked inside encoded payloads. A honeypot's own address
survived in a base64 `payload` field for exactly that reason, and a manual
review would not have caught it either — the value is opaque to the eye.

So the check runs here, decoding rather than reading.
"""
from __future__ import annotations

import base64
import glob
import re

import pytest

#: RFC 5737 documentation ranges — the only addresses fixtures may contain.
ALLOWED_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
#: Not addresses, but equally identifying.
FORBIDDEN_STRINGS = re.compile(r"(?i)examplecorp|digitalplumbing|\bctihost\b")

_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_B64 = re.compile(r'"([A-Za-z0-9+/]{16,}={0,2})"')


def _fixture_files() -> list[str]:
    return sorted(p for p in glob.glob("tests/fixtures/**/*", recursive=True)
                  if p.endswith((".json", ".jsonl")))


def _decoded_blobs(line: str) -> str:
    """Every base64-looking value in the line, decoded and concatenated."""
    out = []
    for token in _B64.findall(line):
        try:
            out.append(base64.b64decode(token).decode("utf-8", "replace"))
        except Exception:
            continue
    return "\n".join(out)


def test_there_are_fixtures_to_check():
    """Guard the guard: a glob that silently matches nothing would make every
    assertion below vacuously true."""
    assert len(_fixture_files()) >= 5


@pytest.mark.parametrize("path", _fixture_files())
def test_no_real_address_or_identifier_in_any_fixture(path):
    for n, line in enumerate(open(path, errors="replace"), 1):
        if not line.strip():
            continue
        for source, text in (("plaintext", line), ("base64", _decoded_blobs(line))):
            if not text:
                continue
            leaked = sorted({
                ip for ip in _IP.findall(text)
                if not ip.startswith(ALLOWED_PREFIXES)
                # 0.* and 255.255.* appear as masks/placeholders, not hosts
                and not ip.startswith(("0.", "255.255"))
            })
            assert not leaked, (
                f"{path}:{n} leaks {leaked} in {source}. Fixtures may only "
                f"contain RFC 5737 documentation addresses {ALLOWED_PREFIXES}."
            )
            found = FORBIDDEN_STRINGS.findall(text)
            assert not found, f"{path}:{n} leaks identifier {found} in {source}"
