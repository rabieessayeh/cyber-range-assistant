"""The requirements table in docs/architecture.md must name tests that exist."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_requirement_table_references_existing_tests():
    doc = (ROOT / "docs" / "architecture.md").read_text(encoding="utf-8")
    rows = [line for line in doc.splitlines() if line.startswith("| REQ-")]
    assert [r.split("|")[1].strip() for r in rows] == [f"REQ-{i:02d}" for i in range(1, 13)]
    referenced = set(re.findall(r"`(test_\w+)`", "\n".join(rows)))
    defined = set()
    for path in (ROOT / "tests").glob("test_*.py"):
        defined |= set(re.findall(r"^def (test_\w+)", path.read_text(encoding="utf-8"), re.MULTILINE))
    assert referenced, "no tests referenced"
    assert referenced <= defined, f"unknown tests in docs: {sorted(referenced - defined)}"
