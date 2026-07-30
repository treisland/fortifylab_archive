"""Regression checks for the foundational architecture decision set."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "docs" / "architecture.md"
ADR_DIRECTORY = ROOT / "docs" / "adr"
FOUNDATIONAL_ADRS = tuple(range(1, 9))


class ArchitectureDecisionTests(unittest.TestCase):
    def test_index_links_every_accepted_foundational_decision(self) -> None:
        index = INDEX.read_text(encoding="utf-8")
        for number in FOUNDATIONAL_ADRS:
            matches = list(ADR_DIRECTORY.glob(f"{number:04d}-*.md"))
            self.assertEqual(len(matches), 1, number)
            relative_target = f"adr/{matches[0].name}"
            self.assertIn(f"]({relative_target})", index)

    def test_foundational_decisions_have_required_sections(self) -> None:
        required_headings = (
            "## Context",
            "## Decision",
            "## Consequences",
            "## Security and operational implications",
            "## Compatibility and migration",
            "## Related decisions",
        )
        for number in FOUNDATIONAL_ADRS[1:]:
            document = next(ADR_DIRECTORY.glob(f"{number:04d}-*.md"))
            content = document.read_text(encoding="utf-8")
            with self.subTest(adr=document.name):
                self.assertIn("- Status: Accepted", content)
                self.assertRegex(
                    content, r"## (?:Considered alternatives|Alternatives)"
                )
                for heading in required_headings:
                    self.assertIn(heading, content)

    def test_index_keeps_implementation_tasks_in_issues(self) -> None:
        index = INDEX.read_text(encoding="utf-8")
        self.assertIn("Follow-up implementation work belongs in GitHub issues", index)
        for document in ADR_DIRECTORY.glob("*.md"):
            content = document.read_text(encoding="utf-8")
            task_lines = re.findall(r"(?m)^\s*[-*]\s+\[[ xX]\]\s+", content)
            self.assertEqual(task_lines, [], document.name)


if __name__ == "__main__":
    unittest.main()
