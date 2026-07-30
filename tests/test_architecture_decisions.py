"""Regression checks for the foundational architecture decision set."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "docs" / "architecture.md"
ADR_DIRECTORY = ROOT / "docs" / "adr"
FOUNDATIONAL_ADRS = tuple(range(1, 10))


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

    def test_manager_runtime_boundary_is_explicit_and_fail_closed(self) -> None:
        document = ADR_DIRECTORY / "0009-manager-runtime-boundary.md"
        content = document.read_text(encoding="utf-8")
        normalized_content = " ".join(content.split())

        required_contracts = (
            "/api/v1alpha1",
            "POST /api/v1alpha1/session",
            "apiVersion",
            "SQLite",
            "server-side session",
            "loopback-only",
            "SameSite=Strict",
            "dedicated ServiceAccount",
            "`get`, `list`, and `watch` only",
            "no access to `secrets`",
            "SSC remains the application-security system of record",
            "Follow-up implementation stays in ordered GitHub issues",
        )
        for contract in required_contracts:
            with self.subTest(contract=contract):
                self.assertIn(contract, normalized_content)

        forbidden_capabilities = (
            "There is no raw Kubernetes proxy",
            "browser-triggered install",
            "It does not store secret values",
            "It is neither a ClusterRole",
        )
        for capability in forbidden_capabilities:
            with self.subTest(capability=capability):
                self.assertIn(capability, normalized_content)


if __name__ == "__main__":
    unittest.main()
