"""Release-gate coverage for the bounded Autonomous supervisor fixtures."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "evaluations" / "autonomous-supervisor-v0.4" / "scenarios.json"


class AutonomousSupervisorEvaluationTests(unittest.TestCase):
    def test_required_fail_closed_scenarios_are_versioned(self) -> None:
        suite = json.loads(SUITE.read_text(encoding="utf-8"))
        self.assertEqual(suite["kind"], "AutonomousSupervisorSuite")
        self.assertEqual(
            {scenario["id"] for scenario in suite["scenarios"]},
            {
                "eligible-exact-head", "missing-required-check", "merge-conflict",
                "changes-requested", "secret-scan-finding", "sensitive-scope",
                "changed-head-race", "restart-active-lease", "expired-lease",
                "telegram-outage", "emergency-hold", "duplicate-merge-progression",
            },
        )
        self.assertFalse(suite["scope"]["liveMutation"])
        self.assertEqual(suite["scope"]["aspm"], "excluded")


if __name__ == "__main__":
    unittest.main()
