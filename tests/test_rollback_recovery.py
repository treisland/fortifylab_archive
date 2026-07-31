"""Static rollback/recovery drill and cross-surface contract coverage."""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLASSES = {"reversible", "compensating-action", "restore-required", "irreversible"}


class RollbackRecoveryDrillTests(unittest.TestCase):
    def test_required_drills_are_explicit_and_never_claim_live_execution(self):
        document = json.loads(
            (ROOT / "evaluations/rollback-recovery-v0.4/drills.json").read_text()
        )
        self.assertFalse(document["liveClusterExecuted"])
        drills = document["drills"]
        self.assertEqual(
            {item["id"] for item in drills},
            {"ssc-migration-failure", "dast-migration-timeout",
             "database-upgrade-cancellation", "ingress-chart-failure",
             "certificate-compensation"},
        )
        self.assertTrue(all(item["recoveryClass"] in CLASSES for item in drills))
        self.assertTrue(all(item["unsupportedClaim"] for item in drills))

    def test_api_ui_telegram_and_docs_present_the_boundary(self):
        self.assertIn(
            "recoveryClass",
            (ROOT / "manager/web/assets/dashboard.js").read_text(),
        )
        self.assertIn(
            "Rollback boundary:",
            (ROOT / "manager/remote_actions.py").read_text(),
        )
        self.assertIn("recoveryClass", (ROOT / "docs/api.md").read_text())
        operator = (
            ROOT / "docs/operations/rollback-recovery.md"
        ).read_text()
        self.assertTrue(all(value in operator for value in CLASSES))


if __name__ == "__main__":
    unittest.main()
