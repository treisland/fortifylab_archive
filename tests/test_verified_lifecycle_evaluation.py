"""Milestone 0.4 deterministic and separately authorized live-evidence gate."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from manager.observable_evaluation import assert_artifact_safe, load
from manager.verified_lifecycle_evaluation import evaluate


ROOT = Path(__file__).resolve().parents[1]
EVALUATION_ROOT = ROOT / "evaluations" / "verified-platform-lifecycle-v0.4"
REQUIRED_SCENARIOS = {
    "connected-inventory", "degraded-read-model", "layered-health",
    "clean-install", "dependency-ordering", "cancellation", "retry",
    "backup-restore", "upgrade", "rollback-boundary", "service-restart",
    "protected-input-boundary",
}


class VerifiedLifecycleEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.suite = load(EVALUATION_ROOT / "scenarios.json")
        cls.observations = load(EVALUATION_ROOT / "observations.json")
        cls.live = load(EVALUATION_ROOT / "live-evidence.json")
        cls.schema = load(EVALUATION_ROOT / "schema.json")
        cls.live_schema = load(EVALUATION_ROOT / "live-evidence.schema.json")
        for schema in (cls.schema, cls.live_schema):
            Draft202012Validator.check_schema(schema)
        Draft202012Validator(cls.schema).validate(cls.suite)
        Draft202012Validator(
            cls.live_schema, format_checker=FormatChecker()
        ).validate(cls.live)

    def test_required_deterministic_scenarios_are_complete_and_reproducible(self):
        scenarios = self.suite["scenarios"]
        self.assertEqual({item["id"] for item in scenarios}, REQUIRED_SCENARIOS)
        self.assertEqual(len(scenarios), len(REQUIRED_SCENARIOS))
        for scenario in scenarios:
            with self.subTest(scenario=scenario["id"]):
                self.assertTrue(scenario["command"].startswith("python3 -m unittest "))
                self.assertTrue(scenario["expectedOutcome"])
                self.assertTrue(scenario["expected"]["residualLimitation"])
                self.assertEqual(scenario["evidence"], "deterministic-fixture")

    def test_browser_acceptance_is_machine_checkable_in_every_scenario(self):
        for scenario in self.suite["scenarios"]:
            expected = scenario["expected"]
            self.assertTrue(expected["actualClusterState"])
            self.assertTrue(expected["primaryRootCause"])
            self.assertIsInstance(expected["blockedConsumers"], list)
            self.assertTrue(expected["remediation"])

    def test_artifacts_are_bounded_synthetic_and_exclude_aspm(self):
        self.assertEqual(self.suite["scope"]["platform"], "single-node MicroK8s")
        self.assertEqual(self.suite["scope"]["aspm"], "excluded")
        for artifact in (self.suite, self.observations, self.live):
            assert_artifact_safe(artifact)
        serialized = json.dumps(
            [self.suite, self.observations, self.live], sort_keys=True
        ).lower()
        for prohibited in (
            "credential=", "licensecontent", "private key", "rawlog",
            "protectedpath",
        ):
            self.assertNotIn(prohibited, serialized)

    def test_checked_in_gate_fails_because_live_evidence_is_missing(self):
        result = evaluate(
            self.suite, self.observations, self.live,
            evaluated_at="2026-07-31T12:00:00Z",
        )
        self.assertEqual(result["deterministicEvidence"]["status"], "passed")
        self.assertEqual(result["liveEvidence"]["status"], "failed")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            result["liveEvidence"]["reasons"], ["live-evidence-not-passed"]
        )

    def test_missing_changed_and_unexpected_fixture_evidence_fail(self):
        for mutation in ("missing", "changed", "unexpected"):
            observations = copy.deepcopy(self.observations)
            if mutation == "missing":
                del observations["observedOutcomeDigests"]["retry"]
            elif mutation == "changed":
                observations["observedOutcomeDigests"]["retry"] = "0" * 64
            else:
                observations["observedOutcomeDigests"]["unexpected"] = "0" * 64
            result = evaluate(
                self.suite, observations, self.live,
                evaluated_at="2026-07-31T12:00:00Z",
            )
            self.assertEqual(result["deterministicEvidence"]["status"], "failed")
            self.assertEqual(result["status"], "failed")

    def test_fresh_verified_exact_profile_live_evidence_passes(self):
        live = self._passing_live()
        Draft202012Validator(
            self.live_schema, format_checker=FormatChecker()
        ).validate(live)
        result = evaluate(
            self.suite, self.observations, live,
            evaluated_at="2026-07-31T12:00:00Z",
        )
        self.assertEqual(result["liveEvidence"]["status"], "passed")
        self.assertEqual(result["status"], "passed")

    def test_stale_or_unverified_or_wrong_profile_live_evidence_fails(self):
        cases = (
            ("stale", {"expiresAt": "2026-07-31T11:59:59Z"}, "live-evidence-stale"),
            ("unverified", {"profileVerification": "unverified"}, "profile-unverified"),
            ("wrong-profile", {"profileId": "other-profile"}, "profile-mismatch"),
        )
        for name, changes, reason in cases:
            with self.subTest(name=name):
                live = self._passing_live()
                live.update(changes)
                result = evaluate(
                    self.suite, self.observations, live,
                    evaluated_at="2026-07-31T12:00:00Z",
                )
                self.assertEqual(result["status"], "failed")
                self.assertIn(reason, result["liveEvidence"]["reasons"])

    def test_incomplete_lifecycle_or_browser_checks_fail_closed(self):
        for field, key, reason in (
            ("checks", "retry", "lifecycle-checks-incomplete"),
            ("browserChecks", "blockedConsumers", "browser-checks-incomplete"),
        ):
            live = self._passing_live()
            del live[field][key]
            result = evaluate(
                self.suite, self.observations, live,
                evaluated_at="2026-07-31T12:00:00Z",
            )
            self.assertIn(reason, result["liveEvidence"]["reasons"])
            self.assertEqual(result["status"], "failed")

    def _passing_live(self):
        return {
            "apiVersion": "fortifylab.io/evaluations/v1alpha1",
            "kind": "VerifiedPlatformLifecycleLiveEvidence",
            "status": "passed",
            "profileId": self.suite["requiredProfileId"],
            "profileVerification": "verified",
            "platform": "single-node MicroK8s",
            "recordedAt": "2026-07-31T10:00:00Z",
            "expiresAt": "2026-08-07T10:00:00Z",
            "checks": {
                key: "passed" for key in (
                    "cleanInstall", "dependencyOrdering", "cancellation", "retry",
                    "backupRestore", "upgrade", "rollbackBoundary",
                    "serviceRestart", "secretSafety",
                )
            },
            "browserChecks": {
                key: "passed" for key in (
                    "actualClusterState", "primaryRootCause", "blockedConsumers",
                    "actionableRemediation",
                )
            },
            "commands": ["Use the documented fixed evaluation commands."],
            "limitations": ["Single-node MicroK8s only; ASPM excluded."],
        }


if __name__ == "__main__":
    unittest.main()
