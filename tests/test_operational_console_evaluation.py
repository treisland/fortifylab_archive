"""Deterministic operational-console browser gate and live-evidence boundary."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from manager.observable_evaluation import assert_artifact_safe, load
from manager.operational_console_evaluation import evaluate


ROOT = Path(__file__).resolve().parents[1]
EVALUATION_ROOT = ROOT / "evaluations" / "operational-console-browser-v0.4"
REQUIRED = {
    "progressive-partial-recovery", "capability-disabled-enabled",
    "component-inspector-desktop", "component-inspector-narrow",
    "quick-link-transitions", "lifecycle-plan-approval-progress",
    "lifecycle-cancel-fail-retry-restart", "telegram-audit-correlation",
    "protected-data-absence",
}


class OperationalConsoleEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = load(EVALUATION_ROOT / "scenarios.json")
        cls.observations = load(EVALUATION_ROOT / "observations.json")
        cls.live = load(EVALUATION_ROOT / "live-evidence.json")
        cls.live_schema = load(EVALUATION_ROOT / "live-evidence.schema.json")
        Draft202012Validator.check_schema(cls.live_schema)
        Draft202012Validator(
            cls.live_schema, format_checker=FormatChecker()
        ).validate(cls.live)

    def test_journeys_cover_exact_scope_and_both_viewports(self):
        self.assertEqual({item["id"] for item in self.suite["journeys"]}, REQUIRED)
        self.assertEqual(
            {item["viewport"] for item in self.suite["journeys"]},
            {"desktop", "narrow"},
        )
        self.assertEqual(
            self.suite["viewports"],
            {
                "desktop": {"width": 1440, "height": 1000},
                "narrow": {"width": 390, "height": 844},
            },
        )
        self.assertEqual(self.suite["scope"]["platform"], "single-node MicroK8s")
        self.assertEqual(self.suite["scope"]["aspm"], "excluded")
        for journey in self.suite["journeys"]:
            self.assertTrue(journey["command"].startswith("python3 -m unittest "))
            self.assertTrue(journey["expected"]["residualLimitation"])

    def test_artifacts_are_synthetic_bounded_and_secret_safe(self):
        for artifact in (self.suite, self.observations, self.live):
            assert_artifact_safe(artifact)
        serialized = json.dumps(
            [self.suite, self.observations, self.live], sort_keys=True
        ).lower()
        for prohibited in (
            "private key", "licensecontent", "credential=", "protectedpath",
            "rawlog", "screenshotdata",
        ):
            self.assertNotIn(prohibited, serialized)

    def test_deterministic_journeys_pass_but_live_gate_is_unavailable(self):
        result = evaluate(
            self.suite, self.observations, self.live,
            evaluated_at="2026-07-31T12:00:00Z",
        )
        self.assertEqual(result["deterministicBrowserEvidence"]["status"], "passed")
        self.assertEqual(result["liveEvidence"]["status"], "unavailable")
        self.assertEqual(result["status"], "failed")

    def test_changed_missing_or_unexpected_journey_blocks_gate(self):
        for mutation in ("changed", "missing", "unexpected"):
            observations = copy.deepcopy(self.observations)
            if mutation == "changed":
                observations["observedOutcomeDigests"]["quick-link-transitions"] = "0" * 64
            elif mutation == "missing":
                del observations["observedOutcomeDigests"]["quick-link-transitions"]
            else:
                observations["observedOutcomeDigests"]["unexpected"] = "0" * 64
            result = evaluate(
                self.suite, observations, self.live,
                evaluated_at="2026-07-31T12:00:00Z",
            )
            self.assertEqual(result["deterministicBrowserEvidence"]["status"], "failed")
            self.assertEqual(result["status"], "failed")

    def test_only_fresh_exact_profile_complete_authorized_evidence_passes(self):
        live = self._passing_live()
        Draft202012Validator(
            self.live_schema, format_checker=FormatChecker()
        ).validate(live)
        result = evaluate(
            self.suite, self.observations, live,
            evaluated_at="2026-07-31T12:00:00Z",
        )
        self.assertEqual(result["status"], "passed")

        for field, value, reason in (
            ("profileId", "wrong", "profile-mismatch"),
            ("platform", "other", "platform-mismatch"),
            ("expiresAt", "2026-07-31T11:59:59Z", "live-evidence-stale"),
            ("sanitizationCheck", "failed", "sanitization-check-incomplete"),
            ("telegramAuditCorrelation", "failed", "telegram-audit-correlation-incomplete"),
        ):
            changed = self._passing_live()
            changed[field] = value
            result = evaluate(
                self.suite, self.observations, changed,
                evaluated_at="2026-07-31T12:00:00Z",
            )
            self.assertIn(reason, result["liveEvidence"]["reasons"])
            self.assertEqual(result["status"], "failed")

    def test_incomplete_live_journey_set_fails_closed(self):
        live = self._passing_live()
        del live["journeyChecks"]["protected-data-absence"]
        result = evaluate(
            self.suite, self.observations, live,
            evaluated_at="2026-07-31T12:00:00Z",
        )
        self.assertIn("browser-journeys-incomplete", result["liveEvidence"]["reasons"])

    def _passing_live(self):
        return {
            "apiVersion": "fortifylab.io/evaluations/v1alpha1",
            "kind": "OperationalConsoleBrowserLiveEvidence",
            "status": "passed",
            "profileId": self.suite["requiredProfileId"],
            "platform": "single-node MicroK8s",
            "recordedAt": "2026-07-31T10:00:00Z",
            "expiresAt": "2026-08-07T10:00:00Z",
            "journeyChecks": {key: "passed" for key in REQUIRED},
            "sanitizationCheck": "passed",
            "telegramAuditCorrelation": "passed",
            "commands": ["Run the documented authorized browser evidence procedure."],
            "limitations": ["Single-node MicroK8s only; ASPM excluded."],
        }


if __name__ == "__main__":
    unittest.main()
