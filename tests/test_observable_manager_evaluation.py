"""Release-gate tests for the 0.2 observable-manager vertical slice."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from manager.observable_evaluation import (
    assert_artifact_safe,
    digest,
    evaluate,
    load,
)
from manager.runner_heartbeat import PHASES, TERMINAL_PHASES


ROOT = Path(__file__).resolve().parents[1]
EVALUATION_ROOT = ROOT / "evaluations" / "observable-manager-v0.2"
REQUIRED_SCENARIOS = {
    "clean-install-remote-login",
    "healthy-complete-lab",
    "mysql-blocks-consumers",
    "postgresql-lim-block-dast",
    "infrastructure-degradation",
    "missing-external-license",
    "restart-history-continuity",
    "disconnected-cluster",
    "runner-phase-transitions",
    "long-quiet-command-classification",
    "stall-and-recovery-classifications",
    "adaptive-heartbeat-cadence",
    "approval-required-actions",
    "quiet-hours-watch-policy",
    "monitor-overlap-restart",
    "telegram-outage-recovery",
    "details-message-visibility",
    "stop-callback-security",
    "cross-surface-redaction",
    "api-ui-read-only-redaction",
}


class ObservableManagerEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = load(EVALUATION_ROOT / "schema.json")
        cls.suite = load(EVALUATION_ROOT / "scenarios.json")
        cls.observations = load(EVALUATION_ROOT / "observations.json")
        cls.recorded = load(EVALUATION_ROOT / "recorded-result.json")
        Draft202012Validator.check_schema(cls.schema)
        Draft202012Validator(cls.schema).validate(cls.suite)

    def test_required_scenarios_are_unique_and_complete(self) -> None:
        identifiers = [scenario["id"] for scenario in self.suite["scenarios"]]
        self.assertEqual(set(identifiers), REQUIRED_SCENARIOS)
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertEqual(
            {scenario["area"] for scenario in self.suite["scenarios"]},
            {"manager", "health", "workflow", "telegram", "security"},
        )

    def test_every_scenario_has_explicit_cross_surface_outcomes(self) -> None:
        required = {
            "health",
            "heartbeat",
            "event",
            "api",
            "ui",
            "telegram",
            "diagnostics",
            "remediation",
            "workflowAuthorization",
        }
        for scenario in self.suite["scenarios"]:
            with self.subTest(scenario=scenario["id"]):
                self.assertEqual(set(scenario["expected"]), required)

    def test_fixture_artifacts_are_bounded_and_fail_closed(self) -> None:
        assert_artifact_safe(self.suite)
        assert_artifact_safe(self.observations)
        assert_artifact_safe(self.recorded)
        for prohibited in self.suite["artifactPolicy"]["forbidden"]:
            self.assertNotIn(prohibited, json.dumps(self.observations).lower())
        with self.assertRaisesRegex(ValueError, "prohibited"):
            assert_artifact_safe({"rawLog": "synthetic"})
        with self.assertRaisesRegex(ValueError, "bounded"):
            assert_artifact_safe({"summary": "line one\nline two"})

    def test_runner_phase_fixture_tracks_the_runtime_contract(self) -> None:
        scenario = next(
            item
            for item in self.suite["scenarios"]
            if item["id"] == "runner-phase-transitions"
        )
        # Hyphenated runtime phases are represented by their full ordered string.
        sequence = scenario["fixture"]["signals"]["phaseSequence"]
        for phase in PHASES:
            self.assertIn(phase, sequence)
        terminals = scenario["fixture"]["signals"]["terminalOutcomes"]
        for phase in TERMINAL_PHASES:
            self.assertIn(phase, terminals)

    def test_recorded_result_is_the_current_milestone_gate(self) -> None:
        result = evaluate(self.suite, self.observations)
        passed = sum(item["status"] == "passed" for item in result["results"])
        failed = sum(item["status"] == "failed" for item in result["results"])
        expected_gate = {
            "apiVersion": "fortifylab.io/evaluations/v1alpha1",
            "kind": "ObservableManagerEvaluationGate",
            "suiteVersion": self.suite["suiteVersion"],
            "suiteDigest": digest(self.suite),
            "observationDigest": digest(self.observations),
            "status": result["status"],
            "passedScenarioCount": passed,
            "failedScenarioCount": failed,
            "evidence": result["evidence"],
            "liveEvidence": result["liveEvidence"],
        }
        self.assertEqual(self.recorded, expected_gate)
        self.assertEqual(self.recorded["status"], "passed")
        self.assertEqual(self.recorded["failedScenarioCount"], 0)

    def test_provider_failure_cannot_advance_authority(self) -> None:
        scenario = next(
            item
            for item in self.suite["scenarios"]
            if item["id"] == "telegram-outage-recovery"
        )
        self.assertEqual(
            scenario["expected"]["workflowAuthorization"], "unchanged"
        )
        self.assertEqual(
            scenario["fixture"]["signals"]["authoritativeState"], "waiting"
        )


if __name__ == "__main__":
    unittest.main()
