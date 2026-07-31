"""Release-gate tests for the 0.3 controlled-operations milestone."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from manager.authorization import (
    APPROVAL_REQUIRED,
    HIGH_RISK_SOURCES,
    RISK_BY_OPERATION,
)
from manager.component_registry import ComponentRegistry
from manager.controlled_operations_evaluation import evaluate
from manager.observable_evaluation import assert_artifact_safe, digest, load
from manager.operation_engine import (
    DependencyBlocked,
    OperationEngine,
    OperationStore,
    TERMINAL_STATES,
)


ROOT = Path(__file__).resolve().parents[1]
EVALUATION_ROOT = ROOT / "evaluations" / "controlled-operations-v0.3"
REQUIRED_SCENARIOS = {
    "dependency-ordered-start-stop",
    "mysql-blocking-ssc",
    "cancellation",
    "timeout",
    "retry",
    "manager-restart",
    "concurrent-conflict",
    "stale-approval",
    "telegram-outage",
    "unauthorized-callback",
    "write-only-input-update",
    "destructive-action-boundary",
    "post-operation-health-failure",
}
SECRET_SURFACES = {
    "api", "ui", "cli", "telegram", "logs", "history", "diagnostics"
}


class Adapter:
    def execute(self, step, *, deadline, cancelled):
        raise AssertionError("evaluation contract tests must not mutate a cluster")


class Verifier:
    def verify(self, component_id, check_id, *, deadline, cancelled):
        raise AssertionError("evaluation contract tests must not contact a cluster")


class ControlledOperationsEvaluationTests(unittest.TestCase):
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
            {"lifecycle", "approval", "telegram", "secret", "safety", "health"},
        )

    def test_every_scenario_has_machine_checkable_cross_interface_outcomes(self) -> None:
        for scenario in self.suite["scenarios"]:
            with self.subTest(scenario=scenario["id"]):
                expected = scenario["expected"]
                self.assertEqual(
                    set(expected["interfaces"]), {"api", "ui", "cli", "telegram"}
                )
                self.assertIsInstance(expected["plan"]["orderedSteps"], list)
                self.assertTrue(expected["events"])
                self.assertIn(expected["terminalState"], TERMINAL_STATES | {"conflict", "blocked", "pending"})
                self.assertTrue(expected["health"])

    def test_secret_leakage_assertions_cover_every_required_surface(self) -> None:
        self.assertEqual(
            set(self.suite["artifactPolicy"]["secretLeakageSurfaces"]),
            SECRET_SURFACES,
        )
        scenario = self._scenario("write-only-input-update")
        self.assertEqual(
            set(scenario["expected"]["secretLeakage"]["surfaces"]),
            SECRET_SURFACES,
        )
        assert_artifact_safe(self.suite)
        assert_artifact_safe(self.observations)
        assert_artifact_safe(self.recorded)
        serialized = json.dumps(
            [self.suite, self.observations, self.recorded], sort_keys=True
        ).lower()
        for prohibited in self.suite["artifactPolicy"]["forbidden"]:
            self.assertNotIn(prohibited, serialized.split('"forbidden"', 1)[-1].split("]", 1)[-1])

    def test_plans_and_safety_expectations_track_runtime_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = OperationStore(Path(directory) / "operations.sqlite3")
            try:
                engine = OperationEngine(
                    ComponentRegistry.load(), store, Adapter(), Verifier()
                )
                plan = engine.plan("start", ["scancentral-sast"])
                actual = [
                    f"{step['component']}:{step['operation']}"
                    for step in plan["steps"]
                ]
                expected = self._scenario("dependency-ordered-start-stop")
                self.assertEqual(actual, expected["expected"]["plan"]["orderedSteps"])
                with self.assertRaises(DependencyBlocked):
                    engine.plan("stop", ["mysql"])
            finally:
                store.close()

        boundary = self._scenario("destructive-action-boundary")["expected"]
        self.assertEqual(RISK_BY_OPERATION["uninstall"], "high")
        self.assertIn("high", APPROVAL_REQUIRED)
        self.assertEqual(HIGH_RISK_SOURCES, {"local-cli", "web"})
        self.assertTrue(boundary["plan"]["destructive"])
        self.assertFalse(boundary["plan"]["deletesData"])

    def test_fixture_and_live_evidence_cannot_be_conflated(self) -> None:
        self.assertEqual(self.suite["scope"]["liveEvidence"], "separate-required-artifact")
        for scenario in self.suite["scenarios"]:
            self.assertEqual(scenario["evidence"], "deterministic-fixture")
        self.assertEqual(self.recorded["evidence"], "deterministic-fixture")
        self.assertEqual(self.recorded["liveEvidence"]["status"], "not-run")

    def test_recorded_result_is_the_versioned_milestone_gate(self) -> None:
        result = evaluate(self.suite, self.observations)
        expected_gate = {
            "apiVersion": "fortifylab.io/evaluations/v1alpha1",
            "kind": "ControlledOperationsEvaluationGate",
            "milestone": "0.3-controlled-operations",
            "suiteVersion": self.suite["suiteVersion"],
            "suiteDigest": digest(self.suite),
            "observationDigest": digest(self.observations),
            "status": result["status"],
            "passedScenarioCount": sum(
                item["status"] == "passed" for item in result["results"]
            ),
            "failedScenarioCount": sum(
                item["status"] == "failed" for item in result["results"]
            ),
            "evidence": result["evidence"],
            "liveEvidence": result["liveEvidence"],
        }
        self.assertEqual(self.recorded, expected_gate)
        self.assertEqual(self.recorded["status"], "passed")
        self.assertEqual(self.recorded["failedScenarioCount"], 0)

    def test_gate_fails_on_changed_missing_or_unexpected_observations(self) -> None:
        changed = copy.deepcopy(self.observations)
        changed["observedOutcomeDigests"]["timeout"] = digest({"changed": True})
        self.assertEqual(evaluate(self.suite, changed)["status"], "failed")

        missing = copy.deepcopy(self.observations)
        del missing["observedOutcomeDigests"]["retry"]
        missing_result = evaluate(self.suite, missing)
        self.assertEqual(missing_result["status"], "failed")
        retry = next(item for item in missing_result["results"] if item["id"] == "retry")
        self.assertEqual(retry["status"], "failed")

        unexpected = copy.deepcopy(self.observations)
        unexpected["observedOutcomeDigests"]["unexpected-case"] = digest(None)
        unexpected_result = evaluate(self.suite, unexpected)
        self.assertEqual(unexpected_result["status"], "failed")
        self.assertEqual(
            unexpected_result["unexpectedObservationIds"], ["unexpected-case"]
        )

    @classmethod
    def _scenario(cls, identifier: str) -> dict:
        return next(item for item in cls.suite["scenarios"] if item["id"] == identifier)


if __name__ == "__main__":
    unittest.main()
