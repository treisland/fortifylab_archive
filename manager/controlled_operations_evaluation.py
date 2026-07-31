"""Deterministic milestone gate for the 0.3 controlled-operations suite."""

from __future__ import annotations

from typing import Any

from manager.observable_evaluation import (
    assert_artifact_safe,
    digest,
    load,
)


def evaluate(suite: dict[str, Any], observations: dict[str, Any]) -> dict[str, Any]:
    """Compare sanitized fixture observations with every versioned expectation."""

    assert_artifact_safe(suite)
    assert_artifact_safe(observations)
    observed = observations.get("observedOutcomeDigests", {})
    scenario_ids = {scenario["id"] for scenario in suite["scenarios"]}
    results = []
    for scenario in suite["scenarios"]:
        expected_digest = digest(scenario["expected"])
        actual_digest = observed.get(scenario["id"])
        results.append(
            {
                "id": scenario["id"],
                "status": "passed" if actual_digest == expected_digest else "failed",
                "expectedDigest": expected_digest,
                "observedDigest": actual_digest or digest(None),
            }
        )
    unexpected = sorted(set(observed) - scenario_ids)
    passed = bool(results) and all(item["status"] == "passed" for item in results)
    return {
        "apiVersion": "fortifylab.io/evaluations/v1alpha1",
        "kind": "ControlledOperationsEvaluationResult",
        "suiteVersion": suite["suiteVersion"],
        "suiteDigest": digest(suite),
        "status": "passed" if passed and not unexpected else "failed",
        "evidence": "deterministic-fixture",
        "results": results,
        "unexpectedObservationIds": unexpected,
        "liveEvidence": {
            "status": "not-run",
            "reason": "Local evaluation does not contact MicroK8s, browsers, or providers",
        },
    }
