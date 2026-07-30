"""Deterministic gate for the 0.2 observable-manager scenario suite."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


FORBIDDEN_KEYS = frozenset(
    {
        "secret",
        "password",
        "token",
        "licensecontent",
        "path",
        "prompt",
        "source",
        "environment",
        "log",
        "rawlog",
    }
)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def assert_artifact_safe(value: Any) -> None:
    """Reject artifact shapes capable of carrying prohibited raw material."""

    if isinstance(value, dict):
        for key, child in value.items():
            normalized = "".join(character for character in key.lower() if character.isalpha())
            if normalized in FORBIDDEN_KEYS:
                raise ValueError(f"prohibited evaluation artifact field: {key}")
            assert_artifact_safe(child)
    elif isinstance(value, list):
        for child in value:
            assert_artifact_safe(child)
    elif isinstance(value, str):
        if len(value) > 500 or "\n" in value or "\r" in value:
            raise ValueError("evaluation artifacts accept bounded single-line text only")


def evaluate(suite: dict, observations: dict) -> dict:
    """Compare sanitized fixture observations with the versioned expectations."""

    assert_artifact_safe(suite)
    assert_artifact_safe(observations)
    observed = observations.get("observedOutcomeDigests", {})
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
    extra = sorted(set(observed) - {scenario["id"] for scenario in suite["scenarios"]})
    passed = bool(results) and all(result["status"] == "passed" for result in results)
    return {
        "apiVersion": "fortifylab.io/evaluations/v1alpha1",
        "kind": "ObservableManagerEvaluationResult",
        "suiteVersion": suite["suiteVersion"],
        "suiteDigest": digest(suite),
        "status": "passed" if passed and not extra else "failed",
        "evidence": "deterministic-fixture",
        "results": results,
        "unexpectedObservationIds": extra,
        "liveEvidence": {
            "status": "not-run",
            "reason": "Local evaluation does not contact MicroK8s, browsers, or providers",
        },
    }


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
