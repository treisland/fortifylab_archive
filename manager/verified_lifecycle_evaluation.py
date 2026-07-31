"""Deterministic 0.4 gate with an explicit, sanitized live-evidence boundary."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from manager.observable_evaluation import assert_artifact_safe, digest


REQUIRED_LIVE_CHECKS = frozenset(
    {
        "cleanInstall",
        "dependencyOrdering",
        "cancellation",
        "retry",
        "backupRestore",
        "upgrade",
        "rollbackBoundary",
        "serviceRestart",
        "secretSafety",
    }
)
REQUIRED_BROWSER_CHECKS = frozenset(
    {
        "actualClusterState",
        "primaryRootCause",
        "blockedConsumers",
        "actionableRemediation",
    }
)


def _instant(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("evidence timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def evaluate(
    suite: dict[str, Any],
    observations: dict[str, Any],
    live_evidence: dict[str, Any],
    *,
    evaluated_at: str,
) -> dict[str, Any]:
    """Evaluate fixture outcomes and fail closed on absent or invalid live proof."""

    for artifact in (suite, observations, live_evidence):
        assert_artifact_safe(artifact)

    observed = observations.get("observedOutcomeDigests", {})
    scenario_ids = {scenario["id"] for scenario in suite["scenarios"]}
    results = []
    for scenario in suite["scenarios"]:
        actual = observed.get(scenario["id"])
        expected = digest(scenario["expected"])
        results.append(
            {
                "id": scenario["id"],
                "status": "passed" if actual == expected else "failed",
                "expectedDigest": expected,
                "observedDigest": actual or digest(None),
            }
        )
    unexpected = sorted(set(observed) - scenario_ids)
    fixtures_passed = (
        bool(results)
        and all(item["status"] == "passed" for item in results)
        and not unexpected
    )

    reasons: list[str] = []
    live_passed = live_evidence.get("status") == "passed"
    if not live_passed:
        reasons.append("live-evidence-not-passed")
    else:
        if live_evidence.get("profileId") != suite["requiredProfileId"]:
            reasons.append("profile-mismatch")
        if live_evidence.get("profileVerification") != "verified":
            reasons.append("profile-unverified")
        if live_evidence.get("platform") != "single-node MicroK8s":
            reasons.append("platform-mismatch")
        checks = live_evidence.get("checks", {})
        if set(checks) != REQUIRED_LIVE_CHECKS or any(
            state != "passed" for state in checks.values()
        ):
            reasons.append("lifecycle-checks-incomplete")
        browser = live_evidence.get("browserChecks", {})
        if set(browser) != REQUIRED_BROWSER_CHECKS or any(
            state != "passed" for state in browser.values()
        ):
            reasons.append("browser-checks-incomplete")
        try:
            recorded = _instant(live_evidence["recordedAt"])
            expires = _instant(live_evidence["expiresAt"])
            evaluated = _instant(evaluated_at)
            if not recorded <= evaluated <= expires:
                reasons.append("live-evidence-stale")
        except (KeyError, TypeError, ValueError):
            reasons.append("live-evidence-time-invalid")
        live_passed = not reasons

    status = "passed" if fixtures_passed and live_passed else "failed"
    return {
        "apiVersion": "fortifylab.io/evaluations/v1alpha1",
        "kind": "VerifiedPlatformLifecycleEvaluationResult",
        "milestone": suite["milestoneGate"],
        "suiteVersion": suite["suiteVersion"],
        "suiteDigest": digest(suite),
        "observationDigest": digest(observations),
        "status": status,
        "deterministicEvidence": {
            "status": "passed" if fixtures_passed else "failed",
            "results": results,
            "unexpectedObservationIds": unexpected,
        },
        "liveEvidence": {
            "status": "passed" if live_passed else "failed",
            "artifactDigest": digest(live_evidence),
            "reasons": reasons,
        },
        "rule": "Milestone passes only when every deterministic scenario and fresh exact-profile live check passes.",
    }
