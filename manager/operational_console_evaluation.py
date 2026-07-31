"""Operational-console browser contract and authorized live-evidence gate."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from manager.observable_evaluation import assert_artifact_safe, digest


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
    """Fail closed unless every browser journey and exact-profile live check passes."""

    for artifact in (suite, observations, live_evidence):
        assert_artifact_safe(artifact)
    expected_ids = {item["id"] for item in suite["journeys"]}
    observed = observations.get("observedOutcomeDigests", {})
    results = [
        {
            "id": item["id"],
            "status": "passed"
            if observed.get(item["id"]) == digest(item["expected"])
            else "failed",
            "expectedDigest": digest(item["expected"]),
            "observedDigest": observed.get(item["id"]) or digest(None),
        }
        for item in suite["journeys"]
    ]
    unexpected = sorted(set(observed) - expected_ids)
    deterministic_passed = (
        bool(results)
        and all(item["status"] == "passed" for item in results)
        and not unexpected
    )

    reasons: list[str] = []
    live_passed = live_evidence.get("status") == "passed"
    if not live_passed:
        reasons.append("authorized-live-browser-evidence-unavailable")
    else:
        if live_evidence.get("profileId") != suite["requiredProfileId"]:
            reasons.append("profile-mismatch")
        if live_evidence.get("platform") != "single-node MicroK8s":
            reasons.append("platform-mismatch")
        checks = live_evidence.get("journeyChecks", {})
        if set(checks) != expected_ids or any(value != "passed" for value in checks.values()):
            reasons.append("browser-journeys-incomplete")
        if live_evidence.get("sanitizationCheck") != "passed":
            reasons.append("sanitization-check-incomplete")
        if live_evidence.get("telegramAuditCorrelation") != "passed":
            reasons.append("telegram-audit-correlation-incomplete")
        try:
            recorded = _instant(live_evidence["recordedAt"])
            expires = _instant(live_evidence["expiresAt"])
            evaluated = _instant(evaluated_at)
            if not recorded <= evaluated <= expires:
                reasons.append("live-evidence-stale")
        except (KeyError, TypeError, ValueError):
            reasons.append("live-evidence-time-invalid")
        live_passed = not reasons

    return {
        "apiVersion": "fortifylab.io/evaluations/v1alpha1",
        "kind": "OperationalConsoleBrowserEvaluationResult",
        "milestone": suite["milestoneGate"],
        "suiteVersion": suite["suiteVersion"],
        "suiteDigest": digest(suite),
        "observationDigest": digest(observations),
        "status": "passed" if deterministic_passed and live_passed else "failed",
        "deterministicBrowserEvidence": {
            "status": "passed" if deterministic_passed else "failed",
            "results": results,
            "unexpectedObservationIds": unexpected,
        },
        "liveEvidence": {
            "status": "passed" if live_passed else "unavailable",
            "artifactDigest": digest(live_evidence),
            "reasons": reasons,
        },
        "rule": "Release evidence requires passing deterministic journeys and authorized, fresh, exact-profile browser evidence.",
    }
