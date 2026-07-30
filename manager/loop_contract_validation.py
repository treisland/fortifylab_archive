"""Semantic validation for technology-neutral loop contracts."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any


SENSITIVE_KEY = re.compile(
    r"password|passwd|secret|token|credential|license|private.?key|authorization|cookie",
    re.IGNORECASE,
)
SENSITIVE_VALUE = re.compile(
    r"(?i)(?:bearer\s+[a-z0-9._~+/=-]+|password\s*[=:]\s*\S+|"
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"
)


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_semantics(
    document: dict[str, Any],
    *,
    expected_plan_digest: str | None = None,
    at: datetime | None = None,
) -> list[str]:
    """Return sanitized semantic errors for an otherwise schema-valid document."""
    errors: list[str] = []
    kind = document.get("kind")

    if kind == "OperationProgress":
        attempt = document["attempt"]
        policy = document["policy"]
        mode = document["idempotency"]["mode"]
        key = document["idempotency"]["key"]
        if attempt > policy["maxAttempts"]:
            errors.append("operation attempt exceeds the bounded retry policy")
        if policy["maxAttempts"] > 1 and mode == "non-idempotent":
            errors.append("non-idempotent operations cannot be retried automatically")
        if mode == "keyed" and not key:
            errors.append("keyed idempotency requires a non-empty key")
        if mode != "keyed" and key is not None:
            errors.append("only keyed idempotency may carry a key")
        cancellation = document["cancellation"]
        if cancellation["requested"] and "requestedAt" not in cancellation:
            errors.append("a cancellation request requires its request time")

    elif kind == "HealthObservation":
        check_ids = {check["id"] for check in document["checks"]}
        root = document.get("rootCauseCheckId")
        if root is not None and root not in check_ids:
            errors.append("health root cause must reference an included check")
        if document["status"] in {"degraded", "unhealthy"} and root is None:
            errors.append("degraded or unhealthy observations require a root cause")

    elif kind == "Incident":
        if document["rootCause"]["eventId"] not in document["eventIds"]:
            errors.append("incident root cause must reference included evidence")
        resolved = document.get("resolvedAt")
        if document["status"] == "resolved" and resolved is None:
            errors.append("resolved incidents require a resolution time")
        if resolved is not None and _instant(resolved) < _instant(document["openedAt"]):
            errors.append("incident resolution cannot precede opening")

    elif kind == "PlanApproval":
        created = _instant(document["createdAt"])
        expires = _instant(document["expiresAt"])
        if expires <= created:
            errors.append("approval expiry must be after creation")
        if (
            expected_plan_digest is not None
            and document["planDigest"] != expected_plan_digest
        ):
            errors.append("approval does not bind to the requested plan digest")
        if (
            at is not None
            and document["state"] in {"pending", "approved"}
            and at >= expires
        ):
            errors.append("approval has expired and cannot authorize execution")
        if document["state"] in {"approved", "rejected"} and "decidedAt" not in document:
            errors.append("a decided approval requires its decision time")
        if document["state"] == "consumed":
            if "consumedAt" not in document:
                errors.append("a consumed approval requires its consumption time")
            if "decidedAt" not in document:
                errors.append("a consumed approval requires a prior decision")
        for field in ("decidedAt", "consumedAt"):
            if field in document and not created <= _instant(document[field]) <= expires:
                errors.append(f"approval {field} must fall within its validity window")

    elif kind == "SanitizedTrace":
        for entry in document["entries"]:
            if SENSITIVE_VALUE.search(entry["message"]):
                errors.append("trace message contains a recognizable sensitive value")
            for key, value in entry.get("fields", {}).items():
                if SENSITIVE_KEY.search(key):
                    errors.append("trace fields contain a sensitive key")
                if isinstance(value, str) and SENSITIVE_VALUE.search(value):
                    errors.append("trace fields contain a recognizable sensitive value")

    return errors
