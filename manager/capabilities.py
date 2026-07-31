"""Sanitized, versioned effective Manager capability contract."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable


CAPABILITY_API_VERSION = "fortifylab.io/v1alpha1"
CAPABILITY_CONTRACT_VERSION = "1.0"
CAPABILITY_MAX_AGE_SECONDS = 45
CAPABILITY_STATES = {
    "available",
    "disabled",
    "not-configured",
    "unauthorized",
    "degraded",
    "temporarily-unavailable",
}

PRESENTATION_STATES = {
    "available": ("available", "info"),
    "disabled": ("disabled-by-policy", "info"),
    "not-configured": ("setup-required", "warning"),
    "unauthorized": ("unauthorized", "error"),
    "degraded": ("temporarily-unavailable", "warning"),
    "temporarily-unavailable": ("temporarily-unavailable", "warning"),
    "unsupported": ("unsupported", "info"),
}

SAFE_ACTIONS = {
    "available": "No action required; current evidence supports this capability.",
    "disabled": "Use the documented operator activation workflow if mutation is intended.",
    "not-configured": "Complete the documented protected setup, then refresh.",
    "unauthorized": "Use an authorized Manager account; do not broaden cluster RBAC.",
    "degraded": "Restore the documented prerequisite, then refresh.",
    "temporarily-unavailable": "Restore the documented prerequisite, then refresh.",
    "unsupported": "Install and verify the documented service before enabling this feature.",
}

CAPABILITY_METADATA = {
    "observation": ("observation", "manager-runtime-boundary"),
    "functional-health": ("observation", "functional-probe-boundary"),
    "lifecycle-execution": ("mutation", "lifecycle-service-boundary"),
    "approvals": ("mutation", "approval-service-boundary"),
    "backup-restore": ("mutation", "recovery-helper-boundary"),
    "upgrades": ("mutation", "upgrade-service-boundary"),
    "secret-workflows": ("mutation", "secret-service-boundary"),
    "notifications": ("observation", "notification-provider-boundary"),
}

DOCS_ROOT = "/docs"
PREREQUISITES = {
    "observation": (),
    "functional-health": ("OBSERVATION_AVAILABLE", "FUNCTIONAL_PROBE_COMPOSED"),
    "lifecycle-execution": ("OBSERVATION_AVAILABLE", "LIFECYCLE_SERVICE_COMPOSED"),
    "approvals": ("LIFECYCLE_EXECUTION_AVAILABLE", "APPROVAL_SERVICE_COMPOSED"),
    "backup-restore": ("LIFECYCLE_EXECUTION_AVAILABLE", "RECOVERY_HELPER_COMPOSED"),
    "upgrades": ("LIFECYCLE_EXECUTION_AVAILABLE", "UPGRADE_SERVICE_COMPOSED"),
    "secret-workflows": ("SECRET_SERVICE_COMPOSED",),
    "notifications": ("NOTIFICATION_PROVIDER_COMPOSED",),
}


class CapabilityProvider:
    """Build effective states from Manager composition and current observation."""

    def __init__(
        self,
        *,
        observation_state: Callable[[], str] | None = None,
        functional_health_configured: bool = False,
        functional_health_state: Callable[[], bool] | None = None,
        lifecycle_enabled: bool = False,
        lifecycle_configured: bool = False,
        lifecycle_credential_state: Callable[[], bool] | None = None,
        lifecycle_authorization_state: Callable[[], bool] | None = None,
        lifecycle_adapter_state: Callable[[], bool] | None = None,
        lifecycle_activation_state: Callable[[], str] | None = None,
        approvals_configured: bool = False,
        approvals_state: Callable[[], bool] | None = None,
        recovery_configured: bool = False,
        recovery_state: Callable[[], bool] | None = None,
        upgrades_configured: bool = False,
        upgrades_state: Callable[[], bool] | None = None,
        secrets_configured: bool = False,
        secrets_state: Callable[[], bool] | None = None,
        notifications_configured: bool = False,
        notifications_state: Callable[[], bool] | None = None,
        authorized: Callable[[Any, str], bool] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._observation_state = observation_state
        self._functional_health_configured = functional_health_configured
        self._functional_health_state = functional_health_state
        self._lifecycle_enabled = lifecycle_enabled
        self._lifecycle_configured = lifecycle_configured
        self._lifecycle_credential_state = lifecycle_credential_state
        self._lifecycle_authorization_state = lifecycle_authorization_state
        self._lifecycle_adapter_state = lifecycle_adapter_state
        self._lifecycle_activation_state = lifecycle_activation_state
        self._approvals_configured = approvals_configured
        self._approvals_state = approvals_state
        self._recovery_configured = recovery_configured
        self._recovery_state = recovery_state
        self._upgrades_configured = upgrades_configured
        self._upgrades_state = upgrades_state
        self._secrets_configured = secrets_configured
        self._secrets_state = secrets_state
        self._notifications_configured = notifications_configured
        self._notifications_state = notifications_state
        self._authorized = authorized or (lambda _identity, _capability: True)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def document(self, identity: Any = None) -> dict[str, Any]:
        generated = self._clock()
        observation = self._effective_observation()
        lifecycle = self._effective_lifecycle(identity, observation)
        entries = [
            observation,
            self._functional_health(identity, observation),
            lifecycle,
            self._dependent(
                "approvals", identity, lifecycle, self._approvals_configured,
                self._approvals_state, "APPROVALS_NOT_CONFIGURED",
                "APPROVAL_STORE_UNAVAILABLE", "operations/authorization",
            ),
            self._dependent(
                "backup-restore", identity, lifecycle, self._recovery_configured,
                self._recovery_state, "BACKUP_RESTORE_NOT_CONFIGURED",
                "RECOVERY_HELPER_UNAVAILABLE", "operations/backup-restore",
            ),
            self._dependent(
                "upgrades", identity, lifecycle, self._upgrades_configured,
                self._upgrades_state, "UPGRADES_NOT_CONFIGURED",
                "UPGRADE_SERVICE_UNAVAILABLE", "operations/profile-upgrades",
            ),
            self._configured(
                "secret-workflows", identity, self._secrets_configured,
                self._secrets_state, "SECRET_WORKFLOWS_NOT_CONFIGURED",
                "SECRET_SERVICE_UNAVAILABLE", "operations/write-only-secrets",
            ),
            self._configured(
                "notifications", identity, self._notifications_configured,
                self._notifications_state, "NOTIFICATIONS_NOT_CONFIGURED",
                "NOTIFICATION_PROVIDER_UNAVAILABLE", "operations/telegram-observability",
            ),
        ]
        return {
            "apiVersion": CAPABILITY_API_VERSION,
            "kind": "ManagerCapabilities",
            "contractVersion": CAPABILITY_CONTRACT_VERSION,
            "generatedAt": _timestamp(generated),
            "expiresAt": _timestamp(
                generated + timedelta(seconds=CAPABILITY_MAX_AGE_SECONDS)
            ),
            "refreshAfterSeconds": 30,
            "capabilities": [self._with_evidence(item, generated) for item in entries],
        }

    @staticmethod
    def _with_evidence(entry: dict[str, Any], generated: datetime) -> dict[str, Any]:
        entry["evidenceAt"] = _timestamp(generated)
        return entry

    def _effective_observation(self) -> dict[str, Any]:
        if self._observation_state is None:
            return _entry(
                "observation", "not-configured", False, False,
                "OBSERVATION_NOT_CONFIGURED", "manager-runtime-boundary",
            )
        try:
            state = self._observation_state()
        except Exception:
            state = "unavailable"
        if state == "available":
            return _entry(
                "observation", "available", True, False,
                "OBSERVATION_AVAILABLE", "manager-runtime-boundary",
            )
        return _entry(
            "observation", "temporarily-unavailable", True, False,
            "OBSERVER_DISCONNECTED", "manager-runtime-boundary",
        )

    def _functional_health(
        self, identity: Any, observation: dict[str, Any]
    ) -> dict[str, Any]:
        if not self._authorized(identity, "functional-health"):
            return _unauthorized("functional-health", "health-checks")
        if observation["state"] != "available":
            return _entry(
                "functional-health", "temporarily-unavailable", True, False,
                "OBSERVATION_REQUIRED", "health-checks",
            )
        if not self._functional_health_configured:
            return _entry(
                "functional-health", "not-configured", True, False,
                "FUNCTIONAL_PROBE_NOT_CONFIGURED", "health-checks",
            )
        try:
            ready = (
                self._functional_health_state()
                if self._functional_health_state is not None
                else False
            )
        except Exception:
            ready = False
        if not ready:
            return _entry(
                "functional-health", "temporarily-unavailable", True, False,
                "FUNCTIONAL_PROBE_HANDSHAKE_FAILED", "health-checks",
            )
        return _entry(
            "functional-health", "available", True, False,
            "FUNCTIONAL_HEALTH_AVAILABLE", "health-checks",
        )

    def _effective_lifecycle(
        self, identity: Any, observation: dict[str, Any]
    ) -> dict[str, Any]:
        if not self._authorized(identity, "lifecycle-execution"):
            return _unauthorized("lifecycle-execution", "operations/lifecycle-engine")
        if not self._lifecycle_enabled:
            return _entry(
                "lifecycle-execution", "disabled", True, False,
                "OPERATIONS_DISABLED", "operations/lifecycle-engine",
            )
        if not self._lifecycle_configured:
            return _entry(
                "lifecycle-execution", "not-configured", True, False,
                "OPERATIONS_UNAVAILABLE", "operations/lifecycle-engine",
            )
        activation = _activation(self._lifecycle_activation_state)
        if activation == "restart-required":
            return _entry(
                "lifecycle-execution", "temporarily-unavailable", True, False,
                "RBAC_RESTART_REQUIRED", "operations/manager",
                activation={
                    "desired": "RBAC",
                    "effective": "previous-authorization",
                    "action": "restart-required",
                },
            )
        if observation["state"] != "available":
            return _entry(
                "lifecycle-execution", "temporarily-unavailable", True, False,
                "OBSERVER_DISCONNECTED", "operations/lifecycle-engine",
            )
        if not _current(self._lifecycle_credential_state):
            return _entry(
                "lifecycle-execution", "not-configured", True, False,
                "LIFECYCLE_CREDENTIAL_UNAVAILABLE", "operations/lifecycle-engine",
            )
        if not _current(self._lifecycle_authorization_state):
            return _entry(
                "lifecycle-execution", "unauthorized", True, False,
                "LIFECYCLE_CREDENTIAL_UNAUTHORIZED", "operations/lifecycle-engine",
            )
        if not _current(self._lifecycle_adapter_state):
            return _entry(
                "lifecycle-execution", "degraded", True, False,
                "LIFECYCLE_ADAPTER_UNAVAILABLE", "operations/lifecycle-engine",
            )
        return _entry(
            "lifecycle-execution", "available", True, True,
            "OPERATIONS_AVAILABLE", "operations/lifecycle-engine",
        )

    def _dependent(
        self, capability_id: str, identity: Any, lifecycle: dict[str, Any],
        configured: bool, runtime_state: Callable[[], bool] | None,
        missing_code: str, unavailable_code: str, docs: str,
    ) -> dict[str, Any]:
        if not self._authorized(identity, capability_id):
            return _unauthorized(capability_id, docs)
        if not configured:
            return _entry(
                capability_id, "not-configured", True, False, missing_code, docs,
                presentation_state="unsupported",
            )
        if lifecycle["state"] != "available":
            return _entry(
                capability_id, lifecycle["state"], True, False,
                lifecycle["code"], docs,
            )
        if not _current(runtime_state):
            return _entry(
                capability_id, "temporarily-unavailable", True, False,
                unavailable_code, docs,
            )
        return _entry(
            capability_id, "available", True, True,
            f"{capability_id.replace('-', '_').upper()}_AVAILABLE", docs,
        )

    def _configured(
        self, capability_id: str, identity: Any, configured: bool,
        runtime_state: Callable[[], bool] | None, missing_code: str,
        unavailable_code: str, docs: str,
    ) -> dict[str, Any]:
        if not self._authorized(identity, capability_id):
            return _unauthorized(capability_id, docs)
        if not configured:
            return _entry(
                capability_id, "not-configured", True, False, missing_code, docs,
                presentation_state="unsupported",
            )
        if not _current(runtime_state):
            return _entry(
                capability_id, "temporarily-unavailable", True, False,
                unavailable_code, docs,
            )
        return _entry(
            capability_id, "available", True, True,
            f"{capability_id.replace('-', '_').upper()}_AVAILABLE", docs,
        )


def _current(check: Callable[[], bool] | None) -> bool:
    """Fail closed when composed services cannot provide current evidence."""
    if check is None:
        return False
    try:
        return check() is True
    except Exception:
        return False


def _activation(check: Callable[[], str] | None) -> str:
    """Return only the bounded activation states understood by this contract."""
    if check is None:
        return "not-reported"
    try:
        state = check()
    except Exception:
        return "ambiguous"
    return state if state in {"active", "restart-required", "ambiguous"} else "ambiguous"


def _unauthorized(capability_id: str, docs: str) -> dict[str, Any]:
    return _entry(
        capability_id, "unauthorized", True, False,
        "CAPABILITY_UNAUTHORIZED", docs,
    )


def _entry(
    capability_id: str, state: str, inspect: bool, mutate: bool,
    code: str, docs: str, *, activation: dict[str, str] | None = None,
    presentation_state: str | None = None,
) -> dict[str, Any]:
    if state not in CAPABILITY_STATES:
        raise ValueError("invalid capability state")
    category, boundary = CAPABILITY_METADATA[capability_id]
    presentation, severity = PRESENTATION_STATES[state]
    if presentation_state == "unsupported":
        presentation, severity = PRESENTATION_STATES["unsupported"]
    entry = {
        "id": capability_id,
        "state": state,
        "presentationState": presentation,
        "severity": severity,
        "category": category,
        "responsibleBoundary": boundary,
        "canInspect": inspect,
        "canMutate": mutate,
        "code": code,
        "prerequisites": list(PREREQUISITES[capability_id]),
        "remediation": {
            "code": code,
            "href": f"{DOCS_ROOT}/{docs}.md",
            "summary": (
                "Restart MicroK8s through the documented operator workflow, then "
                "verify least-privilege authorization and refresh."
                if code == "RBAC_RESTART_REQUIRED" else SAFE_ACTIONS[
                    "unsupported" if presentation == "unsupported" else state
                ]
            ),
        },
    }
    if activation is not None:
        entry["activation"] = activation
    return entry


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
