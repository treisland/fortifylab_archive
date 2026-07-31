"""Read-only, repeatable, secret-safe deployment preflight evaluation."""

from __future__ import annotations

import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from manager.component_registry import ComponentRegistry


API_VERSION = "fortifylab.io/v1alpha1"
RESULT_STATES = frozenset({"pass", "warning", "fail"})
ACTION_CHECKS = {
    "observation": ("microk8s",),
    "deployment": (),  # Every check applies.
    "start": ("microk8s", "storage", "configuration", "compatibility"),
    "suspend": ("microk8s",),
}


@dataclass(frozen=True)
class PreflightCheck:
    """Allow-listed observation request passed to a read-only adapter."""

    id: str
    category: str
    probe_type: str
    target: str
    timeout_seconds: float
    remediation: str
    remediation_href: str


@dataclass(frozen=True)
class PreflightResult:
    """State-only result; adapters cannot contribute report text."""

    state: str

    def __post_init__(self) -> None:
        if self.state not in RESULT_STATES:
            raise ValueError("unsupported preflight result state")


class PreflightProbe(Protocol):
    """Technology-neutral boundary for read-only deployment observations."""

    def probe(self, check: PreflightCheck) -> PreflightResult:
        """Evaluate one allow-listed check without mutation or secret output."""


class UnavailablePreflightProbe:
    def probe(self, check: PreflightCheck) -> PreflightResult:
        raise RuntimeError("preflight adapter is unavailable")


class PreflightEngine:
    """Build a fresh readiness report without changing host or cluster state."""

    def __init__(
        self,
        registry: ComponentRegistry,
        probe: PreflightProbe | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
        max_probe_timeout: float = 30.0,
        max_workers: int = 6,
        aggregate_timeout: float | None = None,
        capability_provider: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        self._registry = registry
        self._probe = probe or UnavailablePreflightProbe()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_probe_timeout = max_probe_timeout
        self._max_workers = max(1, max_workers)
        self._aggregate_timeout = (
            max_probe_timeout if aggregate_timeout is None else aggregate_timeout
        )
        self._capability_provider = capability_provider

    def document(self) -> dict:
        generated_at = self._clock()
        checks = self._checks()
        executor = ThreadPoolExecutor(
            max_workers=self._max_workers, thread_name_prefix="preflight"
        )
        started = {check.id: time.monotonic() for check in checks}
        futures = {
            executor.submit(self._probe.probe, check): check for check in checks
        }
        done, pending = wait(
            futures, timeout=max(0.0, self._aggregate_timeout)
        )
        for future in pending:
            future.cancel()
        items = [
            self._result(
                check,
                future,
                future in done,
                started[check.id],
            )
            for future, check in futures.items()
        ]
        executor.shutdown(wait=False, cancel_futures=True)
        counts = {
            classification: sum(
                item["classification"] == classification for item in items
            )
            for classification in ("blocker", "warning", "information")
        }
        readiness = self._readiness(items)
        return {
            "apiVersion": API_VERSION,
            "kind": "DeploymentPreflight",
            "generatedAt": _timestamp(generated_at),
            # Backward-compatible alias for deployment clients.
            "ready": readiness["deployment"]["ready"],
            "readiness": readiness,
            "profile": {
                "id": self._registry.profile.id,
                "maturity": self._registry.profile.maturity,
                "vendorSupported": False,
            },
            "summary": counts,
            "evidence": {
                "source": (
                    "unavailable"
                    if isinstance(self._probe, UnavailablePreflightProbe)
                    else "runtime-adapter"
                ),
                "mode": "read-only",
            },
            "items": items,
        }

    def _readiness(self, items: list[dict]) -> dict[str, dict[str, Any]]:
        failed = {
            item["id"] for item in items if item["classification"] == "blocker"
        }
        capability_states: dict[str, dict[str, Any]] = {}
        if self._capability_provider is not None:
            try:
                document = self._capability_provider()
                expires_at = _instant(document.get("expiresAt"))
                if expires_at > self._clock():
                    capability_states = {
                        item["id"]: item for item in document.get("capabilities", [])
                    }
            except Exception:
                capability_states = {}

        readiness: dict[str, dict[str, Any]] = {}
        for action, applicable in ACTION_CHECKS.items():
            check_blockers = sorted(failed if not applicable else failed.intersection(applicable))
            blockers = [f"PREFLIGHT_{item.upper().replace('-', '_')}" for item in check_blockers]
            if action in {"deployment", "start", "suspend"}:
                lifecycle = capability_states.get("lifecycle-execution")
                if lifecycle is None or lifecycle.get("state") != "available" or lifecycle.get("canMutate") is not True:
                    blockers.append(
                        str((lifecycle or {}).get("code") or "LIFECYCLE_EVIDENCE_UNAVAILABLE")
                    )
            if action == "observation" and isinstance(self._probe, UnavailablePreflightProbe):
                blockers.append("OBSERVER_NOT_CONFIGURED")
            readiness[action] = {
                "ready": not blockers,
                "blockers": list(dict.fromkeys(blockers)),
            }
        return readiness

    def _result(
        self,
        check: PreflightCheck,
        future: Future[PreflightResult],
        completed: bool,
        started: float,
    ) -> dict:
        try:
            if not completed:
                raise TimeoutError
            result = future.result()
            state = result.state
            summary = _result_summary(check.id, state)
        except TimeoutError:
            state = "fail"
            summary = "Check exceeded the aggregate bounded deadline"
        except Exception:
            state = "fail"
            summary = "Check could not obtain safe evidence"

        classification = {
            "pass": "information",
            "warning": "warning",
            "fail": "blocker",
        }[state]
        item = {
            "id": check.id,
            "category": check.category,
            "classification": classification,
            "status": state,
            "summary": summary,
            "latencyMs": max(0, round((time.monotonic() - started) * 1000)),
        }
        if classification == "blocker":
            item["remediation"] = {
                "summary": check.remediation,
                "href": check.remediation_href,
                "safe": True,
            }
        return item

    def _checks(self) -> tuple[PreflightCheck, ...]:
        # Loading ComponentRegistry has already schema-validated the desired bundle.
        # The adapter compares its pins to the selected tested profile without
        # receiving configuration or credential values.
        _ = self._registry.component_ids
        definitions = (
            ("host-capacity", "capacity", "host-capacity", "single-node", "Free CPU, memory, or disk capacity for the documented lab profile", "host-capacity"),
            ("microk8s", "microk8s", "microk8s-status", "local-cluster", "Install or start the supported MicroK8s version, then rerun preflight", "microk8s"),
            ("microk8s-addons", "microk8s", "addon-status", "required-addons", "Enable the required DNS, storage, ingress, Helm, and registry addons", "microk8s-addons"),
            ("storage", "storage", "storage-readiness", "default-storage", "Configure a writable default storage class with sufficient free capacity", "storage"),
            ("ingress", "ingress", "ingress-readiness", "managed-ingress", "Enable the MicroK8s ingress addon and resolve reported port conflicts", "ingress"),
            ("dns", "dns-tls", "managed-dns", "managed-hosts", "Point every managed hostname at the lab node and verify client and cluster DNS", "dns"),
            ("tls", "dns-tls", "managed-tls", "managed-hosts", "Create a valid managed-host certificate and configure trust before deployment", "tls"),
            ("external-license", "license", "license-readable", "configured-license", "Configure a readable Fortify license file with protected permissions", "external-license"),
            ("registry-authentication", "registry", "registry-authentication", "required-registries", "Configure valid registry credentials without placing them in logs or command arguments", "registry-authentication"),
            ("image-reachability", "registry", "image-reachability", self._registry.profile.id, "Restore registry access and verify every pinned component image is reachable", "image-reachability"),
            ("configuration", "configuration", "configuration-valid", "deployment-config", "Correct the reported configuration field using the documented configuration reference", "configuration"),
            ("compatibility", "compatibility", "profile-compatible", self._registry.profile.id, "Select a documented compatible platform profile and pinned component versions", "compatibility"),
        )
        return tuple(
            PreflightCheck(
                check_id,
                category,
                probe_type,
                target,
                10.0,
                remediation,
                f"/docs/deployment-preflight.md#{anchor}",
            )
            for check_id, category, probe_type, target, remediation, anchor in definitions
        )


def _result_summary(check_id: str, state: str) -> str:
    subject = check_id.replace("-", " ").capitalize()
    return {
        "pass": f"{subject} check passed",
        "warning": f"{subject} requires operator review",
        "fail": f"{subject} is not ready",
    }[state]


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("preflight timestamp must include a timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _instant(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("capability evidence has no expiry")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("capability evidence expiry has no timezone")
    return parsed.astimezone(timezone.utc)
