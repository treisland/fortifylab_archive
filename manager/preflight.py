"""Read-only, repeatable, secret-safe deployment preflight evaluation."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Protocol

from manager.component_registry import ComponentRegistry


API_VERSION = "fortifylab.io/v1alpha1"
RESULT_STATES = frozenset({"pass", "warning", "fail"})


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
    ) -> None:
        self._registry = registry
        self._probe = probe or UnavailablePreflightProbe()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_probe_timeout = max_probe_timeout

    def document(self) -> dict:
        generated_at = self._clock()
        items = [self._run(check) for check in self._checks()]
        counts = {
            classification: sum(
                item["classification"] == classification for item in items
            )
            for classification in ("blocker", "warning", "information")
        }
        return {
            "apiVersion": API_VERSION,
            "kind": "DeploymentPreflight",
            "generatedAt": _timestamp(generated_at),
            "ready": counts["blocker"] == 0,
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

    def _run(self, check: PreflightCheck) -> dict:
        started = time.monotonic()
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="preflight")
        future = executor.submit(self._probe.probe, check)
        try:
            result = future.result(
                timeout=min(check.timeout_seconds, self._max_probe_timeout)
            )
            state = result.state
            summary = _result_summary(check.id, state)
        except TimeoutError:
            future.cancel()
            state = "fail"
            summary = "Check exceeded its bounded deadline"
        except Exception:
            state = "fail"
            summary = "Check could not obtain safe evidence"
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

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
