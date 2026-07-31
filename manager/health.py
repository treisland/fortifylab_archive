"""Layered, dependency-aware, secret-safe health evaluation."""

from __future__ import annotations

import re
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol

from manager.component_registry import ComponentRegistry


API_VERSION = "fortifylab.io/v1alpha1"
HEALTH_STATES = frozenset(
    {
        "healthy", "starting", "degraded", "blocked", "misconfigured",
        "stopped", "unreachable", "unhealthy", "unknown", "stale",
    }
)
_PROBE_STATES = HEALTH_STATES - {"blocked", "stale"}
_SENSITIVE = re.compile(
    r"(?i)(?:password|passwd|secret|token|credential|"
    r"license\s*(?:data|value|key|content|[:=])|private.?key|"
    r"authorization|cookie|bearer\s+\S+)"
)


@dataclass(frozen=True)
class CheckSpec:
    """An allow-listed check identity passed to a runtime adapter."""

    id: str
    subject_id: str
    layer: str
    probe_type: str
    target: str
    timeout_seconds: float
    required: bool = True


@dataclass(frozen=True)
class ProbeResult:
    """Sanitized evidence returned by a runtime adapter."""

    state: str
    summary: str
    observed_at: datetime
    latency_ms: int | None = None
    workload_present: bool | None = None
    desired_replicas: int | None = None
    ready_replicas: int | None = None

    def __post_init__(self) -> None:
        if self.state not in _PROBE_STATES:
            raise ValueError("unsupported probe state")
        if self.observed_at.tzinfo is None:
            raise ValueError("probe timestamp must include a timezone")
        if self.latency_ms is not None and self.latency_ms < 0:
            raise ValueError("probe latency must be non-negative")
        for value in (self.desired_replicas, self.ready_replicas):
            if value is not None and value < 0:
                raise ValueError("replica evidence must be non-negative")


class HealthProbe(Protocol):
    def probe(self, check: CheckSpec) -> ProbeResult:
        """Evaluate one allow-listed check without returning sensitive material."""


class UnavailableHealthProbe:
    def probe(self, check: CheckSpec) -> ProbeResult:
        raise RuntimeError("live cluster adapter is unavailable")


@dataclass(frozen=True)
class _Subject:
    id: str
    display_name: str
    dependencies: tuple[str, ...]
    checks: tuple[CheckSpec, ...]
    remediation: str


class HealthEngine:
    """Evaluate roots before consumers and suppress downstream symptoms."""

    def __init__(
        self,
        registry: ComponentRegistry,
        probe: HealthProbe | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
        stale_after: timedelta = timedelta(minutes=5),
        max_probe_timeout: float = 30.0,
        max_workers: int = 8,
        aggregate_timeout: float | None = None,
    ) -> None:
        self._registry = registry
        self._probe = probe or UnavailableHealthProbe()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._stale_after = stale_after
        self._max_probe_timeout = max_probe_timeout
        self._max_workers = max(1, max_workers)
        self._aggregate_timeout = (
            max_probe_timeout if aggregate_timeout is None else aggregate_timeout
        )

    def document(self) -> dict:
        now = self._clock()
        subjects = self._subjects()
        executor = ThreadPoolExecutor(
            max_workers=self._max_workers, thread_name_prefix="health-probe"
        )
        deadline = time.monotonic() + max(0.0, self._aggregate_timeout)
        items: list[dict] = []
        results: dict[str, dict] = {}
        for subject in subjects:
            failed_dependency = next(
                (
                    dependency
                    for dependency in subject.dependencies
                    if results[dependency]["state"] != "healthy"
                ),
                None,
            )
            blocked_root = None
            if failed_dependency:
                blocked_root = results[failed_dependency].get(
                    "rootCause", failed_dependency
                )
            runnable = tuple(
                check for check in subject.checks
                if not failed_dependency or check.layer == "workload"
            )
            started = {check.id: time.monotonic() for check in runnable}
            futures = {
                executor.submit(self._probe.probe, check): check
                for check in runnable
            }
            done, pending = wait(
                futures, timeout=max(0.0, deadline - time.monotonic())
            )
            for future in pending:
                future.cancel()
            evidence = [
                self._result(
                    check, future, future in done, now, started[check.id]
                )
                for future, check in futures.items()
            ]
            if failed_dependency:
                evidence.append(self._dependency_evidence(failed_dependency, now))
                evidence.extend(
                    self._unavailable_evidence(check, failed_dependency, now)
                    for check in subject.checks if check not in runnable
                )
            item = self._evaluate(
                subject, now, evidence,
                blocked_by=failed_dependency, blocked_root=blocked_root,
            )
            results[subject.id] = item
            items.append(item)
        executor.shutdown(wait=False, cancel_futures=True)

        aggregate = self._aggregate(items)
        return {
            "apiVersion": API_VERSION,
            "kind": "EnvironmentHealth",
            "generatedAt": _timestamp(now),
            "evidence": {
                "source": (
                    "unavailable"
                    if isinstance(self._probe, UnavailableHealthProbe)
                    else "live-cluster"
                ),
                "validation": "runtime-observation",
            },
            "state": aggregate,
            "summary": self._summary(items),
            "items": items,
        }

    def _evaluate(
        self, subject: _Subject, now: datetime, evidence: list[dict],
        *, blocked_by: str | None = None, blocked_root: str | None = None,
    ) -> dict:
        required = [entry for entry in evidence if entry["required"]]
        state = "healthy"
        root: str | None = None
        for candidate in (
            "unhealthy", "misconfigured", "unreachable", "unknown", "stale",
            "stopped", "starting", "degraded",
        ):
            match = next(
                (entry for entry in required if entry["state"] == candidate), None
            )
            if match:
                state = candidate
                root = f"{subject.id}/{match['id']}"
                break
        if state == "healthy" and any(
            entry["state"] != "healthy" for entry in evidence
        ):
            state = "degraded"
            root = f"{subject.id}/" + next(
                entry["id"] for entry in evidence if entry["state"] != "healthy"
            )
        local_roots = [
            f"{subject.id}/{entry['id']}" for entry in required
            if entry["layer"] != "dependency"
            and (
                entry["state"] in {"unhealthy", "misconfigured", "unreachable", "stale"}
                or entry["layer"] == "workload" and entry["state"] == "degraded"
                or not blocked_by and entry["state"] == "unknown"
            )
        ]
        roots = list(dict.fromkeys(([blocked_root] if blocked_root else []) + local_roots))
        if blocked_by and not local_roots:
            state = "blocked"
        item = self._base(subject, state, evidence, now)
        if roots:
            item["rootCause"] = roots[0]
            item["rootCauses"] = roots
        if blocked_by:
            item["blockedBy"] = blocked_by
        item["dimensions"] = self._dimensions(evidence, blocked_by)
        return item

    def _result(
        self,
        check: CheckSpec,
        future: Future[ProbeResult],
        completed: bool,
        now: datetime,
        started: float,
    ) -> dict:
        try:
            if not completed:
                raise TimeoutError
            result = future.result()
            age = now - result.observed_at.astimezone(timezone.utc)
            state = "stale" if age > self._stale_after else result.state
            summary = (
                "Evidence is older than the freshness threshold"
                if state == "stale"
                else _safe_summary(result.summary)
            )
            observed_at = result.observed_at
        except TimeoutError:
            state, summary, observed_at = (
                "unknown",
                "Check exceeded the aggregate bounded deadline",
                now,
            )
        except Exception:
            state, summary, observed_at = (
                "unknown",
                "Check could not obtain safe evidence",
                now,
            )
        measured_latency = max(0, round((time.monotonic() - started) * 1000))
        entry = {
            "id": check.id,
            "layer": check.layer,
            "state": state,
            "required": check.required,
            "summary": summary,
            "observedAt": _timestamp(observed_at),
            "latencyMs": (
                result.latency_ms
                if "result" in locals() and result.latency_ms is not None
                else measured_latency
            ),
        }
        if "result" in locals() and check.layer == "workload":
            entry["workload"] = {
                "present": result.workload_present,
                "desiredReplicas": result.desired_replicas,
                "readyReplicas": result.ready_replicas,
            }
        return entry

    @staticmethod
    def _dependency_evidence(dependency: str, now: datetime) -> dict:
        return {
                "id": "dependency",
                "layer": "dependency",
                "state": "blocked",
                "required": True,
                "summary": f"Blocked by dependency {dependency}",
                "observedAt": _timestamp(now),
                "latencyMs": 0,
            }

    @staticmethod
    def _unavailable_evidence(check: CheckSpec, dependency: str, now: datetime) -> dict:
        return {
            "id": check.id, "layer": check.layer, "state": "unknown",
            "required": check.required,
            "summary": f"Probe unavailable while blocked by dependency {dependency}",
            "observedAt": _timestamp(now), "latencyMs": 0,
        }

    @staticmethod
    def _dimensions(evidence: list[dict], blocked_by: str | None) -> dict:
        workload = [entry for entry in evidence if entry["layer"] == "workload"]
        application = [entry for entry in evidence if entry["layer"] in {"application", "functional"}]
        absent = any(entry.get("workload", {}).get("present") is False for entry in workload)
        mismatch = any(
            entry.get("workload", {}).get("present") is True
            and entry.get("workload", {}).get("desiredReplicas") is not None
            and entry.get("workload", {}).get("readyReplicas")
            < entry.get("workload", {}).get("desiredReplicas")
            for entry in workload
        )
        workload_state = "absent" if absent else "not-ready" if mismatch else (
            "ready" if workload and all(entry["state"] == "healthy" for entry in workload)
            else "unknown"
        )
        application_state = "unknown" if not application or any(
            entry["state"] in {"unknown", "stale"} for entry in application
        ) else "healthy" if all(entry["state"] == "healthy" for entry in application) else "unhealthy"
        return {
            "dependency": {"state": "blocked" if blocked_by else "clear", "blockedBy": blocked_by},
            "workload": {"state": workload_state},
            "application": {"state": application_state},
        }

    @staticmethod
    def _base(
        subject: _Subject, state: str, evidence: list[dict], now: datetime
    ) -> dict:
        return {
            "id": subject.id,
            "displayName": subject.display_name,
            "state": state,
            "dependencies": list(subject.dependencies),
            "checkedAt": _timestamp(now),
            "evidence": evidence,
            "remediation": {
                "summary": "Open the health guide for safe diagnostic steps",
                "href": subject.remediation,
                "safe": True,
            },
        }

    @staticmethod
    def _aggregate(items: list[dict]) -> str:
        states = {item["state"] for item in items}
        for state in (
            "unhealthy", "misconfigured", "unreachable", "unknown", "stale",
            "stopped", "starting", "degraded", "blocked",
        ):
            if state in states:
                return state
        return "healthy"

    @staticmethod
    def _summary(items: list[dict]) -> dict:
        components = [item for item in items if item["id"] not in {
            "microk8s-node", "storage", "dns", "ingress", "tls"
        }]
        return {
            "components": len(components),
            "blocked": sum(item["dimensions"]["dependency"]["state"] == "blocked" for item in components),
            "workloadAbsent": sum(item["dimensions"]["workload"]["state"] == "absent" for item in components),
            "workloadNotReady": sum(item["dimensions"]["workload"]["state"] == "not-ready" for item in components),
            "applicationUnknown": sum(item["dimensions"]["application"]["state"] == "unknown" for item in components),
        }

    def _subjects(self) -> tuple[_Subject, ...]:
        infrastructure = _infrastructure_subjects()
        component_dependencies = {
            "mysql": ("storage", "dns", "tls"),
            "postgresql": ("storage", "dns"),
            "lim": ("dns", "ingress", "tls"),
            "ssc": ("dns", "ingress", "tls"),
            "scancentral-sast": ("dns", "ingress", "tls"),
            "scancentral-dast-core": ("dns", "ingress", "tls"),
            "scancentral-dast-scanner": ("dns",),
        }
        components: list[_Subject] = []
        for component_id in self._registry.dependency_order():
            component = self._registry.component(component_id)
            checks = tuple(
                CheckSpec(
                    id=check["id"],
                    subject_id=component_id,
                    layer=_component_layer(check["type"]),
                    probe_type=check["type"],
                    target=check["target"],
                    timeout_seconds=min(float(check["timeoutSeconds"]), 30.0),
                    required=check["required"],
                )
                for check in component["health"]["checks"]
                if check["required"]
            )
            dependencies = (
                component_dependencies.get(component_id, ())
                + tuple(component["dependencies"])
            )
            components.append(
                _Subject(
                    component_id,
                    component["displayName"],
                    dependencies,
                    checks,
                    f"/docs/health-checks.md#{component_id}",
                )
            )
        return infrastructure + tuple(components)


def _infrastructure_subjects() -> tuple[_Subject, ...]:
    definitions = (
        ("microk8s-node", "MicroK8s node", (), "infrastructure", "node-ready", "node"),
        ("storage", "Storage", ("microk8s-node",), "storage", "storage-ready", "default"),
        ("dns", "Cluster DNS", ("microk8s-node",), "network", "dns-lookup", "kubernetes.default"),
        ("ingress", "Ingress", ("dns",), "network", "ingress-ready", "ingress"),
        ("tls", "TLS", ("ingress",), "network", "tls-valid", "managed-hosts"),
    )
    return tuple(
        _Subject(
            subject_id,
            name,
            dependencies,
            (
                CheckSpec(
                    check_id,
                    subject_id,
                    layer,
                    check_id,
                    target,
                    10.0,
                ),
            ),
            f"/docs/health-checks.md#{subject_id}",
        )
        for subject_id, name, dependencies, layer, check_id, target in definitions
    )


def _component_layer(probe_type: str) -> str:
    return {
        "workload-ready": "workload",
        "persistent-volume": "storage",
        "native-readiness": "application",
        "database-query": "application",
        "https": "application",
        "tcp": "functional",
        "application-ready": "application",
        "dependency-connectivity": "dependency",
        "configuration": "functional",
        "registration": "functional",
    }[probe_type]


def _safe_summary(value: str) -> str:
    text = " ".join(str(value).split())
    if not text or len(text) > 256 or _SENSITIVE.search(text):
        return "Probe returned evidence that could not be safely displayed"
    return text


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
