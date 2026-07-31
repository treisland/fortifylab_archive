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

    def __post_init__(self) -> None:
        if self.state not in _PROBE_STATES:
            raise ValueError("unsupported probe state")
        if self.observed_at.tzinfo is None:
            raise ValueError("probe timestamp must include a timezone")
        if self.latency_ms is not None and self.latency_ms < 0:
            raise ValueError("probe latency must be non-negative")


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
            if failed_dependency:
                root = results[failed_dependency].get("rootCause", failed_dependency)
                item = self._blocked(subject, failed_dependency, root, now)
            else:
                started = {check.id: time.monotonic() for check in subject.checks}
                futures = {
                    executor.submit(self._probe.probe, check): check
                    for check in subject.checks
                }
                done, pending = wait(
                    futures, timeout=max(0.0, deadline - time.monotonic())
                )
                for future in pending:
                    future.cancel()
                item = self._evaluate(
                    subject,
                    now,
                    [
                        self._result(
                            check,
                            future,
                            future in done,
                            now,
                            started[check.id],
                        )
                        for future, check in futures.items()
                    ],
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
            "items": items,
        }

    def _evaluate(
        self, subject: _Subject, now: datetime, evidence: list[dict]
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
        item = self._base(subject, state, evidence, now)
        if root:
            item["rootCause"] = root
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
        return {
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

    @staticmethod
    def _blocked(
        subject: _Subject, dependency: str, root: str, now: datetime
    ) -> dict:
        evidence = [
            {
                "id": "dependency",
                "layer": "dependency",
                "state": "blocked",
                "required": True,
                "summary": f"Blocked by dependency {dependency}",
                "observedAt": _timestamp(now),
                "latencyMs": 0,
            }
        ]
        item = HealthEngine._base(subject, "blocked", evidence, now)
        item["blockedBy"] = dependency
        item["rootCause"] = root
        return item

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
