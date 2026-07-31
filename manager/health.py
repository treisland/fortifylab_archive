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

_DIRECT_PRECEDENCE = (
    "unhealthy", "misconfigured", "stopped", "unreachable", "unknown",
    "stale", "starting", "degraded",
)
_DOMAIN_LAYERS = {
    "infrastructure": ("infrastructure",),
    "workload": ("workload",),
    "persistence": ("storage",),
    "internalService": ("internal-service", "dependency"),
    "application": ("application", "functional"),
    "ingressTls": ("ingress-tls",),
    "externalReachability": ("external-reachability",),
}


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
    dependencies: tuple[str, ...] = ()


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
        availability: dict | None = None,
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
        self._availability = availability or {}

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
            blocked_checks = {
                check.id: tuple(
                    dependency for dependency in check.dependencies
                    if self._dependency_blocks(dependency, results)
                )
                for check in subject.checks
            }
            runnable = tuple(check for check in subject.checks if not blocked_checks[check.id])
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
            blocked_dependencies = tuple(dict.fromkeys(
                dependency
                for check in subject.checks
                for dependency in blocked_checks[check.id]
            ))
            evidence.extend(
                self._unavailable_evidence(check, blocked_checks[check.id], now)
                for check in subject.checks if blocked_checks[check.id]
            )
            evidence.extend(self._external_evidence(subject, now))
            item = self._evaluate(subject, now, evidence, results, blocked_dependencies)
            results[subject.id] = item
            items.append(item)
        executor.shutdown(wait=False, cancel_futures=True)

        for item in items:
            item["downstreamImpact"] = sorted(
                consumer["id"] for consumer in items
                if any(
                    item["id"] in entry.get("blockedBy", [])
                    for entry in consumer["evidence"]
                )
            )

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
        self,
        subject: _Subject,
        now: datetime,
        evidence: list[dict],
        results: dict[str, dict],
        blocked_dependencies: tuple[str, ...],
    ) -> dict:
        required = [entry for entry in evidence if entry["required"]]
        direct = [
            entry for entry in required
            if entry["layer"] not in {
                "dependency", "ingress-tls", "external-reachability"
            }
            and not entry.get("derived", False)
        ]
        direct_state = self._rank_state(direct)
        access = [
            entry for entry in required
            if entry["layer"] in {"ingress-tls", "external-reachability"}
        ]
        access_state = self._rank_state(access)
        if direct_state != "healthy":
            state = direct_state
        elif blocked_dependencies:
            state = "blocked"
        elif access_state != "healthy":
            state = "degraded"
        elif any(entry["state"] != "healthy" for entry in evidence):
            state = "degraded"
        else:
            state = "healthy"

        local_roots = [
            f"{subject.id}/{entry['id']}" for entry in required
            if entry["state"] != "healthy" and not entry.get("derived", False)
        ]
        dependency_roots = [
            results[dependency].get("rootCause", dependency)
            for dependency in blocked_dependencies
        ]
        roots = list(dict.fromkeys(dependency_roots + local_roots))
        item = self._base(subject, state, evidence, now)
        if roots:
            item["rootCause"] = roots[0]
            item["rootCauses"] = roots
        if blocked_dependencies:
            item["blockedBy"] = blocked_dependencies[0]
        item["directState"] = direct_state
        item["affectedDomains"] = [
            name for name, domain in self._domains(evidence).items()
            if domain["state"] not in {"healthy", "not-applicable"}
        ]
        item["domains"] = self._domains(evidence)
        item["downstreamImpact"] = []
        item["dimensions"] = self._dimensions(
            evidence, blocked_dependencies[0] if blocked_dependencies else None
        )
        return item

    @staticmethod
    def _rank_state(evidence: list[dict]) -> str:
        states = {entry["state"] for entry in evidence}
        for candidate in _DIRECT_PRECEDENCE:
            if candidate in states:
                return candidate
        return "healthy"

    @classmethod
    def _domains(cls, evidence: list[dict]) -> dict[str, dict]:
        domains = {}
        for name, layers in _DOMAIN_LAYERS.items():
            entries = [entry for entry in evidence if entry["layer"] in layers]
            if not entries:
                domains[name] = {
                    "state": "not-applicable", "rootCause": None, "direct": True,
                }
                continue
            state = cls._rank_state(entries)
            failed = next((entry for entry in entries if entry["state"] != "healthy"), None)
            domains[name] = {
                "state": state,
                "rootCause": failed["id"] if failed else None,
                "direct": not any(entry.get("derived", False) for entry in entries),
            }
        return domains

    @staticmethod
    def _dependency_blocks(dependency: str, results: dict[str, dict]) -> bool:
        item = results.get(dependency)
        if item is None:
            return True
        domains = item.get("domains", {})
        if dependency in {"microk8s-node", "storage", "dns", "ingress", "tls"}:
            return item["state"] != "healthy"
        relevant = (
            domains.get("workload", {}).get("state"),
            domains.get("persistence", {}).get("state"),
            domains.get("internalService", {}).get("state"),
            domains.get("application", {}).get("state"),
        )
        return any(state not in {"healthy", "not-applicable"} for state in relevant)

    def _external_evidence(self, subject: _Subject, now: datetime) -> list[dict]:
        item = next(
            (
                entry for entry in self._availability.get("items", [])
                if entry.get("id") == subject.id
            ),
            None,
        )
        if item is None:
            return []
        external_state = {
            "reachable": "healthy",
            "degraded": "degraded",
            "tls-warning": "degraded",
            "dns-mismatch": "unreachable",
            "unreachable": "unreachable",
            "not-configured": "unknown",
            "unknown": "unknown",
        }.get(item.get("state"), "unknown")
        tls_state = {
            "valid": "healthy",
            "warning": "degraded",
            "failed": "unreachable",
            "not-configured": "unknown",
            "not-attempted": "unknown",
        }.get(item.get("tls"), "unknown")
        observed = item.get("checkedAt") or _timestamp(now)
        try:
            observed_time = datetime.fromisoformat(observed.replace("Z", "+00:00"))
            if now - observed_time.astimezone(timezone.utc) > self._stale_after:
                external_state = "stale"
                tls_state = "stale"
        except (AttributeError, TypeError, ValueError):
            observed = _timestamp(now)
            external_state = "unknown"
            tls_state = "unknown"
        evidence = [{
                "id": "external-route",
                "layer": "external-reachability",
                "state": external_state,
                "required": True,
                "summary": _safe_summary(item.get("summary", "External route evidence unavailable")),
                "observedAt": observed,
                "latencyMs": max(0, int(item.get("latencyMs") or 0)),
            }]
        if item.get("tls") in {"valid", "warning", "failed"}:
            evidence.append({
                "id": "ingress-tls",
                "layer": "ingress-tls",
                "state": tls_state,
                "required": True,
                "summary": "TLS evidence is reported independently from application health",
                "observedAt": observed,
                "latencyMs": 0,
            })
        return evidence

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
    def _unavailable_evidence(
        check: CheckSpec, dependencies: tuple[str, ...], now: datetime
    ) -> dict:
        return {
            "id": check.id, "layer": check.layer, "state": "unknown",
            "required": check.required,
            "summary": "Probe unavailable while a relevant dependency is unhealthy",
            "observedAt": _timestamp(now), "latencyMs": 0,
            "derived": True,
            "blockedBy": list(dependencies),
        }

    @staticmethod
    def _dimensions(evidence: list[dict], blocked_by: str | None) -> dict:
        workload = [entry for entry in evidence if entry["layer"] == "workload"]
        application = [
            entry for entry in evidence
            if entry["layer"] in {"internal-service", "application", "functional"}
        ]
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
        components: list[_Subject] = []
        for component_id in self._registry.dependency_order():
            component = self._registry.component(component_id)
            component_dependencies = tuple(component["dependencies"])
            checks = tuple(
                CheckSpec(
                    id=check["id"],
                    subject_id=component_id,
                    layer=_component_layer(check["type"]),
                    probe_type=check["type"],
                    target=check["target"],
                    timeout_seconds=min(float(check["timeoutSeconds"]), 30.0),
                    required=check["required"],
                    dependencies=_component_check_dependencies(
                        _component_layer(check["type"]), component_dependencies
                    ),
                )
                for check in component["health"]["checks"]
                if check["required"]
            )
            dependencies = tuple(dict.fromkeys(
                ("microk8s-node", "dns") + component_dependencies
                + (("storage",) if any(check.layer == "storage" for check in checks) else ())
            ))
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
        ("dns", "In-cluster DNS", ("microk8s-node",), "internal-service", "dns-lookup", "kubernetes.default"),
        ("ingress", "Ingress routing", ("microk8s-node",), "ingress-tls", "ingress-ready", "ingress"),
        ("tls", "TLS", ("ingress",), "ingress-tls", "tls-valid", "managed-hosts"),
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
                    dependencies=dependencies,
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
        "https": "internal-service",
        "tcp": "functional",
        "application-ready": "application",
        "dependency-connectivity": "internal-service",
        "configuration": "functional",
        "registration": "functional",
    }[probe_type]


def _component_check_dependencies(
    layer: str, component_dependencies: tuple[str, ...]
) -> tuple[str, ...]:
    if layer == "workload":
        return ("microk8s-node",)
    if layer == "storage":
        return ("microk8s-node", "storage")
    return tuple(dict.fromkeys(
        ("microk8s-node", "dns") + component_dependencies
    ))


def _safe_summary(value: str) -> str:
    text = " ".join(str(value).split())
    if not text or len(text) > 256 or _SENSITIVE.search(text):
        return "Probe returned evidence that could not be safely displayed"
    return text


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
