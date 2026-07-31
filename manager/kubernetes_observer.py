"""Bounded, namespace-scoped Kubernetes metadata observation."""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from manager.component_inventory import (
    ClusterUnavailable,
    ResourceIdentity,
    ResourceObservation,
)
from manager.component_registry import ComponentRegistry
from manager.health import CheckSpec, ProbeResult
from manager.preflight import PreflightCheck, PreflightResult


NAMESPACE = "fortify"
_WORKLOAD_PATHS = {
    "Deployment": "apis/apps/v1/namespaces/{namespace}/deployments/{name}",
    "StatefulSet": "apis/apps/v1/namespaces/{namespace}/statefulsets/{name}",
}


@dataclass(frozen=True)
class ClusterEvidence:
    node: str
    namespace: str
    kubernetes_version: str
    observed_at: datetime
    latency_ms: int


class KubernetesObserver:
    """One fixed-namespace observer implementing all manager read boundaries."""

    def __init__(
        self,
        server: str,
        token_file: Path,
        ca_file: Path,
        registry: ComponentRegistry,
        *,
        namespace: str = NAMESPACE,
        timeout_seconds: float = 5.0,
    ) -> None:
        if namespace != NAMESPACE:
            raise ValueError("only the managed fortify namespace is supported")
        if not server.startswith("https://") or "?" in server or "#" in server:
            raise ValueError("cluster server must be an HTTPS origin")
        self._server = server.rstrip("/")
        self._token_file = token_file
        self._context = ssl.create_default_context(cafile=str(ca_file))
        self._registry = registry
        self._namespace = namespace
        self._timeout = min(max(float(timeout_seconds), 0.1), 10.0)
        self._workloads = {
            (component["id"], workload["id"]): workload
            for component in (
                registry.component(component_id)
                for component_id in registry.component_ids
            )
            for workload in component["workloads"]
        }

    def observe(
        self, resources: Sequence[ResourceIdentity]
    ) -> Sequence[ResourceObservation]:
        observations = []
        for resource in resources:
            self._validate_resource(resource)
            try:
                self._get(
                    _WORKLOAD_PATHS[resource.kind].format(
                        namespace=self._namespace,
                        name=urllib.parse.quote(resource.name, safe=""),
                    )
                )
                state = "present"
            except urllib.error.HTTPError as error:
                if error.code == 404:
                    state = "absent"
                    error.close()
                else:
                    error.close()
                    raise ClusterUnavailable("cluster observation failed") from error
            observations.append(
                ResourceObservation(
                    resource.resource_id,
                    state,
                    resource.kind,
                    resource.name,
                    self._namespace,
                )
            )
        return tuple(observations)

    def evidence(self) -> ClusterEvidence:
        started = time.monotonic()
        version = self._get("version")
        nodes = self._get("api/v1/nodes")
        names = sorted(
            item.get("metadata", {}).get("name", "")
            for item in nodes.get("items", [])
            if item.get("metadata", {}).get("name")
        )
        if not names or not isinstance(version.get("gitVersion"), str):
            raise ClusterUnavailable("cluster evidence is malformed")
        return ClusterEvidence(
            node=names[0],
            namespace=self._namespace,
            kubernetes_version=version["gitVersion"],
            observed_at=datetime.now(timezone.utc),
            latency_ms=max(0, round((time.monotonic() - started) * 1000)),
        )

    def diagnose_access(self, resources: Sequence[ResourceIdentity]) -> ClusterEvidence:
        """Verify positive and negative permissions without returning API bodies."""
        evidence = self.evidence()
        self.observe(resources)
        for path in (
            "apis/storage.k8s.io/v1/storageclasses",
            f"api/v1/namespaces/{self._namespace}/services",
            f"apis/networking.k8s.io/v1/namespaces/{self._namespace}/ingresses",
        ):
            self._get(path)
        for path in (
            f"api/v1/namespaces/{self._namespace}/secrets",
            "api/v1/namespaces/default/services",
            f"api/v1/namespaces/{self._namespace}/pods/access-check/log",
        ):
            try:
                self._get(path)
            except urllib.error.HTTPError as error:
                denied = error.code in {401, 403}
                error.close()
                if denied:
                    continue
            raise ClusterUnavailable("cluster observer has excessive permissions")
        return evidence

    def probe(self, check: CheckSpec | PreflightCheck) -> ProbeResult | PreflightResult:
        if isinstance(check, PreflightCheck):
            return self._preflight(check)
        now = datetime.now(timezone.utc)
        if check.subject_id == "microk8s-node":
            self.evidence()
            return ProbeResult("healthy", "MicroK8s node metadata is reachable", now)
        if check.subject_id in {"storage", "dns", "ingress"}:
            path = {
                "storage": "apis/storage.k8s.io/v1/storageclasses",
                "dns": f"api/v1/namespaces/{self._namespace}/services",
                "ingress": f"apis/networking.k8s.io/v1/namespaces/{self._namespace}/ingresses",
            }[check.subject_id]
            document = self._get(path)
            state = "healthy" if document.get("items") else "degraded"
            return ProbeResult(state, "Required Kubernetes metadata was observed", now)
        if check.subject_id == "tls":
            return ProbeResult(
                "degraded",
                "TLS contents are intentionally outside observer permissions",
                now,
            )
        workload = self._workloads.get((check.subject_id, check.target))
        if workload is None:
            return ProbeResult(
                "degraded",
                "Check requires application evidence outside metadata observation",
                now,
            )
        path = _WORKLOAD_PATHS[workload["kind"]].format(
            namespace=self._namespace,
            name=urllib.parse.quote(workload["name"], safe=""),
        )
        try:
            document = self._get(path)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return ProbeResult("unhealthy", "Desired workload is absent", now)
            raise
        desired = int(document.get("spec", {}).get("replicas", 1))
        ready = int(document.get("status", {}).get("readyReplicas", 0))
        state = "healthy" if desired > 0 and ready >= desired else "degraded"
        return ProbeResult(state, "Workload readiness metadata was observed", now)

    def _preflight(self, check: PreflightCheck) -> PreflightResult:
        paths = {
            "microk8s-status": "version",
            "storage-readiness": "apis/storage.k8s.io/v1/storageclasses",
            "ingress-readiness": (
                f"apis/networking.k8s.io/v1/namespaces/{self._namespace}/ingresses"
            ),
            "managed-dns": f"api/v1/namespaces/{self._namespace}/services",
        }
        path = paths.get(check.probe_type)
        if path is None:
            return PreflightResult("warning")
        document = self._get(path)
        if path == "version":
            return PreflightResult("pass" if document.get("gitVersion") else "fail")
        return PreflightResult("pass" if document.get("items") else "warning")

    def _validate_resource(self, resource: ResourceIdentity) -> None:
        expected = self._workloads.get((resource.component_id, resource.resource_id.split("/", 1)[-1]))
        if (
            resource.namespace != self._namespace
            or expected is None
            or resource.kind != expected["kind"]
            or resource.name != expected["name"]
        ):
            raise ClusterUnavailable("cluster request is outside the registry allow-list")

    def _get(self, path: str) -> dict[str, Any]:
        try:
            token = self._token_file.read_text(encoding="utf-8").strip()
            if not token or len(token) > 16384:
                raise ValueError
            request = urllib.request.Request(
                f"{self._server}/{path}",
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token}",
                },
                method="GET",
            )
            with urllib.request.urlopen(
                request, timeout=self._timeout, context=self._context
            ) as response:
                payload = response.read(2 * 1024 * 1024 + 1)
            if len(payload) > 2 * 1024 * 1024:
                raise ValueError
            document = json.loads(payload)
            if not isinstance(document, dict):
                raise ValueError
            return document
        except urllib.error.HTTPError:
            raise
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as error:
            raise ClusterUnavailable("cluster observation failed") from error
