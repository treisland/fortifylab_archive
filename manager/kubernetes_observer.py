"""Bounded, namespace-scoped Kubernetes metadata observation."""

from __future__ import annotations

import json
import re
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
from manager.availability import ObservedRoute
from manager.component_registry import ComponentRegistry
from manager.health import CheckSpec, HealthProbe, ProbeResult
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
        functional_probe: HealthProbe | None = None,
        public_address: str | None = None,
    ) -> None:
        if namespace != NAMESPACE:
            raise ValueError("only the managed fortify namespace is supported")
        if not server.startswith("https://") or "?" in server or "#" in server:
            raise ValueError("cluster server must be an HTTPS origin")
        self._server = server.rstrip("/")
        self._token_file = token_file
        self._context = ssl.create_default_context(cafile=str(ca_file))
        # MicroK8s clusters upgraded from older releases can retain a trusted
        # CA without the RFC 5280 keyUsage extension. OpenSSL strict mode
        # rejects that legacy extension shape. Preserve CA-chain and hostname
        # verification while accepting the documented MicroK8s CA.
        strict_flag = getattr(ssl, "VERIFY_X509_STRICT", 0)
        if strict_flag:
            self._context.verify_flags &= ~strict_flag
        self._registry = registry
        self._namespace = namespace
        self._timeout = min(max(float(timeout_seconds), 0.1), 10.0)
        self._functional_probe = functional_probe
        self._public_address = public_address
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
                document = self._get(
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
            release_name = chart_version = app_version = None
            image_versions: tuple[str, ...] = ()
            if state == "present":
                metadata = document.get("metadata", {})
                labels = metadata.get("labels", {}) if isinstance(metadata, dict) else {}
                annotations = (
                    metadata.get("annotations", {}) if isinstance(metadata, dict) else {}
                )
                if not isinstance(labels, dict):
                    labels = {}
                if not isinstance(annotations, dict):
                    annotations = {}
                release_name = self._safe_label(
                    labels.get("app.kubernetes.io/instance")
                    or annotations.get("meta.helm.sh/release-name")
                )
                chart = self._safe_label(labels.get("helm.sh/chart"))
                chart_match = re.search(r"-(\d[0-9A-Za-z.+_-]*)$", chart or "")
                chart_version = chart_match.group(1) if chart_match else None
                app_version = self._safe_label(labels.get("app.kubernetes.io/version"))
                containers = (
                    document.get("spec", {})
                    .get("template", {})
                    .get("spec", {})
                    .get("containers", [])
                )
                if isinstance(containers, list):
                    image_versions = tuple(
                        sorted(
                            {
                                version
                                for container in containers
                                if isinstance(container, dict)
                                for version in (
                                    self._safe_image_version(container.get("image")),
                                )
                                if version
                            }
                        )
                    )
            observations.append(
                ResourceObservation(
                    resource.resource_id,
                    state,
                    resource.kind,
                    resource.name,
                    self._namespace,
                    release_name,
                    chart_version,
                    app_version,
                    image_versions,
                )
            )
        return tuple(observations)

    @staticmethod
    def _safe_label(value: Any) -> str | None:
        if not isinstance(value, str) or not value or len(value) > 128:
            return None
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        return value if set(value) <= allowed else None

    @staticmethod
    def _safe_image_version(image: Any) -> str | None:
        """Return only a tag or digest; never disclose a registry/repository path."""
        if not isinstance(image, str) or not image or len(image) > 512:
            return None
        leaf = image.rsplit("/", 1)[-1]
        if "@" in leaf:
            value = leaf.split("@", 1)[1]
        elif ":" in leaf:
            value = leaf.rsplit(":", 1)[1]
        else:
            return None
        if not value or len(value) > 160:
            return None
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-:+")
        return value if set(value) <= allowed else None

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

    def installation_footprint(
        self, component_ids: tuple[str, ...]
    ) -> dict[str, str]:
        """Detect allow-listed workloads and retained PVCs without reading data."""
        result: dict[str, str] = {}
        for component_id in component_ids:
            component = self._registry.component(component_id)
            paths = [
                _WORKLOAD_PATHS[item["kind"]].format(
                    namespace=self._namespace,
                    name=urllib.parse.quote(item["name"], safe=""),
                )
                for item in component["workloads"]
            ]
            paths.extend(
                f"api/v1/namespaces/{self._namespace}/persistentvolumeclaims/"
                f"{urllib.parse.quote(item['claim'], safe='')}"
                for item in component["persistence"]
            )
            present = False
            for path in paths:
                try:
                    self._get(path)
                    present = True
                except urllib.error.HTTPError as error:
                    if error.code != 404:
                        error.close()
                        raise ClusterUnavailable(
                            "installation footprint observation failed"
                        ) from error
                    error.close()
            result[component_id] = "present" if present else "absent"
        return result

    def observed_routes(self) -> tuple[ObservedRoute, ...]:
        """Project only registry-approved Web ingress host and address metadata."""
        document = self._get(
            f"apis/networking.k8s.io/v1/namespaces/{self._namespace}/ingresses"
        )
        labels = {"lab": "manager"}
        labels.update(
            {
                component["web"]["hostLabel"]: component_id
                for component_id in self._registry.component_ids
                for component in (self._registry.component(component_id),)
                if component.get("web")
            }
        )
        routes = []
        for ingress in document.get("items", []):
            spec = ingress.get("spec", {})
            tls_hosts = {
                host
                for entry in spec.get("tls", [])
                for host in entry.get("hosts", [])
                if isinstance(host, str)
            }
            ingress_addresses = tuple(
                sorted(
                    {
                        address["ip"]
                        for address in ingress.get("status", {})
                        .get("loadBalancer", {})
                        .get("ingress", [])
                        if isinstance(address.get("ip"), str)
                    }
                )
            )
            for rule in spec.get("rules", []):
                host = rule.get("host")
                if not isinstance(host, str) or "." not in host:
                    continue
                endpoint_id = labels.get(host.split(".", 1)[0])
                if endpoint_id is not None:
                    routes.append(
                        ObservedRoute(
                            endpoint_id,
                            host,
                            host in tls_hosts,
                            (getattr(self, "_public_address", None),)
                            if getattr(self, "_public_address", None)
                            else ingress_addresses,
                            ingress_addresses=ingress_addresses,
                        )
                    )
        return tuple(routes)

    def diagnose_access(self, resources: Sequence[ResourceIdentity]) -> ClusterEvidence:
        """Verify positive and negative permissions without returning API bodies."""
        evidence = self.evidence()
        self.observe(resources)
        for path in (
            "apis/storage.k8s.io/v1/storageclasses",
            f"api/v1/namespaces/{self._namespace}/services",
            f"api/v1/namespaces/{self._namespace}/persistentvolumeclaims",
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
            document = self._get("api/v1/nodes")
            ready = any(
                condition.get("type") == "Ready" and condition.get("status") == "True"
                for item in document.get("items", [])
                for condition in item.get("status", {}).get("conditions", [])
            )
            return ProbeResult(
                "healthy" if ready else "unhealthy",
                "MicroK8s node reports Ready"
                if ready else "MicroK8s node does not report Ready",
                now,
            )
        if check.subject_id == "storage":
            document = self._get("apis/storage.k8s.io/v1/storageclasses")
            state = "healthy" if document.get("items") else "degraded"
            return ProbeResult(state, "Required Kubernetes metadata was observed", now)
        if check.subject_id in {"dns", "ingress", "tls"}:
            return self._functional(check, now)
        if check.probe_type == "persistent-volume":
            component = self._registry.component(check.subject_id)
            persistence = next(
                (
                    item for item in component["persistence"]
                    if item["id"] == check.target
                ),
                None,
            )
            if persistence is None:
                return ProbeResult(
                    "unknown", "Persistent volume target is not registered", now
                )
            name = urllib.parse.quote(persistence["claim"], safe="")
            try:
                document = self._get(
                    f"api/v1/namespaces/{self._namespace}/persistentvolumeclaims/{name}"
                )
            except urllib.error.HTTPError as error:
                if error.code == 404:
                    error.close()
                    return ProbeResult(
                        "unhealthy",
                        "Required persistent volume claim is absent",
                        now,
                    )
                raise
            phase = document.get("status", {}).get("phase")
            return ProbeResult(
                "healthy" if phase == "Bound" else "unhealthy",
                "Persistent volume claim is bound"
                if phase == "Bound"
                else "Persistent volume claim is not bound",
                now,
            )
        if check.probe_type != "workload-ready":
            return self._functional(check, now)
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
                error.close()
                return ProbeResult(
                    "unhealthy", "Desired workload is absent", now,
                    workload_present=False,
                )
            raise
        desired = int(document.get("spec", {}).get("replicas", 1))
        ready = int(document.get("status", {}).get("readyReplicas", 0))
        state = "healthy" if desired > 0 and ready >= desired else "degraded"
        return ProbeResult(
            state,
            f"Workload has {ready} of {desired} desired replicas ready",
            now,
            workload_present=True,
            desired_replicas=desired,
            ready_replicas=ready,
        )

    def _functional(self, check: CheckSpec, now: datetime) -> ProbeResult:
        if self._functional_probe is None:
            return ProbeResult(
                "unknown",
                "Protected functional probe service is unavailable",
                now,
            )
        return self._functional_probe.probe(check)

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
