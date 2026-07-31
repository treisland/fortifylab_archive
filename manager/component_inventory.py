"""Safe desired and observed component inventory contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, Sequence

from manager.component_registry import ComponentRegistry


API_VERSION = "fortifylab.io/v1alpha1"
NAMESPACE = "fortify"
OBSERVED_STATES = frozenset({"present", "absent", "unknown"})


@dataclass(frozen=True)
class ResourceIdentity:
    """Allow-listed identity passed to a cluster observation adapter."""

    component_id: str
    resource_id: str
    kind: str
    name: str
    namespace: str = NAMESPACE


@dataclass(frozen=True)
class ResourceObservation:
    """Sanitized cluster evidence for one desired resource."""

    resource_id: str
    state: str
    kind: str
    name: str
    namespace: str = NAMESPACE

    def __post_init__(self) -> None:
        if self.state not in OBSERVED_STATES:
            raise ValueError("unsupported observed resource state")


class ClusterUnavailable(RuntimeError):
    """The allow-listed cluster observer could not determine current state."""


class ClusterObserver(Protocol):
    """Technology-neutral, read-only cluster observation boundary."""

    def observe(
        self, resources: Sequence[ResourceIdentity]
    ) -> Sequence[ResourceObservation]:
        """Return exactly one sanitized observation per desired resource."""


class UnavailableClusterObserver:
    """Fail-closed default used when no cluster adapter is configured."""

    def observe(
        self, resources: Sequence[ResourceIdentity]
    ) -> Sequence[ResourceObservation]:
        raise ClusterUnavailable("cluster observation is unavailable")


class ComponentInventory:
    """Build an API-safe projection from registry intent and cluster evidence."""

    def __init__(
        self,
        registry: ComponentRegistry,
        observer: ClusterObserver | None = None,
    ) -> None:
        self._registry = registry
        self._observer = observer or UnavailableClusterObserver()

    def document(self) -> dict:
        desired = self._desired_resources()
        observation_status = "available"
        metadata: dict = {}
        started_at = datetime.now(timezone.utc)
        try:
            observations = self._validated_observations(
                self._observer.observe(tuple(resource for _, resource in desired)),
                {resource.resource_id for _, resource in desired},
            )
            evidence = getattr(self._observer, "evidence", lambda: None)()
            if evidence is not None:
                metadata = {
                    "node": evidence.node,
                    "namespace": evidence.namespace,
                    "kubernetesVersion": evidence.kubernetes_version,
                    "observedAt": evidence.observed_at.astimezone(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "ageSeconds": max(
                        0,
                        round(
                            (
                                datetime.now(timezone.utc) - evidence.observed_at
                            ).total_seconds()
                        ),
                    ),
                    "latencyMs": max(
                        evidence.latency_ms,
                        round(
                            (
                                datetime.now(timezone.utc) - started_at
                            ).total_seconds()
                            * 1000
                        ),
                    ),
                }
        except Exception:
            observation_status = "unavailable"
            observations = {}

        items = []
        for component_id in self._registry.component_ids:
            component = self._registry.component(component_id)
            component_resources = []
            for owner, resource in desired:
                if owner != component_id:
                    continue
                observed = observations.get(resource.resource_id)
                component_resources.append(
                    {
                        "id": resource.resource_id,
                        "kind": resource.kind,
                        "name": resource.name,
                        "namespace": resource.namespace,
                        "state": observed.state if observed else "unknown",
                    }
                )
            items.append(
                {
                    "identity": {
                        "id": component_id,
                        "displayName": component["displayName"],
                    },
                    "version": component["version"],
                    "dependencies": list(component["dependencies"]),
                    "desiredState": {
                        "state": "present",
                        "resources": [
                            {
                                "id": resource["id"],
                                "kind": resource["kind"],
                                "name": resource["name"],
                                "namespace": resource["namespace"],
                            }
                            for resource in component_resources
                        ],
                    },
                    "observedResources": component_resources,
                }
            )
        return {
            "apiVersion": API_VERSION,
            "kind": "ComponentInventory",
            "observation": {
                "state": observation_status,
                **metadata,
                "latencyMs": metadata.get(
                    "latencyMs",
                    max(
                        0,
                        round(
                            (
                                datetime.now(timezone.utc) - started_at
                            ).total_seconds()
                            * 1000
                        ),
                    ),
                ),
            },
            "items": items,
        }

    def _desired_resources(self) -> list[tuple[str, ResourceIdentity]]:
        resources = []
        for component_id in self._registry.component_ids:
            for workload in self._registry.component(component_id)["workloads"]:
                resources.append(
                    (
                        component_id,
                        ResourceIdentity(
                            component_id=component_id,
                            resource_id=f"{component_id}/{workload['id']}",
                            kind=workload["kind"],
                            name=workload["name"],
                        ),
                    )
                )
        return resources

    @staticmethod
    def _validated_observations(
        observed: Sequence[ResourceObservation],
        expected_ids: set[str],
    ) -> dict[str, ResourceObservation]:
        result: dict[str, ResourceObservation] = {}
        for item in observed:
            if item.resource_id in result:
                raise ClusterUnavailable("cluster observation is inconsistent")
            result[item.resource_id] = item
        if set(result) != expected_ids:
            raise ClusterUnavailable("cluster observation is incomplete")
        return result
