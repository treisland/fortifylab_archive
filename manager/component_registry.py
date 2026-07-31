"""Read-only access to the authoritative Fortify component registry."""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Any, Iterable

from manager.platform_profiles import PlatformProfile, PlatformProfileError


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "registry" / "components.json"


class RegistryError(ValueError):
    """The component registry is internally inconsistent."""


class ComponentRegistry:
    """Shared component definitions for lifecycle and monitoring consumers."""

    def __init__(
        self, document: dict[str, Any], profile: PlatformProfile | None = None
    ) -> None:
        self.document = document
        self.profile = profile
        components = document.get("components", [])
        self._components = {component["id"]: component for component in components}

    @classmethod
    def load(cls, path: Path = DEFAULT_REGISTRY) -> "ComponentRegistry":
        """Load and validate the registry through its sole runtime entry point."""
        try:
            with path.open(encoding="utf-8") as stream:
                document = json.load(stream)
        except (OSError, json.JSONDecodeError) as error:
            raise RegistryError("component registry is unavailable or malformed") from error
        if not isinstance(document, dict):
            raise RegistryError("component registry is malformed")

        # Imported lazily because semantic validation uses ComponentRegistry for
        # dependency-cycle checks.
        from manager.registry_validation import validate_registry

        try:
            profile = PlatformProfile.load(document.get("profileRef", ""))
        except PlatformProfileError as error:
            raise RegistryError("component registry platform profile is invalid") from error
        errors = validate_registry(document, ROOT, profile)
        if errors:
            raise RegistryError(f"component registry is invalid: {errors[0]}")
        return cls(document, profile)

    @property
    def component_ids(self) -> tuple[str, ...]:
        return tuple(self._components)

    def component(self, component_id: str) -> dict[str, Any]:
        try:
            return self._components[component_id]
        except KeyError as error:
            raise RegistryError(f"unknown component: {component_id}") from error

    def lifecycle_operations(self, component_id: str) -> tuple[dict[str, Any], ...]:
        """Return lifecycle capabilities without adding runtime state."""
        return tuple(self.component(component_id)["operations"])

    def monitoring_checks(self, component_id: str) -> tuple[dict[str, Any], ...]:
        """Return the same component's declared health evidence."""
        return tuple(self.component(component_id)["health"]["checks"])

    def dependency_order(self, selected: Iterable[str] | None = None) -> tuple[str, ...]:
        """Return dependencies before consumers, rejecting cycles and gaps."""
        requested = set(selected or self._components)
        closure: set[str] = set()

        def include(component_id: str) -> None:
            component = self.component(component_id)
            if component_id in closure:
                return
            closure.add(component_id)
            for dependency in component["dependencies"]:
                include(dependency)

        for component_id in requested:
            include(component_id)

        indegree = {component_id: 0 for component_id in closure}
        consumers = {component_id: [] for component_id in closure}
        for component_id in closure:
            for dependency in self.component(component_id)["dependencies"]:
                indegree[component_id] += 1
                consumers[dependency].append(component_id)

        ready = deque(
            component_id
            for component_id in self._components
            if component_id in closure and indegree[component_id] == 0
        )
        ordered: list[str] = []
        while ready:
            dependency = ready.popleft()
            ordered.append(dependency)
            for consumer in consumers[dependency]:
                indegree[consumer] -= 1
                if indegree[consumer] == 0:
                    ready.append(consumer)
        if len(ordered) != len(closure):
            cyclic = sorted(component_id for component_id, value in indegree.items() if value)
            raise RegistryError(f"dependency cycle involves: {', '.join(cyclic)}")
        return tuple(ordered)
