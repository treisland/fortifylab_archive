"""Deterministic structural and cross-reference validation for the registry."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from manager.component_registry import ComponentRegistry, RegistryError
from manager.platform_profiles import PlatformProfile, PlatformProfileError


TOP_LEVEL_KEYS = {"$schema", "apiVersion", "kind", "scope", "profileRef", "components"}
COMPONENT_KEYS = {
    "id",
    "displayName",
    "version",
    "dependencies",
    "workloads",
    "operations",
    "secrets",
    "persistence",
    "health",
    "diagnostics",
}
SECRET_VALUE_KEYS = {"value", "data", "stringData", "contents", "password", "token"}


def _unique_ids(items: list[dict[str, Any]], label: str, errors: list[str]) -> set[str]:
    identifiers = [item.get("id") for item in items]
    duplicates = sorted({item for item in identifiers if identifiers.count(item) > 1})
    if duplicates:
        errors.append(f"{label} has duplicate ids: {', '.join(duplicates)}")
    return set(identifiers)


def validate_registry(
    document: dict[str, Any], root: Path, profile: PlatformProfile | None = None
) -> list[str]:
    """Return sanitized contract errors; an empty list means valid."""
    errors: list[str] = []
    if profile is None:
        try:
            profile = PlatformProfile.load(document.get("profileRef", ""))
        except PlatformProfileError:
            profile = None
    extra = set(document) - TOP_LEVEL_KEYS
    missing = TOP_LEVEL_KEYS - set(document)
    if extra:
        errors.append(f"registry has unsupported fields: {', '.join(sorted(extra))}")
    if missing:
        errors.append(f"registry is missing fields: {', '.join(sorted(missing))}")
    if document.get("$schema") != "schemas/component-registry.schema.json":
        errors.append("registry must reference the versioned local schema")
    if document.get("apiVersion") != "fortifylab.io/v1alpha1":
        errors.append("registry apiVersion must be fortifylab.io/v1alpha1")
    if document.get("kind") != "ComponentRegistry":
        errors.append("registry kind must be ComponentRegistry")
    if document.get("scope") != {"platform": "microk8s", "aspm": False}:
        errors.append("registry scope must be MicroK8s-first with ASPM excluded")
    if profile is None or document.get("profileRef") != profile.id:
        errors.append("registry must reference a loadable platform profile")
    elif profile.maturity == "unsupported":
        errors.append("registry cannot select an unsupported platform profile")

    components = document.get("components")
    if not isinstance(components, list) or not components:
        return errors + ["registry components must be a non-empty array"]
    component_ids = _unique_ids(components, "registry", errors)

    for component in components:
        component_id = component.get("id", "<missing>")
        prefix = f"component {component_id}"
        if set(component) != COMPONENT_KEYS:
            errors.append(f"{prefix} fields do not match component schema")
            continue
        version = component["version"]
        if (
            not isinstance(version, dict)
            or set(version) != {"chart", "images"}
            or not isinstance(version.get("chart"), str)
            or not version["chart"]
            or not isinstance(version.get("images"), dict)
            or any(
                not isinstance(name, str)
                or not name
                or not isinstance(value, str)
                or not value
                for name, value in version.get("images", {}).items()
            )
        ):
            errors.append(f"{prefix} version must contain chart and image pins")
        elif profile is not None:
            try:
                expected = profile.component_version(component_id)
            except Exception:
                errors.append(f"{prefix} is absent from the platform profile")
            else:
                if version != expected:
                    errors.append(
                        f"{prefix} version does not match platform profile"
                    )
        for field in ("dependencies", "workloads", "operations", "secrets", "persistence", "diagnostics"):
            if not isinstance(component[field], list):
                errors.append(f"{prefix} {field} must be an array")
        if any(not isinstance(component[field], list) for field in
               ("dependencies", "workloads", "operations", "secrets", "persistence", "diagnostics")):
            continue

        dependencies = component["dependencies"]
        if component_id in dependencies:
            errors.append(f"{prefix} cannot depend on itself")
        missing_dependencies = sorted(set(dependencies) - component_ids)
        if missing_dependencies:
            errors.append(f"{prefix} has unknown dependencies: {', '.join(missing_dependencies)}")

        workload_ids = _unique_ids(component["workloads"], f"{prefix} workloads", errors)
        if not workload_ids:
            errors.append(f"{prefix} must declare at least one workload")
        scalable = {
            workload["id"] for workload in component["workloads"] if workload.get("scalable") is True
        }

        health = component.get("health")
        if not isinstance(health, dict) or set(health) != {"aggregate", "checks"}:
            errors.append(f"{prefix} health must contain only aggregate and checks")
            continue
        checks = health.get("checks")
        if not isinstance(checks, list) or not checks:
            errors.append(f"{prefix} must declare health checks")
            continue
        check_ids = _unique_ids(checks, f"{prefix} health checks", errors)
        for check in checks:
            if check.get("type") == "workload-ready" and check.get("target") not in workload_ids:
                errors.append(f"{prefix} health check {check.get('id')} targets an unknown workload")
            if check.get("type") == "persistent-volume" and check.get("target") not in {
                item.get("id") for item in component["persistence"]
            }:
                errors.append(f"{prefix} health check {check.get('id')} targets unknown persistence")

        operation_ids = _unique_ids(component["operations"], f"{prefix} operations", errors)
        for operation in component["operations"]:
            operation_id = operation.get("id", "<missing>")
            adapter = operation.get("adapter")
            if not isinstance(adapter, str) or not adapter.startswith("apps/") or not adapter.endswith(".sh"):
                errors.append(f"{prefix} operation {operation_id} has an invalid adapter")
            elif not (root / adapter).is_file():
                errors.append(f"{prefix} operation {operation_id} adapter does not exist")
            timeout = operation.get("timeoutSeconds")
            if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 7200:
                errors.append(f"{prefix} operation {operation_id} needs a bounded timeout")
            unknown_checks = sorted(set(operation.get("verify", [])) - check_ids)
            if unknown_checks:
                errors.append(
                    f"{prefix} operation {operation_id} has unknown verification checks: "
                    f"{', '.join(unknown_checks)}"
                )
            if operation.get("destructive") and operation_id != "delete-data":
                errors.append(f"{prefix} destructive behavior must use delete-data")
            if operation_id == "delete-data" and operation.get("destructive") is not True:
                errors.append(f"{prefix} delete-data must be marked destructive")
        if "scale" in operation_ids and not scalable:
            errors.append(f"{prefix} exposes scale without a scalable workload")

        _unique_ids(component["secrets"], f"{prefix} secrets", errors)
        for secret in component["secrets"]:
            leaked_fields = sorted(set(secret) & SECRET_VALUE_KEYS)
            if leaked_fields:
                errors.append(
                    f"{prefix} secret {secret.get('id')} contains forbidden value fields"
                )
        persistence_ids = _unique_ids(
            component["persistence"], f"{prefix} persistence", errors
        )
        diagnostic_ids = _unique_ids(
            component["diagnostics"], f"{prefix} diagnostics", errors
        )
        if not diagnostic_ids:
            errors.append(f"{prefix} must declare diagnostics")
        valid_targets = workload_ids | persistence_ids | check_ids
        for diagnostic in component["diagnostics"]:
            if diagnostic.get("target") not in valid_targets:
                errors.append(
                    f"{prefix} diagnostic {diagnostic.get('id')} targets an unknown contract"
                )

    try:
        ComponentRegistry(document).dependency_order()
    except (RegistryError, KeyError, TypeError) as error:
        errors.append(str(error))
    return errors
