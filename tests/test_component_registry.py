"""Tests for authoritative component and dependency contracts."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, RefResolver

from manager.component_registry import ComponentRegistry, RegistryError
from manager.registry_validation import validate_registry


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "registry" / "components.json"
SCHEMA_DIR = ROOT / "registry" / "schemas"


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


class ComponentRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = load_json(REGISTRY_PATH)

    def test_registry_matches_json_schemas(self) -> None:
        registry_schema = load_json(SCHEMA_DIR / "component-registry.schema.json")
        component_schema = load_json(SCHEMA_DIR / "component.schema.json")
        resolver = RefResolver.from_schema(
            registry_schema,
            store={component_schema["$id"]: component_schema},
        )
        Draft202012Validator(registry_schema, resolver=resolver).validate(self.document)
        self.assertEqual(validate_registry(self.document, ROOT), [])

    def test_declared_dependency_paths_and_order(self) -> None:
        registry = ComponentRegistry(self.document)
        self.assertEqual(registry.component("ssc")["dependencies"], ["mysql"])
        self.assertEqual(
            registry.component("scancentral-sast")["dependencies"], ["ssc"]
        )
        self.assertEqual(
            set(registry.component("scancentral-dast-core")["dependencies"]),
            {"postgresql", "lim", "ssc"},
        )
        self.assertEqual(
            registry.component("scancentral-dast-scanner")["dependencies"],
            ["scancentral-dast-core"],
        )
        order = registry.dependency_order(["scancentral-dast-scanner"])
        for dependency in ("mysql", "ssc", "postgresql", "lim"):
            self.assertLess(order.index(dependency), order.index("scancentral-dast-core"))
        self.assertLess(
            order.index("scancentral-dast-core"),
            order.index("scancentral-dast-scanner"),
        )

    def test_lifecycle_and_monitoring_read_same_definition(self) -> None:
        registry = ComponentRegistry(self.document)
        component = registry.component("scancentral-sast")
        self.assertIs(registry.lifecycle_operations("scancentral-sast")[0], component["operations"][0])
        self.assertIs(registry.monitoring_checks("scancentral-sast")[0], component["health"]["checks"][0])

    def test_schema_rejects_secret_values_and_unknown_fields(self) -> None:
        invalid = copy.deepcopy(self.document)
        invalid["components"][0]["secrets"][0]["value"] = "not-a-real-secret"
        errors = validate_registry(invalid, ROOT)
        self.assertTrue(any("forbidden value fields" in error for error in errors))

        component_schema = load_json(SCHEMA_DIR / "component.schema.json")
        component = copy.deepcopy(self.document["components"][0])
        component["unexpected"] = True
        errors = list(Draft202012Validator(component_schema).iter_errors(component))
        self.assertTrue(errors)

    def test_semantics_reject_missing_dependencies_and_verification(self) -> None:
        invalid = copy.deepcopy(self.document)
        invalid["components"][1]["dependencies"] = ["missing-database"]
        invalid["components"][1]["operations"][0]["verify"] = ["missing-check"]
        errors = validate_registry(invalid, ROOT)
        self.assertTrue(any("unknown dependencies" in error for error in errors))
        self.assertTrue(any("unknown verification checks" in error for error in errors))

    def test_semantics_reject_dependency_cycles(self) -> None:
        invalid = copy.deepcopy(self.document)
        invalid["components"][0]["dependencies"] = ["ssc"]
        with self.assertRaises(RegistryError):
            ComponentRegistry(invalid).dependency_order()
        self.assertTrue(any("dependency cycle" in error for error in validate_registry(invalid, ROOT)))

    def test_destructive_data_deletion_is_not_exposed_as_uninstall(self) -> None:
        registry = ComponentRegistry(self.document)
        for component_id in ("mysql", "postgresql", "lim"):
            operations = {
                operation["id"]: operation
                for operation in registry.lifecycle_operations(component_id)
            }
            self.assertNotIn("uninstall", operations)
            self.assertTrue(operations["delete-data"]["destructive"])


if __name__ == "__main__":
    unittest.main()
