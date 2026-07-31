"""Contract tests for the read-only component inventory API."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from manager.api import COMPONENTS_PATH, ManagerAPI
from manager.component_inventory import ClusterUnavailable, ResourceObservation
from manager.component_registry import ComponentRegistry


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_SCHEMA = json.loads(
    (ROOT / "registry/schemas/component-inventory.schema.json").read_text(
        encoding="utf-8"
    )
)


class PresentObserver:
    def observe(self, resources):
        return tuple(
            ResourceObservation(
                resource_id=resource.resource_id,
                state="present",
                kind=resource.kind,
                name=resource.name,
                namespace=resource.namespace,
            )
            for resource in resources
        )


class MixedObserver:
    def observe(self, resources):
        return tuple(
            ResourceObservation(
                resource_id=resource.resource_id,
                state="absent" if index == 0 else "present",
                kind=resource.kind,
                name=resource.name,
                namespace=resource.namespace,
            )
            for index, resource in enumerate(resources)
        )


class UnavailableObserver:
    def observe(self, resources):
        raise ClusterUnavailable("details must not leave the adapter")


class VersionObserver:
    def observe(self, resources):
        return tuple(
            ResourceObservation(
                resource.resource_id,
                "present",
                resource.kind,
                resource.name,
                resource.namespace,
                "sast-26-2" if resource.component_id == "scancentral-sast" else resource.component_id,
                "26.2.0" if resource.component_id == "scancentral-sast" else "9.19.0",
                "26.2",
                (("25.2",) if resource.resource_id.endswith("/sensor") else ("26.2",)),
            )
            for resource in resources
        )


def request(app, method="GET"):
    response = {}

    def start_response(status, headers):
        response["status"] = status
        response["headers"] = dict(headers)

    body = b"".join(
        app(
            {"REQUEST_METHOD": method, "PATH_INFO": COMPONENTS_PATH},
            start_response,
        )
    )
    response["body"] = body
    response["json"] = json.loads(body) if body else None
    return response


class ComponentInventoryAPIContractTests(unittest.TestCase):
    def test_success_reports_safe_inventory_and_dependency_paths(self):
        response = request(ManagerAPI(observer=PresentObserver()))
        self.assertEqual(response["status"], "200 OK")
        document = response["json"]
        Draft202012Validator(INVENTORY_SCHEMA).validate(document)
        self.assertEqual(document["apiVersion"], "fortifylab.io/v1alpha1")
        self.assertEqual(document["observation"]["state"], "available")
        self.assertIn("latencyMs", document["observation"])
        components = {item["identity"]["id"]: item for item in document["items"]}
        self.assertEqual(components["ssc"]["dependencies"], ["mysql"])
        self.assertEqual(components["scancentral-sast"]["dependencies"], ["ssc"])
        self.assertEqual(
            set(components["scancentral-dast-core"]["dependencies"]),
            {"postgresql", "lim", "ssc"},
        )
        self.assertEqual(
            components["mysql"]["version"]["images"]["database"],
            "8.0.36-debian-11-r2",
        )
        self.assertEqual(components["mysql"]["desiredState"]["state"], "present")
        self.assertEqual(components["ssc"]["profile"]["id"], "fortify-24.4-eval.1")
        self.assertEqual(components["ssc"]["profile"]["productVersion"], "24.4.2.0009")
        self.assertEqual(components["ssc"]["ingress"], [{"id": "ssc", "protocol": "https"}])
        self.assertEqual(components["ssc"]["storage"][0]["purpose"], "application-data")
        self.assertEqual(components["scancentral-sast"]["workloads"][1]["role"], "worker")
        self.assertIn(
            "scale",
            {
                operation["id"]
                for operation in components["scancentral-sast"]["supportedOperations"]
            },
        )
        self.assertTrue(
            all(
                resource["state"] == "present"
                for item in document["items"]
                for resource in item["observedResources"]
            )
        )
        serialized = json.dumps(document)
        for forbidden in (
            "kubernetesSecret",
            "adapter",
            "diagnostics",
            "claim",
            "apps/",
            "password",
            "token",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_confirmed_absence_is_distinct_from_unknown(self):
        response = request(ManagerAPI(observer=MixedObserver()))
        resources = [
            resource
            for item in response["json"]["items"]
            for resource in item["observedResources"]
        ]
        self.assertIn("absent", {resource["state"] for resource in resources})
        self.assertNotIn("unknown", {resource["state"] for resource in resources})

    def test_observed_versions_are_independent_and_mixed_workloads_are_visible(self):
        document = request(ManagerAPI(observer=VersionObserver()))["json"]
        Draft202012Validator(INVENTORY_SCHEMA).validate(document)
        sast = next(item for item in document["items"] if item["identity"]["id"] == "scancentral-sast")
        self.assertEqual(sast["version"]["chart"], "24.4.0-2")
        self.assertEqual(sast["observedDeployment"]["state"], "mixed")
        self.assertTrue(sast["updateAvailable"])
        running = {
            workload["id"]: workload["runningImageVersions"]
            for workload in sast["observedDeployment"]["workloads"]
        }
        self.assertEqual(running, {"scancentral-sast/controller": ["26.2"], "scancentral-sast/sensor": ["25.2"]})
        serialized = json.dumps(document)
        self.assertNotIn("registry.internal", serialized)
        self.assertNotIn("helmValues", serialized)

    def test_unavailable_cluster_returns_unknown_resources_without_details(self):
        response = request(ManagerAPI(observer=UnavailableObserver()))
        self.assertEqual(response["status"], "200 OK")
        self.assertEqual(response["json"]["observation"]["state"], "unavailable")
        Draft202012Validator(INVENTORY_SCHEMA).validate(response["json"])
        self.assertTrue(
            all(
                resource["state"] == "unknown"
                for item in response["json"]["items"]
                for resource in item["observedResources"]
            )
        )
        self.assertNotIn("details must not leave", response["body"].decode())

    def test_malformed_registry_returns_sanitized_service_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "components.json"
            path.write_text('{"components":', encoding="utf-8")
            response = request(
                ManagerAPI(registry_loader=lambda: ComponentRegistry.load(path))
            )
        self.assertEqual(response["status"], "503 Service Unavailable")
        self.assertEqual(
            response["json"],
            {
                "code": "REGISTRY_UNAVAILABLE",
                "message": "component inventory is unavailable",
            },
        )
        self.assertNotIn(str(path), response["body"].decode())

    def test_head_is_bodyless_and_mutating_methods_are_rejected(self):
        head = request(ManagerAPI(), method="HEAD")
        self.assertEqual(head["status"], "200 OK")
        self.assertEqual(head["body"], b"")
        post = request(ManagerAPI(), method="POST")
        self.assertEqual(post["status"], "405 Method Not Allowed")
        self.assertEqual(post["headers"]["Allow"], "GET, HEAD")


if __name__ == "__main__":
    unittest.main()
