"""Security and failure contracts for the live Kubernetes observer."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from manager.component_inventory import ClusterUnavailable, ResourceIdentity
from manager.component_registry import ComponentRegistry
from manager.kubernetes_observer import KubernetesObserver


class Response:
    def __init__(self, document):
        self._payload = json.dumps(document).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self, limit):
        return self._payload


class KubernetesObserverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.token = root / "token"
        self.ca = root / "ca.crt"
        self.token.write_text("opaque-observer-value")
        self.ca.write_text("test-ca")
        self.registry = ComponentRegistry.load()
        patcher = patch("manager.kubernetes_observer.ssl.create_default_context")
        self.addCleanup(patcher.stop)
        patcher.start()
        self.observer = KubernetesObserver(
            "https://127.0.0.1:16443",
            self.token,
            self.ca,
            self.registry,
            timeout_seconds=0.1,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_present_absent_and_cluster_evidence_are_sanitized(self):
        calls = []

        def open_request(request, **kwargs):
            calls.append((request.full_url, request.headers, kwargs["timeout"]))
            if request.full_url.endswith("/version"):
                return Response({"gitVersion": "v1.30.1"})
            if request.full_url.endswith("/api/v1/nodes"):
                return Response({"items": [{"metadata": {"name": "lab-node"}}]})
            if request.full_url.endswith("/statefulsets/ssc-webapp"):
                raise urllib.error.HTTPError(
                    request.full_url, 404, "missing", {}, io.BytesIO()
                )
            return Response({"metadata": {"name": "mysql"}})

        resources = (
            ResourceIdentity("mysql", "mysql/database", "StatefulSet", "mysql"),
            ResourceIdentity(
                "ssc", "ssc/webapp", "StatefulSet", "ssc-webapp"
            ),
        )
        with patch("manager.kubernetes_observer.urllib.request.urlopen", open_request):
            observed = self.observer.observe(resources)
            evidence = self.observer.evidence()
        self.assertEqual([item.state for item in observed], ["present", "absent"])
        self.assertEqual(evidence.node, "lab-node")
        self.assertEqual(evidence.namespace, "fortify")
        self.assertEqual(evidence.kubernetes_version, "v1.30.1")
        self.assertTrue(all(timeout == 0.1 for _, _, timeout in calls))
        self.assertTrue(
            all(headers["Authorization"] == "Bearer opaque-observer-value" for _, headers, _ in calls)
        )
        serialized = json.dumps([url for url, _, _ in calls])
        self.assertNotIn("secrets", serialized)
        self.assertNotIn("log", serialized)

    def test_other_namespace_and_unregistered_resource_are_rejected_before_io(self):
        invalid = (
            ResourceIdentity(
                "mysql", "mysql/database", "StatefulSet", "mysql", "default"
            ),
        )
        with patch("manager.kubernetes_observer.urllib.request.urlopen") as request:
            with self.assertRaisesRegex(ClusterUnavailable, "allow-list"):
                self.observer.observe(invalid)
        request.assert_not_called()

    def test_unauthorized_timeout_and_malformed_responses_are_sanitized(self):
        failures = (
            urllib.error.HTTPError(
                "https://cluster", 403, "token=do-not-return", {}, io.BytesIO()
            ),
            TimeoutError("credential details"),
            Response(["not", "an", "object"]),
        )
        resource = (
            ResourceIdentity("mysql", "mysql/database", "StatefulSet", "mysql"),
        )
        for failure in failures:
            def outcome(*args, failure=failure, **kwargs):
                if isinstance(failure, BaseException):
                    raise failure
                return failure

            with self.subTest(failure=type(failure).__name__):
                with patch(
                    "manager.kubernetes_observer.urllib.request.urlopen", outcome
                ):
                    with self.assertRaises(ClusterUnavailable) as caught:
                        self.observer.observe(resource)
                self.assertNotIn("credential", str(caught.exception))
                self.assertNotIn("token", str(caught.exception))

    def test_recovery_uses_fresh_request_after_disconnect(self):
        resource = (
            ResourceIdentity("mysql", "mysql/database", "StatefulSet", "mysql"),
        )
        with patch(
            "manager.kubernetes_observer.urllib.request.urlopen",
            side_effect=[TimeoutError(), Response({"metadata": {"name": "mysql"}})],
        ):
            with self.assertRaises(ClusterUnavailable):
                self.observer.observe(resource)
            self.assertEqual(self.observer.observe(resource)[0].state, "present")

    def test_diagnose_verifies_required_access_and_denials(self):
        urls = []

        def access(request, **kwargs):
            urls.append(request.full_url)
            if request.full_url.endswith("/version"):
                return Response({"gitVersion": "v1.30.1"})
            if request.full_url.endswith("/api/v1/nodes"):
                return Response({"items": [{"metadata": {"name": "lab-node"}}]})
            if any(
                fragment in request.full_url
                for fragment in (
                    "/secrets",
                    "/namespaces/default/",
                    "/pods/access-check/log",
                )
            ):
                return_error = urllib.error.HTTPError(
                    request.full_url, 403, "denied", {}, io.BytesIO()
                )
                raise return_error
            return Response({"items": []})

        resource = (
            ResourceIdentity("mysql", "mysql/database", "StatefulSet", "mysql"),
        )
        with patch("manager.kubernetes_observer.urllib.request.urlopen", access):
            evidence = self.observer.diagnose_access(resource)
        self.assertEqual(evidence.node, "lab-node")
        self.assertTrue(any("/storageclasses" in url for url in urls))
        self.assertTrue(any("/ingresses" in url for url in urls))
        self.assertTrue(any("/secrets" in url for url in urls))
        self.assertTrue(any("/namespaces/default/" in url for url in urls))
        self.assertTrue(any("/pods/access-check/log" in url for url in urls))


if __name__ == "__main__":
    unittest.main()
