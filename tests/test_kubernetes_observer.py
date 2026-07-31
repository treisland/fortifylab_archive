"""Security and failure contracts for the live Kubernetes observer."""

from __future__ import annotations

import io
import json
import datetime
import ssl
import tempfile
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from manager.component_inventory import ClusterUnavailable, ResourceIdentity
from manager.component_registry import ComponentRegistry
from manager.kubernetes_observer import KubernetesObserver
from manager.health import CheckSpec, ProbeResult


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

    def test_release_labels_and_running_image_versions_exclude_repository_paths(self):
        resource = (ResourceIdentity(
            "scancentral-sast", "scancentral-sast/controller", "StatefulSet",
            "scancentral-sast-controller",
        ),)
        document = {
            "metadata": {"labels": {
                "app.kubernetes.io/instance": "sast-26-2",
                "helm.sh/chart": "scancentral-sast-26.2.0-1",
                "app.kubernetes.io/version": "26.2",
                "credential": "must-not-project",
            }},
            "spec": {"template": {"spec": {"containers": [
                {"name": "controller", "image": "registry.internal/private/controller:26.2.0"},
                {"name": "sidecar", "image": "registry.internal/private/sidecar@sha256:abc123"},
            ]}}},
        }
        with patch("manager.kubernetes_observer.urllib.request.urlopen", return_value=Response(document)):
            observed = self.observer.observe(resource)[0]
        self.assertEqual(observed.release_name, "sast-26-2")
        self.assertEqual(observed.chart_version, "26.2.0-1")
        self.assertEqual(observed.app_version, "26.2")
        self.assertEqual(observed.image_versions, ("26.2.0", "sha256:abc123"))
        serialized = json.dumps(observed.__dict__)
        self.assertNotIn("registry.internal", serialized)
        self.assertNotIn("private", serialized)
        self.assertNotIn("credential", serialized)

    def test_legacy_ca_compatibility_preserves_tls_verification(self):
        strict = getattr(ssl, "VERIFY_X509_STRICT", 0)
        retained = getattr(ssl, "VERIFY_X509_TRUSTED_FIRST", 0x8000)
        context = SimpleNamespace(
            verify_flags=strict | retained,
            check_hostname=True,
            verify_mode=ssl.CERT_REQUIRED,
        )
        with patch(
            "manager.kubernetes_observer.ssl.create_default_context",
            return_value=context,
        ) as create_context:
            observer = KubernetesObserver(
                "https://127.0.0.1:16443",
                self.token,
                self.ca,
                self.registry,
            )
        create_context.assert_called_once_with(cafile=str(self.ca))
        self.assertEqual(observer._context.verify_flags & strict, 0)
        self.assertEqual(observer._context.verify_flags & retained, retained)
        self.assertTrue(observer._context.check_hostname)
        self.assertEqual(observer._context.verify_mode, ssl.CERT_REQUIRED)

    def test_invalid_ca_still_fails_context_construction(self):
        with patch(
            "manager.kubernetes_observer.ssl.create_default_context",
            side_effect=ssl.SSLError("untrusted CA"),
        ):
            with self.assertRaises(ssl.SSLError):
                KubernetesObserver(
                    "https://127.0.0.1:16443",
                    self.token,
                    self.ca,
                    self.registry,
                )

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
        self.assertTrue(any("/persistentvolumeclaims" in url for url in urls))
        self.assertTrue(any("/ingresses" in url for url in urls))
        self.assertTrue(any("/secrets" in url for url in urls))
        self.assertTrue(any("/namespaces/default/" in url for url in urls))
        self.assertTrue(any("/pods/access-check/log" in url for url in urls))

    def test_pvc_and_workload_evidence_use_only_allowlisted_metadata(self):
        def metadata(request, **kwargs):
            if "/persistentvolumeclaims/data-mysql-0" in request.full_url:
                return Response({"status": {"phase": "Bound"}})
            return Response({"spec": {"replicas": 1}, "status": {"readyReplicas": 1}})

        pvc = CheckSpec(
            "database-pvc", "mysql", "storage", "persistent-volume",
            "database-data", 1,
        )
        workload = CheckSpec(
            "database-ready", "mysql", "workload", "workload-ready",
            "database", 1,
        )
        with patch("manager.kubernetes_observer.urllib.request.urlopen", metadata):
            self.assertEqual(self.observer.probe(pvc).state, "healthy")
            result = self.observer.probe(workload)
        self.assertEqual(result.state, "healthy")
        self.assertTrue(result.workload_present)
        self.assertEqual(result.desired_replicas, 1)
        self.assertEqual(result.ready_replicas, 1)

    def test_workload_absence_and_replica_mismatch_are_structured(self):
        workload = CheckSpec(
            "scanner-ready", "scancentral-dast-scanner", "workload",
            "workload-ready", "scanner", 1,
        )

        def absent(request, **kwargs):
            raise urllib.error.HTTPError(
                request.full_url, 404, "missing", {}, io.BytesIO()
            )

        with patch("manager.kubernetes_observer.urllib.request.urlopen", absent):
            missing = self.observer.probe(workload)
        self.assertEqual(missing.state, "unhealthy")
        self.assertFalse(missing.workload_present)

        with patch(
            "manager.kubernetes_observer.urllib.request.urlopen",
            return_value=Response(
                {"spec": {"replicas": 1}, "status": {"readyReplicas": 0}}
            ),
        ):
            mismatch = self.observer.probe(workload)
        self.assertEqual(mismatch.state, "degraded")
        self.assertTrue(mismatch.workload_present)
        self.assertEqual((mismatch.ready_replicas, mismatch.desired_replicas), (0, 1))

    def test_clean_install_footprint_detects_workloads_and_retained_pvcs(self):
        urls = []

        def metadata(request, **kwargs):
            urls.append(request.full_url)
            if request.full_url.endswith("/statefulsets/mysql"):
                return Response({"metadata": {"name": "mysql"}})
            raise urllib.error.HTTPError(
                request.full_url, 404, "missing", {}, io.BytesIO()
            )

        with patch("manager.kubernetes_observer.urllib.request.urlopen", metadata):
            result = self.observer.installation_footprint(("mysql", "lim"))
        self.assertEqual(result, {"mysql": "present", "lim": "absent"})
        self.assertTrue(any("persistentvolumeclaims/data-mysql-0" in url for url in urls))
        self.assertTrue(any("persistentvolumeclaims/lim-pvc" in url for url in urls))
        self.assertFalse(any("/secrets" in url or "/pods/" in url for url in urls))

    def test_functional_checks_delegate_and_missing_service_is_unknown(self):
        functional = unittest.mock.Mock()
        functional.probe.return_value = ProbeResult(
            "healthy", "Authenticated query succeeded",
            datetime.datetime.now(datetime.timezone.utc),
        )
        observer = KubernetesObserver(
            "https://127.0.0.1:16443", self.token, self.ca, self.registry,
            timeout_seconds=0.1, functional_probe=functional,
        )
        query = CheckSpec(
            "database-query", "mysql", "application", "database-query",
            "mysql", 1,
        )
        self.assertEqual(observer.probe(query).state, "healthy")
        functional.probe.assert_called_once_with(query)
        self.assertEqual(self.observer.probe(query).state, "unknown")


if __name__ == "__main__":
    unittest.main()
