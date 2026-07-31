"""Curated route, layered probe, scheduling, recovery, and API tests."""

from __future__ import annotations

import io
import json
import ssl
import unittest
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from manager.api import AVAILABILITY_PATH, ManagerAPI
from manager.availability import (
    AvailabilityMonitor,
    HostAvailabilityProbe,
    ObservedRoute,
    ProbeEvidence,
)
from manager.component_registry import ComponentRegistry
from manager.kubernetes_observer import KubernetesObserver


class Routes:
    def __init__(self, routes):
        self.routes = routes

    def observed_routes(self):
        return tuple(self.routes)


class FailedRoutes:
    def observed_routes(self):
        raise RuntimeError("private cluster detail")


class SequenceProbe:
    def __init__(self, states):
        self.states = list(states)
        self.calls = []

    def probe(self, route):
        self.calls.append(route)
        state = self.states.pop(0)
        return ProbeEvidence(
            state,
            "resolved" if state != "unreachable" else "failed",
            "valid" if state not in {"tls-warning", "unreachable"} else "warning",
            "status-200" if state == "reachable" else "unreachable",
            7,
            f"sanitized {state}",
        )


class Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class Opener:
    def __init__(self, result):
        self.result = result

    def open(self, request, timeout):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class AvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.registry = ComponentRegistry.load()
        self.routes = [
            ObservedRoute("manager", "lab.example.test", True, ("192.0.2.10",)),
            ObservedRoute("ssc", "ssc.example.test", True, ("192.0.2.10",)),
            ObservedRoute("scancentral-sast", "sast.example.test", True),
            ObservedRoute("lim", "lim.example.test", True),
            ObservedRoute("scancentral-dast-core", "dast.example.test", True),
        ]

    def test_registry_curates_web_services_and_excludes_databases_and_scanner(self):
        monitor = AvailabilityMonitor(
            self.registry, Routes(self.routes), SequenceProbe(["reachable"] * 5)
        )
        document = monitor.document()
        ids = {item["id"] for item in document["items"]}
        self.assertEqual(
            ids,
            {"manager", "ssc", "scancentral-sast", "lim", "scancentral-dast-core"},
        )
        self.assertTrue(all(item["url"].startswith("https://") for item in document["items"]))
        self.assertNotIn("mysql", ids)
        self.assertNotIn("postgresql", ids)
        self.assertNotIn("scancentral-dast-scanner", ids)
        self.assertTrue(all(item["applicationHealthIndependent"] for item in document["items"]))

    def test_unapproved_host_domain_plain_http_and_unknown_endpoint_are_not_probed(self):
        routes = self.routes + [
            ObservedRoute("ssc", "ssc.attacker.test", True),
            ObservedRoute("lim", "lim.example.test", False),
            ObservedRoute("arbitrary", "metadata.example.test", True),
        ]
        probe = SequenceProbe(["reachable"] * 5)
        document = AvailabilityMonitor(self.registry, Routes(routes), probe).document()
        self.assertEqual(len(probe.calls), 5)
        self.assertNotIn("attacker.test", json.dumps(document))
        self.assertNotIn("metadata.example.test", json.dumps(document))

    def test_observer_projects_only_registry_labels_without_ingress_bodies(self):
        observer = object.__new__(KubernetesObserver)
        observer._registry = self.registry
        observer._namespace = "fortify"
        observer._get = lambda path: {
            "items": [
                {
                    "spec": {
                        "tls": [{"hosts": ["lab.example.test", "ssc.example.test"]}],
                        "rules": [
                            {"host": "lab.example.test", "http": {"paths": [{"backend": {"service": {"name": "fortify-manager-host"}}}]}},
                            {"host": "ssc.example.test", "http": {"paths": [{"backend": {"service": {"name": "ssc-service"}}}]}},
                            {"host": "database.example.test"},
                        ],
                    },
                    "status": {"loadBalancer": {"ingress": [{"ip": "192.0.2.10"}]}},
                }
            ]
        }
        routes = observer.observed_routes()
        self.assertEqual([route.endpoint_id for route in routes], ["manager", "ssc"])
        self.assertEqual(routes[0].addresses, ("192.0.2.10",))
        self.assertNotIn("service", json.dumps([route.__dict__ for route in routes]))

    def test_public_address_is_dns_expectation_not_private_ingress_address(self):
        observer = object.__new__(KubernetesObserver)
        observer._registry = self.registry
        observer._namespace = "fortify"
        observer._public_address = "184.33.159.224"
        observer._get = lambda path: {
            "items": [{
                "spec": {
                    "tls": [{"hosts": ["lab.fortifydemo.com"]}],
                    "rules": [{"host": "lab.fortifydemo.com"}],
                },
                "status": {"loadBalancer": {"ingress": [{"ip": "172.31.30.41"}]}},
            }]
        }
        route = observer.observed_routes()[0]
        self.assertEqual(route.addresses, ("184.33.159.224",))
        self.assertEqual(route.ingress_addresses, ("172.31.30.41",))

    def test_failure_backoff_history_and_recovery_are_bounded(self):
        now = [0.0]
        probe = SequenceProbe(["unreachable", "reachable"])
        monitor = AvailabilityMonitor(
            self.registry,
            Routes(self.routes[:1]),
            probe,
            interval_seconds=5,
            history_limit=2,
            clock=lambda: now[0],
            wall_clock=lambda: datetime(2026, 7, 31, tzinfo=timezone.utc),
        )
        first = monitor.document()["items"][0]
        self.assertEqual(first["state"], "unreachable")
        now[0] = 5
        self.assertEqual(monitor.document()["items"][0]["state"], "unreachable")
        self.assertEqual(len(probe.calls), 1)
        now[0] = 20
        recovered = monitor.document()["items"][0]
        self.assertEqual(recovered["state"], "reachable")
        self.assertEqual(
            [item["state"] for item in recovered["history"]],
            ["reachable", "unreachable"],
        )

    def test_route_observation_failure_is_unknown_and_sanitized(self):
        document = AvailabilityMonitor(self.registry, FailedRoutes()).document()
        self.assertTrue(all(item["state"] == "unknown" for item in document["items"]))
        self.assertTrue(all(item["url"] is None for item in document["items"]))
        self.assertNotIn("private cluster detail", json.dumps(document))

    @patch("manager.availability.socket.getaddrinfo")
    def test_dns_failure_and_mismatch_are_independent(self, getaddrinfo):
        probe = HostAvailabilityProbe()
        getaddrinfo.side_effect = OSError()
        failed = probe.probe(self.routes[0])
        self.assertEqual((failed.state, failed.dns, failed.tls), ("unreachable", "failed", "not-attempted"))
        getaddrinfo.side_effect = None
        getaddrinfo.return_value = [(2, 1, 6, "", ("192.0.2.99", 443))]
        mismatch = probe.probe(self.routes[0])
        self.assertEqual(mismatch.state, "dns-mismatch")
        self.assertEqual(mismatch.http, "not-attempted")

    @patch("manager.availability.socket.getaddrinfo")
    def test_dns_mixed_with_unapproved_answer_is_mismatch(self, getaddrinfo):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("192.0.2.10", 443)),
            (2, 1, 6, "", ("192.0.2.99", 443)),
        ]
        evidence = HostAvailabilityProbe().probe(self.routes[0])
        self.assertEqual(evidence.state, "dns-mismatch")
        self.assertEqual(evidence.dns, "mismatch")
        self.assertEqual(evidence.http, "not-attempted")

    @patch("manager.availability.socket.getaddrinfo")
    def test_tls_http_success_server_error_and_redirect_are_distinct(self, getaddrinfo):
        getaddrinfo.return_value = [(2, 1, 6, "", ("192.0.2.10", 443))]
        probe = HostAvailabilityProbe()
        tls_error = urllib.error.URLError(
            ssl.SSLCertVerificationError("certificate verify failed")
        )
        probe._opener = Opener(tls_error)
        self.assertEqual(probe.probe(self.routes[0]).state, "tls-warning")
        probe._opener = Opener(urllib.error.URLError(ConnectionRefusedError()))
        self.assertEqual(probe.probe(self.routes[0]).state, "unreachable")
        probe._opener = Opener(Response())
        self.assertEqual(probe.probe(self.routes[0]).state, "reachable")
        for code, state in ((503, "degraded"), (302, "degraded")):
            error = urllib.error.HTTPError(
                "https://lab.example.test/", code, "status", {}, io.BytesIO()
            )
            probe._opener = Opener(error)
            evidence = probe.probe(self.routes[0])
            self.assertEqual(evidence.state, state)
            self.assertIn(str(code), evidence.http)

    def test_api_contract_is_schema_valid_and_contains_no_response_data(self):
        monitor = AvailabilityMonitor(
            self.registry, Routes(self.routes), SequenceProbe(["reachable"] * 5)
        )
        app = ManagerAPI(availability_monitor=monitor)
        response = {}

        def start_response(status, headers):
            response["status"] = status

        body = b"".join(
            app(
                {"REQUEST_METHOD": "GET", "PATH_INFO": AVAILABILITY_PATH},
                start_response,
            )
        )
        document = json.loads(body)
        schema = json.loads(
            Path("registry/schemas/service-availability.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator(schema).validate(document)
        self.assertEqual(response["status"], "200 OK")
        for forbidden in ("cookie", "authorization", "responseBody", "certificate"):
            self.assertNotIn(forbidden, body.decode().lower())


if __name__ == "__main__":
    unittest.main()
