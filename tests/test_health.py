"""Tests for layered dependency-aware health evaluation and API."""

from __future__ import annotations

import json
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from manager.api import HEALTH_PATH, ManagerAPI
from manager.component_registry import ComponentRegistry
from manager.health import HealthEngine, ProbeResult


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
SCHEMA = json.loads(
    (ROOT / "registry/schemas/health-report.schema.json").read_text()
)


class FakeProbe:
    def __init__(self):
        self.states = {}
        self.calls = []

    def probe(self, check):
        self.calls.append(check.subject_id)
        state, summary, observed_at = self.states.get(
            check.subject_id, ("healthy", "Authoritative check passed", NOW)
        )
        return ProbeResult(state, summary, observed_at)


class SlowProbe(FakeProbe):
    def probe(self, check):
        time.sleep(0.05)
        return super().probe(check)


class MultidimensionalProbe(FakeProbe):
    def __init__(self):
        super().__init__()
        self.results = {}

    def probe(self, check):
        self.calls.append((check.subject_id, check.id))
        return self.results.get(
            (check.subject_id, check.id),
            ProbeResult("healthy", "Authoritative check passed", NOW),
        )


class Availability:
    def __init__(self, document):
        self._document = document

    def document(self):
        return self._document


def by_id(document):
    return {item["id"]: item for item in document["items"]}


def request(app):
    response = {}

    def start_response(status, headers):
        response["status"] = status
        response["headers"] = dict(headers)

    response["body"] = b"".join(
        app({"REQUEST_METHOD": "GET", "PATH_INFO": HEALTH_PATH}, start_response)
    )
    response["json"] = json.loads(response["body"])
    return response


class HealthEngineTests(unittest.TestCase):
    def setUp(self):
        self.registry = ComponentRegistry.load()
        self.probe = FakeProbe()

    def engine(self, **kwargs):
        return HealthEngine(
            self.registry, self.probe, clock=lambda: NOW, **kwargs
        )

    @staticmethod
    def availability(
        endpoint="ssc", state="reachable", tls="valid", checked_at=NOW
    ):
        return {
            "items": [{
                "id": endpoint,
                "state": state,
                "dns": "mismatch" if state == "dns-mismatch" else "resolved",
                "tls": tls,
                "http": "not-attempted" if state != "reachable" else "status-200",
                "summary": "Sanitized operator route evidence",
                "checkedAt": checked_at.isoformat().replace("+00:00", "Z"),
                "latencyMs": 4,
            }]
        }

    def test_healthy_environment_has_layered_safe_evidence(self):
        document = self.engine().document()
        Draft202012Validator(SCHEMA).validate(document)
        self.assertEqual(document["state"], "healthy")
        self.assertEqual(document["evidence"]["source"], "live-cluster")
        items = by_id(document)
        self.assertEqual(
            list(items)[:5],
            ["microk8s-node", "storage", "dns", "ingress", "tls"],
        )
        self.assertEqual(items["mysql"]["state"], "healthy")
        self.assertTrue(items["mysql"]["remediation"]["safe"])
        checks = {
            entry["id"]
            for component in document["items"]
            for entry in component["evidence"]
        }
        self.assertTrue(
            {
                "database-query",
                "database-pvc",
                "native-readiness",
                "application-initialized",
                "license-pool-configured",
                "worker-registration",
                "database-schema",
                "scanner-registration",
            }
            <= checks
        )

    def test_root_dependency_failure_precedes_and_blocks_consumers(self):
        self.probe.states["microk8s-node"] = ("unhealthy", "Node not ready", NOW)
        items = by_id(self.engine().document())
        self.assertEqual(items["microk8s-node"]["state"], "unhealthy")
        self.assertEqual(items["storage"]["state"], "blocked")
        self.assertEqual(items["mysql"]["state"], "blocked")
        self.assertEqual(items["mysql"]["rootCause"], "microk8s-node/node-ready")
        self.assertNotIn("storage", self.probe.calls)
        self.assertLess(list(items).index("microk8s-node"), list(items).index("mysql"))

    def test_timeout_is_bounded_unknown(self):
        engine = HealthEngine(
            self.registry,
            SlowProbe(),
            clock=lambda: NOW,
            max_probe_timeout=0.005,
        )
        started = time.monotonic()
        document = engine.document()
        self.assertLess(time.monotonic() - started, 0.2)
        root = document["items"][0]
        self.assertEqual(root["state"], "unknown")
        self.assertEqual(
            root["evidence"][0]["summary"],
            "Check exceeded the aggregate bounded deadline",
        )

    def test_checks_within_a_subject_use_controlled_concurrency(self):
        engine = HealthEngine(
            self.registry,
            SlowProbe(),
            clock=lambda: NOW,
            max_probe_timeout=2.0,
            max_workers=4,
        )
        started = time.monotonic()
        document = engine.document()
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.5)
        self.assertEqual(document["state"], "healthy")

    def test_stale_evidence_is_distinct_and_blocks_dependents(self):
        self.probe.states["dns"] = (
            "healthy",
            "Lookup passed",
            NOW - timedelta(minutes=6),
        )
        items = by_id(self.engine().document())
        self.assertEqual(items["dns"]["state"], "stale")
        self.assertEqual(items["ingress"]["state"], "healthy")

    def test_warning_is_degraded_not_unhealthy(self):
        self.probe.states["mysql"] = ("degraded", "Query latency is elevated", NOW)
        items = by_id(self.engine().document())
        self.assertEqual(items["mysql"]["state"], "degraded")
        self.assertEqual(items["ssc"]["state"], "blocked")

    def test_recovery_rechecks_previously_blocked_consumers(self):
        self.probe.states["storage"] = ("unhealthy", "Volume unavailable", NOW)
        self.assertEqual(by_id(self.engine().document())["mysql"]["state"], "blocked")
        self.probe.states["storage"] = ("healthy", "Volume bound", NOW)
        self.probe.calls.clear()
        second = by_id(self.engine().document())
        self.assertEqual(second["storage"]["state"], "healthy")
        self.assertEqual(second["mysql"]["state"], "healthy")
        self.assertIn("mysql", self.probe.calls)

    def test_public_dns_failure_degrades_only_external_domain(self):
        document = HealthEngine(
            self.registry,
            self.probe,
            clock=lambda: NOW,
            availability=self.availability(state="dns-mismatch", tls="not-attempted"),
        ).document()
        Draft202012Validator(SCHEMA).validate(document)
        items = by_id(document)
        self.assertEqual(items["mysql"]["state"], "healthy")
        self.assertEqual(items["mysql"]["domains"]["workload"]["state"], "healthy")
        self.assertEqual(items["ssc"]["state"], "degraded")
        self.assertEqual(items["ssc"]["directState"], "healthy")
        self.assertEqual(
            items["ssc"]["domains"]["externalReachability"]["state"],
            "unreachable",
        )
        self.assertEqual(items["ssc"]["affectedDomains"], ["externalReachability"])
        self.assertEqual(items["scancentral-sast"]["state"], "healthy")

    def test_ingress_and_tls_access_failures_do_not_block_application_dependencies(self):
        for state, tls in (("unreachable", "valid"), ("tls-warning", "warning")):
            with self.subTest(state=state):
                items = by_id(HealthEngine(
                    self.registry,
                    self.probe,
                    clock=lambda: NOW,
                    availability=self.availability(state=state, tls=tls),
                ).document())
                self.assertEqual(items["ssc"]["state"], "degraded")
                self.assertEqual(items["ssc"]["directState"], "healthy")
                self.assertEqual(items["scancentral-sast"]["state"], "healthy")

    def test_ingress_infrastructure_failure_is_independent_from_components(self):
        self.probe.states["ingress"] = ("unhealthy", "Ingress route failed", NOW)
        items = by_id(self.engine().document())
        self.assertEqual(items["ingress"]["state"], "degraded")
        self.assertEqual(items["ingress"]["directState"], "healthy")
        self.assertEqual(items["ssc"]["state"], "healthy")
        self.assertEqual(items["mysql"]["state"], "healthy")

    def test_database_failure_blocks_only_relevant_consumer_checks(self):
        probe = MultidimensionalProbe()
        probe.results[("mysql", "database-query")] = ProbeResult(
            "unhealthy", "Authenticated query failed", NOW
        )
        items = by_id(HealthEngine(self.registry, probe, clock=lambda: NOW).document())
        self.assertEqual(items["mysql"]["state"], "unhealthy")
        self.assertIn("ssc", items["mysql"]["downstreamImpact"])
        self.assertEqual(items["ssc"]["state"], "blocked")
        self.assertEqual(items["ssc"]["domains"]["workload"]["state"], "healthy")
        self.assertEqual(items["ssc"]["blockedBy"], "mysql")

    def test_mixed_dependency_and_external_failures_have_deterministic_precedence(self):
        probe = MultidimensionalProbe()
        probe.results[("mysql", "database-query")] = ProbeResult(
            "unhealthy", "Authenticated query failed", NOW
        )
        items = by_id(HealthEngine(
            self.registry,
            probe,
            clock=lambda: NOW,
            availability=self.availability(state="dns-mismatch", tls="not-attempted"),
        ).document())
        self.assertEqual(items["ssc"]["state"], "blocked")
        self.assertEqual(items["ssc"]["directState"], "healthy")
        self.assertEqual(items["ssc"]["rootCause"], "mysql/database-query")
        self.assertIn("externalReachability", items["ssc"]["affectedDomains"])

    def test_stale_external_evidence_degrades_then_recovers_without_affecting_workload(self):
        stale = HealthEngine(
            self.registry,
            self.probe,
            clock=lambda: NOW,
            availability=self.availability(checked_at=NOW - timedelta(minutes=6)),
        ).document()
        ssc = by_id(stale)["ssc"]
        self.assertEqual(ssc["state"], "degraded")
        self.assertEqual(ssc["domains"]["externalReachability"]["state"], "stale")
        self.assertEqual(ssc["domains"]["workload"]["state"], "healthy")
        recovered = by_id(HealthEngine(
            self.registry,
            self.probe,
            clock=lambda: NOW,
            availability=self.availability(),
        ).document())["ssc"]
        self.assertEqual(recovered["state"], "healthy")

    def test_upstream_unknown_preserves_absent_and_not_ready_workloads(self):
        probe = MultidimensionalProbe()
        probe.results[("dns", "dns-lookup")] = ProbeResult(
            "unknown", "Protected DNS probe is unavailable", NOW
        )
        probe.results[("ssc", "webapp-ready")] = ProbeResult(
            "unhealthy", "Desired workload is absent", NOW,
            workload_present=False,
        )
        probe.results[("scancentral-dast-scanner", "scanner-ready")] = ProbeResult(
            "degraded", "Workload has 0 of 1 desired replicas ready", NOW,
            workload_present=True, desired_replicas=1, ready_replicas=0,
        )
        document = HealthEngine(
            self.registry, probe, clock=lambda: NOW
        ).document()
        Draft202012Validator(SCHEMA).validate(document)
        items = by_id(document)

        self.assertEqual(items["ssc"]["dimensions"]["dependency"]["state"], "blocked")
        self.assertEqual(items["ssc"]["dimensions"]["workload"]["state"], "absent")
        self.assertEqual(items["ssc"]["dimensions"]["application"]["state"], "unknown")
        self.assertIn("ssc/webapp-ready", items["ssc"]["rootCauses"])
        scanner = items["scancentral-dast-scanner"]
        self.assertEqual(scanner["dimensions"]["workload"]["state"], "not-ready")
        self.assertIn("scancentral-dast-scanner/scanner-ready", scanner["rootCauses"])
        self.assertEqual(document["summary"]["workloadAbsent"], 1)
        self.assertEqual(document["summary"]["workloadNotReady"], 1)
        self.assertGreaterEqual(document["summary"]["applicationUnknown"], 2)

    def test_stale_dependency_keeps_fresh_local_workload_evidence_and_recovers(self):
        probe = MultidimensionalProbe()
        probe.results[("dns", "dns-lookup")] = ProbeResult(
            "healthy", "Lookup passed", NOW - timedelta(minutes=6)
        )
        first = by_id(HealthEngine(self.registry, probe, clock=lambda: NOW).document())
        self.assertEqual(first["ssc"]["dimensions"]["dependency"]["state"], "blocked")
        self.assertEqual(first["ssc"]["dimensions"]["workload"]["state"], "ready")
        self.assertEqual(first["ssc"]["dimensions"]["application"]["state"], "unknown")

        probe.results[("dns", "dns-lookup")] = ProbeResult(
            "healthy", "Lookup passed", NOW
        )
        second = by_id(HealthEngine(self.registry, probe, clock=lambda: NOW).document())
        self.assertEqual(second["ssc"]["dimensions"]["dependency"]["state"], "clear")
        self.assertEqual(second["ssc"]["dimensions"]["application"]["state"], "healthy")

    def test_sensitive_probe_summary_is_redacted(self):
        self.probe.states["microk8s-node"] = (
            "unhealthy",
            "authorization: Bearer abc",
            NOW,
        )
        serialized = json.dumps(self.engine().document())
        self.assertNotIn("Bearer abc", serialized)
        self.assertIn("could not be safely displayed", serialized)

    def test_safe_license_configuration_summary_remains_observable(self):
        self.probe.states["lim"] = (
            "healthy",
            "Required license pool is configured",
            NOW,
        )
        evidence = by_id(self.engine().document())["lim"]["evidence"]
        self.assertTrue(
            any(item["summary"] == "Required license pool is configured" for item in evidence)
        )

    def test_health_api_is_read_only_and_schema_valid(self):
        response = request(ManagerAPI(health_probe=self.probe))
        self.assertEqual(response["status"], "200 OK")
        Draft202012Validator(SCHEMA).validate(response["json"])

    def test_health_api_composes_independent_availability_domains(self):
        current = datetime.now(timezone.utc)
        probe = FakeProbe()
        probe.states = {
            subject: ("healthy", "Authoritative check passed", current)
            for subject in (
                "microk8s-node", "storage", "dns", "ingress", "tls", "mysql",
                "postgresql", "lim", "ssc", "scancentral-sast",
                "scancentral-dast-core", "scancentral-dast-scanner",
            )
        }
        response = request(ManagerAPI(
            health_probe=probe,
            availability_monitor=Availability(
                self.availability(
                    state="dns-mismatch", tls="not-attempted", checked_at=current
                )
            ),
        ))
        self.assertEqual(response["status"], "200 OK")
        ssc = by_id(response["json"])["ssc"]
        self.assertEqual(ssc["state"], "degraded")
        self.assertEqual(ssc["directState"], "healthy")


if __name__ == "__main__":
    unittest.main()
