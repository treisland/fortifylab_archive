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
            root["evidence"][0]["summary"], "Check exceeded its bounded deadline"
        )

    def test_stale_evidence_is_distinct_and_blocks_dependents(self):
        self.probe.states["dns"] = (
            "healthy",
            "Lookup passed",
            NOW - timedelta(minutes=6),
        )
        items = by_id(self.engine().document())
        self.assertEqual(items["dns"]["state"], "stale")
        self.assertEqual(items["ingress"]["state"], "blocked")

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

    def test_sensitive_probe_summary_is_redacted(self):
        self.probe.states["microk8s-node"] = (
            "unhealthy",
            "authorization: Bearer abc",
            NOW,
        )
        serialized = json.dumps(self.engine().document())
        self.assertNotIn("Bearer abc", serialized)
        self.assertIn("could not be safely displayed", serialized)

    def test_health_api_is_read_only_and_schema_valid(self):
        response = request(ManagerAPI(health_probe=self.probe))
        self.assertEqual(response["status"], "200 OK")
        Draft202012Validator(SCHEMA).validate(response["json"])


if __name__ == "__main__":
    unittest.main()
