"""Contract and regression tests for deployment preflight."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from manager.api import PREFLIGHT_PATH, ManagerAPI
from manager.component_registry import ComponentRegistry
from manager.preflight import PreflightEngine, PreflightResult


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
SCHEMA = json.loads(
    (ROOT / "registry/schemas/preflight-report.schema.json").read_text()
)


class FakeProbe:
    def __init__(self):
        self.results = {}
        self.calls = []

    def probe(self, check):
        self.calls.append(check)
        return self.results.get(
            check.id, PreflightResult("pass")
        )


class SlowProbe(FakeProbe):
    def probe(self, check):
        time.sleep(0.05)
        return super().probe(check)


def by_id(document):
    return {item["id"]: item for item in document["items"]}


def request(app, method="GET"):
    response = {}

    def start_response(status, headers):
        response["status"] = status
        response["headers"] = dict(headers)

    body = b"".join(
        app(
            {"REQUEST_METHOD": method, "PATH_INFO": PREFLIGHT_PATH},
            start_response,
        )
    )
    response["body"] = body
    response["json"] = json.loads(body) if body else None
    return response


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.registry = ComponentRegistry.load()
        self.probe = FakeProbe()

    def engine(self, probe=None, **kwargs):
        kwargs.setdefault(
            "capability_provider",
            lambda: {"expiresAt": "2099-01-01T00:00:00Z", "capabilities": [{
                "id": "lifecycle-execution", "state": "available", "canMutate": True
            }]},
        )
        return PreflightEngine(
            self.registry,
            probe or self.probe,
            clock=lambda: NOW,
            **kwargs,
        )

    def test_ready_report_covers_full_scope_and_schema(self):
        document = self.engine().document()
        Draft202012Validator(SCHEMA).validate(document)
        self.assertTrue(document["ready"])
        self.assertTrue(document["readiness"]["observation"]["ready"])
        self.assertTrue(document["readiness"]["deployment"]["ready"])
        self.assertTrue(document["readiness"]["start"]["ready"])
        self.assertTrue(document["readiness"]["suspend"]["ready"])
        self.assertEqual(
            document["summary"],
            {"blocker": 0, "warning": 0, "information": 12},
        )
        self.assertEqual(
            set(by_id(document)),
            {
                "host-capacity",
                "microk8s",
                "microk8s-addons",
                "storage",
                "ingress",
                "dns",
                "tls",
                "external-license",
                "registry-authentication",
                "image-reachability",
                "configuration",
                "compatibility",
            },
        )
        self.assertTrue(
            all(
                check.target
                in {
                    "single-node",
                    "local-cluster",
                    "required-addons",
                    "default-storage",
                    "managed-ingress",
                    "managed-hosts",
                    "configured-license",
                    "required-registries",
                    "fortify-24.4-eval.1",
                    "deployment-config",
                }
                for check in self.probe.calls
            )
        )

    def test_required_blockers_have_actionable_safe_remediation(self):
        failures = {
            "external-license",
            "registry-authentication",
            "image-reachability",
            "host-capacity",
            "dns",
            "tls",
        }
        self.probe.results.update(
            {
                check_id: PreflightResult("fail")
                for check_id in failures
            }
        )
        document = self.engine().document()
        items = by_id(document)
        self.assertFalse(document["ready"])
        self.assertEqual(document["summary"]["blocker"], len(failures))
        for check_id in failures:
            self.assertEqual(items[check_id]["classification"], "blocker")
            self.assertTrue(items[check_id]["remediation"]["safe"])
            self.assertTrue(items[check_id]["remediation"]["summary"])
            self.assertIn(f"#{check_id}", items[check_id]["remediation"]["href"])

    def test_warning_does_not_prevent_deployment(self):
        self.probe.results["tls"] = PreflightResult(
            "warning"
        )
        document = self.engine().document()
        self.assertTrue(document["ready"])
        self.assertEqual(
            document["profile"],
            {
                "id": "fortify-24.4-eval.1",
                "maturity": "experimental",
                "vendorSupported": False,
            },
        )
        self.assertEqual(document["summary"]["warning"], 1)
        self.assertEqual(by_id(document)["tls"]["classification"], "warning")

    def test_recovery_is_observed_on_fresh_repeat(self):
        self.probe.results["external-license"] = PreflightResult(
            "fail"
        )
        self.assertFalse(self.engine().document()["ready"])
        self.probe.results["external-license"] = PreflightResult(
            "pass"
        )
        self.probe.calls.clear()
        second = self.engine().document()
        self.assertTrue(second["ready"])
        self.assertEqual(by_id(second)["external-license"]["status"], "pass")
        self.assertEqual(len(self.probe.calls), 12)

    def test_observation_can_be_ready_while_mutation_is_unavailable(self):
        document = self.engine(capability_provider=None).document()
        self.assertTrue(document["readiness"]["observation"]["ready"])
        for action in ("deployment", "start", "suspend"):
            self.assertFalse(document["readiness"][action]["ready"])
            self.assertIn(
                "LIFECYCLE_EVIDENCE_UNAVAILABLE",
                document["readiness"][action]["blockers"],
            )

    def test_action_specific_blockers_do_not_overblock_suspend(self):
        self.probe.results["external-license"] = PreflightResult("fail")
        document = self.engine().document()
        self.assertFalse(document["readiness"]["deployment"]["ready"])
        self.assertTrue(document["readiness"]["start"]["ready"])
        self.assertTrue(document["readiness"]["suspend"]["ready"])

    def test_stale_capability_evidence_blocks_every_mutation_action(self):
        document = self.engine(capability_provider=lambda: {
            "expiresAt": "2026-07-30T11:59:59Z",
            "capabilities": [{
                "id": "lifecycle-execution", "state": "available", "canMutate": True
            }],
        }).document()
        self.assertTrue(document["readiness"]["observation"]["ready"])
        for action in ("deployment", "start", "suspend"):
            self.assertFalse(document["readiness"][action]["ready"])

    def test_unexpected_capability_failure_is_sanitized_and_fails_closed(self):
        def unavailable():
            raise Exception("sensitive capability detail")

        document = self.engine(capability_provider=unavailable).document()
        self.assertTrue(document["readiness"]["observation"]["ready"])
        for action in ("deployment", "start", "suspend"):
            self.assertFalse(document["readiness"][action]["ready"])
            self.assertEqual(
                document["readiness"][action]["blockers"],
                ["LIFECYCLE_EVIDENCE_UNAVAILABLE"],
            )
        self.assertNotIn("sensitive", str(document))

    def test_adapter_exception_details_never_enter_report(self):
        class UnsafeProbe:
            def probe(self, check):
                raise RuntimeError("sensitive adapter detail")

        serialized = json.dumps(self.engine(UnsafeProbe()).document())
        self.assertNotIn("sensitive adapter detail", serialized)
        self.assertIn("could not obtain safe evidence", serialized)

    def test_timeout_is_bounded_and_actionable(self):
        started = time.monotonic()
        document = self.engine(SlowProbe(), max_probe_timeout=0.001).document()
        self.assertLess(time.monotonic() - started, 0.2)
        self.assertFalse(document["ready"])
        self.assertTrue(
            all(
                item["summary"] == "Check exceeded the aggregate bounded deadline"
                and "remediation" in item
                for item in document["items"]
            )
        )

    def test_independent_checks_run_with_controlled_concurrency(self):
        started = time.monotonic()
        document = self.engine(
            SlowProbe(),
            max_probe_timeout=0.2,
            max_workers=6,
        ).document()
        self.assertLess(time.monotonic() - started, 0.15)
        self.assertTrue(document["ready"])

    def test_api_is_get_head_only_and_schema_valid(self):
        app = ManagerAPI(preflight_probe=self.probe)
        get = request(app)
        self.assertEqual(get["status"], "200 OK")
        self.assertEqual(get["headers"]["Cache-Control"], "no-store")
        Draft202012Validator(SCHEMA).validate(get["json"])
        self.assertEqual(request(app, "HEAD")["body"], b"")
        post = request(app, "POST")
        self.assertEqual(post["status"], "405 Method Not Allowed")
        self.assertEqual(post["headers"]["Allow"], "GET, HEAD")

    def test_malformed_registry_error_is_sanitized(self):
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
                "message": "preflight read model is unavailable",
            },
        )
        self.assertNotIn(str(path), response["body"].decode())


if __name__ == "__main__":
    unittest.main()
