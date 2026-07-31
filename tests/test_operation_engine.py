"""Regression tests for typed dependency-aware lifecycle execution."""

from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from manager.component_registry import ComponentRegistry
from manager.authorization import (
    ActorIdentity, ApprovalStore, AuthorizationError, AuthorizationService,
    OperationPlan,
)
from manager.operation_engine import (
    DependencyBlocked,
    ExistingInstallation,
    InvalidOperation,
    OperationConflict,
    OperationEngine,
    OperationError,
    OperationStore,
    PreflightBlocked,
    RECOVERY_CLASS_BY_OPERATION,
    StepCancelled,
    StepTimedOut,
)


ROOT = Path(__file__).resolve().parents[1]


class RecordingAdapter:
    def __init__(self, failures: int = 0) -> None:
        self.calls: list[tuple[str, str]] = []
        self.failures = failures
        self.entered = threading.Event()
        self.release = threading.Event()
        self.block = False

    def execute(self, step, *, deadline, cancelled) -> None:
        self.calls.append((step.component_id, step.operation))
        self.entered.set()
        if self.block:
            while not self.release.wait(0.005):
                if cancelled():
                    raise StepCancelled()
        if self.failures:
            self.failures -= 1
            raise OperationError("simulated adapter failure")


class RecordingVerifier:
    def __init__(self, fail_component: str | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail_component = fail_component

    def verify(self, component_id, check_id, *, deadline, cancelled) -> bool:
        self.calls.append((component_id, check_id))
        return component_id != self.fail_component


class OperationEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = OperationStore(Path(self.temp.name) / "operations.db")
        self.registry = ComponentRegistry.load()
        self.adapter = RecordingAdapter()
        self.verifier = RecordingVerifier()
        self.engine = OperationEngine(
            self.registry, self.store, self.adapter, self.verifier,
            preflight_provider=lambda: {"readiness": {
                action: {"ready": True, "blockers": []}
                for action in ("deploy", "start", "suspend")
            }},
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_success_starts_dependencies_first_and_verifies_health(self) -> None:
        result = self.engine.submit(
            "start", ["scancentral-sast"], actor="local:test"
        )
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(
            self.adapter.calls,
            [
                ("mysql", "start"),
                ("ssc", "start"),
                ("scancentral-sast", "start"),
            ],
        )
        self.assertTrue(self.verifier.calls)
        self.assertEqual(result["completedSteps"], result["totalSteps"])
        schema = json.loads(
            (ROOT / "registry/schemas/lifecycle-operation.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).validate(result)

    def test_plan_and_failure_expose_truthful_recovery_boundaries(self) -> None:
        start = self.engine.plan("start", ["mysql"])
        self.assertEqual(start["steps"][0]["recoveryClass"], "reversible")
        self.assertEqual(
            RECOVERY_CLASS_BY_OPERATION["delete-data"], "irreversible"
        )

        self.verifier.fail_component = "mysql"
        failed = self.engine.submit("start", ["mysql"], actor="local:test")
        self.assertTrue(failed["recovery"]["required"])
        self.assertEqual(failed["recovery"]["boundary"], "reversible")
        self.assertIn("Review evidence", failed["recovery"]["nextAction"])

    def test_stop_blocks_until_all_reverse_dependencies_are_selected(self) -> None:
        with self.assertRaises(DependencyBlocked):
            self.engine.submit("stop", ["mysql"], actor="local:test")

        result = self.engine.submit(
            "stop",
            ["mysql", "ssc", "scancentral-sast", "scancentral-dast-core",
             "scancentral-dast-scanner"],
            actor="local:test",
        )
        self.assertEqual(result["state"], "succeeded")
        self.assertLess(
            self.adapter.calls.index(("scancentral-sast", "stop")),
            self.adapter.calls.index(("ssc", "stop")),
        )
        self.assertLess(
            self.adapter.calls.index(("ssc", "stop")),
            self.adapter.calls.index(("mysql", "stop")),
        )

    def test_lab_plans_expand_the_authoritative_graph_and_preserve_data(self) -> None:
        start = self.engine.lab_plan("start", "scancentral-sast")
        self.assertEqual(
            start["executionOrder"], ["mysql", "ssc", "scancentral-sast"]
        )
        self.assertEqual(start["automaticExpansion"], ["mysql", "ssc"])
        self.assertTrue(start["dataBoundary"]["preservesPersistentVolumes"])
        self.assertFalse(start["dataBoundary"]["uninstallsResources"])
        self.assertFalse(start["dataBoundary"]["deletesData"])
        self.assertFalse(start["dataBoundary"]["stopsMicroK8s"])
        self.assertFalse(start["dataBoundary"]["stopsEC2"])

        suspend = self.engine.lab_plan("suspend", "mysql")
        self.assertEqual(suspend["executionOrder"][-1], "mysql")
        self.assertIn("ssc", suspend["automaticExpansion"])
        order = suspend["executionOrder"]
        self.assertLess(order.index("scancentral-sast"), order.index("ssc"))
        self.assertLess(order.index("ssc"), order.index("mysql"))

    def test_failed_lab_start_does_not_advance_downstream(self) -> None:
        self.verifier.fail_component = "ssc"
        result = self.engine.submit_lab_async(
            "start", "scancentral-sast", actor="local:test"
        )
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            result = self.store.get(result["id"])
            if result["state"] in {"failed", "succeeded"}:
                break
            time.sleep(0.002)
        self.assertEqual(result["state"], "failed")
        self.assertNotIn(("scancentral-sast", "start"), self.adapter.calls)
        self.assertEqual(result["workflow"], "start-lab")

    def test_timeout_is_bounded(self) -> None:
        class TimeoutAdapter:
            def execute(self, step, *, deadline, cancelled):
                raise StepTimedOut()

        engine = OperationEngine(
            self.registry, self.store, TimeoutAdapter(), self.verifier
        )
        result = engine.submit("start", ["mysql"], actor="local:test")
        self.assertEqual(result["state"], "timed-out")
        self.assertNotIn("adapter", result["error"].lower())

    def test_running_operation_can_be_cancelled(self) -> None:
        self.adapter.block = True
        result: list[dict] = []
        worker = threading.Thread(
            target=lambda: result.append(
                self.engine.submit("start", ["mysql"], actor="local:test")
            )
        )
        worker.start()
        self.assertTrue(self.adapter.entered.wait(1))
        operation_id = self.store.connection.execute(
            "SELECT id FROM lifecycle_operations"
        ).fetchone()[0]
        self.engine.cancel(operation_id, actor="local:canceller")
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result[0]["state"], "cancelled")

    def test_idempotent_step_retries_and_records_progress(self) -> None:
        self.adapter.failures = 1
        result = self.engine.submit("start", ["mysql"], actor="local:test")
        self.assertEqual(result["state"], "succeeded")
        failed = [
            event
            for event in self.store.events(result["id"])
            if event["type"] == "attempt-failed"
        ]
        self.assertEqual(failed[0]["attempt"], 1)
        self.assertTrue(failed[0]["retrying"])

    def test_restart_recovers_with_stop_then_dependency_ordered_start(self) -> None:
        result = self.engine.submit(
            "restart", ["scancentral-sast"], actor="local:test"
        )
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(self.adapter.calls[0], ("scancentral-sast", "stop"))
        self.assertEqual(
            self.adapter.calls[-3:],
            [
                ("mysql", "start"),
                ("ssc", "start"),
                ("scancentral-sast", "start"),
            ],
        )

    def test_partial_failure_stops_remaining_plan_and_can_retry(self) -> None:
        self.verifier.fail_component = "ssc"
        failed = self.engine.submit(
            "start", ["scancentral-sast"], actor="local:test"
        )
        self.assertEqual(failed["state"], "failed")
        self.assertNotIn(("scancentral-sast", "start"), self.adapter.calls)

        self.verifier.fail_component = None
        retried = self.engine.retry(failed["id"], actor="local:retry")
        self.assertEqual(retried["state"], "succeeded")
        self.assertEqual(retried["retryOf"], failed["id"])

    def test_clean_install_gates_existing_data_and_preflight_before_execution(self) -> None:
        footprint = {item: "absent" for item in self.registry.component_ids}
        ready = {"ready": True, "items": []}
        engine = OperationEngine(
            self.registry, self.store, self.adapter, self.verifier,
            preflight_provider=lambda: ready,
            footprint_provider=lambda components: {
                item: footprint[item] for item in components
            },
        )
        plan = engine.clean_install_plan()
        self.assertTrue(plan["ready"])
        self.assertEqual(
            plan["components"], list(self.registry.dependency_order())
        )

        ready["ready"] = False
        with self.assertRaises(PreflightBlocked):
            engine.submit_clean_install_async(actor="local:test")
        self.assertEqual(self.adapter.calls, [])

        ready["ready"] = True
        footprint["mysql"] = "present"
        with self.assertRaises(ExistingInstallation):
            engine.submit_clean_install_async(actor="local:test")
        self.assertEqual(self.adapter.calls, [])

    def test_clean_install_retry_resumes_after_verified_steps(self) -> None:
        footprint = {item: "absent" for item in self.registry.component_ids}
        engine = OperationEngine(
            self.registry, self.store, self.adapter, self.verifier,
            preflight_provider=lambda: {"ready": True, "items": []},
            footprint_provider=lambda components: {
                item: footprint[item] for item in components
            },
        )
        self.verifier.fail_component = "ssc"
        failed = engine.submit_clean_install_async(actor="local:test")
        worker_deadline = threading.Event()
        for _ in range(1000):
            failed = self.store.get(failed["id"])
            if failed["state"] in {"failed", "succeeded"}:
                break
            worker_deadline.wait(0.001)
        self.assertEqual(failed["state"], "failed")
        mysql_calls = self.adapter.calls.count(("mysql", "install"))

        self.verifier.fail_component = None
        resumed = engine.retry_async(failed["id"], actor="local:retry")
        for _ in range(1000):
            resumed = self.store.get(resumed["id"])
            if resumed["state"] in {"failed", "succeeded"}:
                break
            worker_deadline.wait(0.001)
        self.assertEqual(resumed["state"], "succeeded")
        self.assertEqual(
            self.adapter.calls.count(("mysql", "install")), mysql_calls
        )
        self.assertTrue(
            any(
                event["type"] == "step-resumed"
                for event in self.store.events(resumed["id"])
            )
        )

    def test_concurrent_conflicts_are_rejected(self) -> None:
        self.adapter.block = True
        worker = threading.Thread(
            target=lambda: self.engine.submit("start", ["mysql"], actor="local:test")
        )
        worker.start()
        self.assertTrue(self.adapter.entered.wait(1))
        with self.assertRaises(OperationConflict):
            self.engine.submit("start", ["ssc"], actor="local:other")
        operation_id = self.store.connection.execute(
            "SELECT id FROM lifecycle_operations"
        ).fetchone()[0]
        self.engine.cancel(operation_id, actor="local:test")
        worker.join(2)

    def test_restart_marks_incomplete_durable_operation_interrupted(self) -> None:
        document = {
            "id": "incomplete",
            "state": "running",
            "components": ["mysql"],
            "error": None,
            "updatedAt": "2026-01-01T00:00:00Z",
        }
        self.store.create(document)
        self.store.close()
        self.store = OperationStore(Path(self.temp.name) / "operations.db")
        recovered = self.store.get("incomplete")
        self.assertEqual(recovered["state"], "interrupted")
        self.assertIn("restarted", recovered["error"])

    def test_request_cannot_supply_commands_paths_or_undeclared_upgrade(self) -> None:
        with self.assertRaises(TypeError):
            self.engine.submit(  # type: ignore[call-arg]
                "start", ["mysql"], actor="local:test", command="rm"
            )
        with self.assertRaises(InvalidOperation):
            self.engine.submit("upgrade", ["mysql"], actor="local:test")
        with self.assertRaises(InvalidOperation):
            self.engine.submit("start", ["../../tmp/adapter"], actor="local:test")
        registry_text = json.dumps(self.registry.document)
        self.assertNotIn("/home/", registry_text)

    def test_shared_authorization_is_enforced_before_adapter_execution(self) -> None:
        approval_store = ApprovalStore(Path(self.temp.name) / "approvals.db")
        now = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
        identity = ActorIdentity("local:test", "web", "session-1", now)
        states = {
            "mysql": "running", "ssc": "running", "scancentral-sast": "running"
        }
        authorization = AuthorizationService(approval_store, clock=lambda: now)
        authorized = OperationEngine(
            self.registry,
            self.store,
            self.adapter,
            self.verifier,
            authorization=authorization,
            state_provider=lambda targets: {target: states[target] for target in targets},
        )
        with self.assertRaises(AuthorizationError):
            authorized.submit(
                "restart", ["scancentral-sast"], actor=identity.actor,
                identity=identity,
            )
        self.assertEqual(self.adapter.calls, [])

        # Engine affected-target ordering follows stop then dependency closure.
        plan = OperationPlan(
            "restart", ("scancentral-sast", "mysql", "ssc"),
            {
                "mysql": "running", "scancentral-sast": "running",
                "ssc": "running",
            },
        )
        approval = authorization.request(plan, identity)
        authorization.approve(approval["id"], identity)
        result = authorized.submit(
            "restart", ["scancentral-sast"], actor=identity.actor,
            identity=identity, approval_id=approval["id"],
        )
        self.assertEqual(result["state"], "succeeded")
        approval_store.close()


if __name__ == "__main__":
    unittest.main()
