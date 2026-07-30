"""Regression tests for typed dependency-aware lifecycle execution."""

from __future__ import annotations

import json
import tempfile
import threading
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
    InvalidOperation,
    OperationConflict,
    OperationEngine,
    OperationError,
    OperationStore,
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
            self.registry, self.store, self.adapter, self.verifier
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
