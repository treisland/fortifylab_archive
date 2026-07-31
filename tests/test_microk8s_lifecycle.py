"""Live-adapter contract tests using process and probe fakes only."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from manager.component_registry import ComponentRegistry
from manager.health import ProbeResult
from manager.microk8s_lifecycle import (
    MicroK8sLifecycleAdapter,
    RegistryHealthVerifier,
)
from manager.operation_engine import OperationError, Step, StepCancelled, StepTimedOut


ROOT = Path(__file__).resolve().parents[1]


class FakeProcess:
    def __init__(self, polls=(None, 0)) -> None:
        self.polls = list(polls)
        self.returncode = None
        self.terminated = False
        self.killed = False

    def poll(self):
        if self.polls:
            result = self.polls.pop(0)
            if result is not None:
                self.returncode = result
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


class Probe:
    def __init__(self, state="healthy") -> None:
        self.state = state
        self.calls = []

    def probe(self, check):
        self.calls.append(check)
        return ProbeResult(
            self.state, "sanitized", datetime.now(timezone.utc), 1
        )


class MicroK8sLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.registry = ComponentRegistry.load()
        self.step = Step(
            "mysql", "start", "apps/mysql/start.sh", 300, ("database-ready",), 2
        )

    def test_executes_exact_declared_action_with_fixed_empty_environment(self):
        captured = {}

        def launch(command, **options):
            captured.update(command=command, **options)
            return FakeProcess()

        adapter = MicroK8sLifecycleAdapter(self.registry, popen=launch)
        with patch("manager.microk8s_lifecycle.time.sleep"):
            adapter.execute(self.step, deadline=float("inf"), cancelled=lambda: False)
        self.assertEqual(
            captured["command"], ["/bin/bash", str(ROOT / "apps/mysql/start.sh")]
        )
        self.assertEqual(
            set(captured["env"]),
            {
                "PATH", "FORTIFY_HOME_K8S", "NAMESPACE", "KUBECONFIG",
                "HELM_DRIVER",
            },
        )
        self.assertEqual(captured["env"]["NAMESPACE"], "fortify")
        self.assertEqual(captured["env"]["HELM_DRIVER"], "configmap")
        self.assertTrue(
            captured["env"]["PATH"].startswith(
                "/var/lib/fortify-lab-manager/lifecycle-bin:"
            )
        )
        self.assertNotIn("/snap/bin", captured["env"]["PATH"])
        self.assertIs(captured["stdout"], subprocess.DEVNULL)
        self.assertIs(captured["stderr"], subprocess.DEVNULL)

    def test_rejects_other_path_operation_namespace_and_root_before_io(self):
        called = []
        adapter = MicroK8sLifecycleAdapter(
            self.registry, popen=lambda *args, **kwargs: called.append(args)
        )
        forged = Step("mysql", "start", "apps/mysql/stop.sh", 1, (), 1)
        with self.assertRaises(OperationError):
            adapter.execute(forged, deadline=float("inf"), cancelled=lambda: False)
        with self.assertRaises(ValueError):
            MicroK8sLifecycleAdapter(self.registry, namespace="default")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                MicroK8sLifecycleAdapter(self.registry, root=Path(directory))
        self.assertEqual(called, [])

    def test_cooperative_cancellation_terminates_child(self):
        process = FakeProcess((None, None))
        states = iter((False, True))
        adapter = MicroK8sLifecycleAdapter(
            self.registry, popen=lambda *args, **kwargs: process
        )
        with patch("manager.microk8s_lifecycle.time.sleep"):
            with self.assertRaises(StepCancelled):
                adapter.execute(
                    self.step, deadline=float("inf"), cancelled=lambda: next(states)
                )
        self.assertTrue(process.terminated)

    def test_timeout_terminates_child(self):
        process = FakeProcess((None, None))
        times = iter((0, 0, 11))
        adapter = MicroK8sLifecycleAdapter(
            self.registry,
            popen=lambda *args, **kwargs: process,
            monotonic=lambda: next(times),
        )
        with patch("manager.microk8s_lifecycle.time.sleep"):
            with self.assertRaises(StepTimedOut):
                adapter.execute(self.step, deadline=10, cancelled=lambda: False)
        self.assertTrue(process.terminated)

    def test_adapter_failure_is_sanitized(self):
        adapter = MicroK8sLifecycleAdapter(
            self.registry, popen=lambda *args, **kwargs: FakeProcess((7,))
        )
        with self.assertRaisesRegex(OperationError, "declared lifecycle action failed"):
            adapter.execute(
                self.step, deadline=float("inf"), cancelled=lambda: False
            )

    def test_verifier_accepts_only_declared_check_and_bounds_timeout(self):
        probe = Probe()
        verifier = RegistryHealthVerifier(self.registry, probe)
        with patch("manager.microk8s_lifecycle.time.monotonic", return_value=5):
            self.assertTrue(
                verifier.verify(
                    "mysql", "database-ready", deadline=8, cancelled=lambda: False
                )
            )
        self.assertEqual(probe.calls[0].timeout_seconds, 3)
        with self.assertRaises(OperationError):
            verifier.verify(
                "mysql", "secret-value", deadline=8, cancelled=lambda: False
            )


if __name__ == "__main__":
    unittest.main()
