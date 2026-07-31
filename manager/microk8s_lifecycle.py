"""Bounded local MicroK8s lifecycle and post-operation health adapters."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Callable

from manager.component_registry import ComponentRegistry
from manager.health import CheckSpec, HealthProbe
from manager.kubernetes_observer import NAMESPACE
from manager.operation_engine import (
    HealthVerifier,
    OperationAdapter,
    OperationError,
    Step,
    StepCancelled,
    StepTimedOut,
)


ROOT = Path(__file__).resolve().parents[1]
LIFECYCLE_KUBECONFIG = "/var/lib/fortify-lab-manager/cluster-access/lifecycle.kubeconfig"
LIFECYCLE_CLIENT_ROOT = "/var/lib/fortify-lab-manager/lifecycle-bin"
_LAYERS = {
    "workload-ready": "workload",
    "persistent-volume": "storage",
    "native-readiness": "application",
    "database-query": "functional",
    "https": "network",
    "application-ready": "application",
    "dependency-connectivity": "dependency",
    "registration": "functional",
}


class MicroK8sLifecycleAdapter(OperationAdapter):
    """Execute only an exact executable declared by the loaded registry.

    The child receives no request arguments and no inherited environment. The
    existing component action remains responsible for using Kubernetes Secret
    references; stdout and stderr are intentionally discarded.
    """

    def __init__(
        self,
        registry: ComponentRegistry,
        *,
        root: Path = ROOT,
        namespace: str = NAMESPACE,
        popen: Callable[..., subprocess.Popen] = subprocess.Popen,
        monotonic: Callable[[], float] = time.monotonic,
        poll_interval: float = 0.1,
    ) -> None:
        if root.resolve() != ROOT.resolve():
            raise ValueError("lifecycle root must be the installed repository")
        if namespace != NAMESPACE:
            raise ValueError("only the managed fortify namespace is supported")
        if poll_interval <= 0 or poll_interval > 1:
            raise ValueError("poll interval must be bounded")
        self._registry = registry
        self._root = root.resolve()
        self._namespace = namespace
        self._popen = popen
        self._monotonic = monotonic
        self._poll_interval = poll_interval

    def runtime_ready(self) -> bool:
        """Verify the installed, allow-listed adapter closure without executing it."""
        if not Path("/bin/bash").is_file():
            return False
        operations = (
            operation
            for component_id in self._registry.component_ids
            for operation in self._registry.lifecycle_operations(component_id)
        )
        adapters = {operation["adapter"] for operation in operations}
        return bool(adapters) and all(
            (self._root / adapter).resolve().is_file()
            and (self._root / adapter).resolve().is_relative_to(self._root / "apps")
            for adapter in adapters
        ) and (Path(LIFECYCLE_CLIENT_ROOT) / "microk8s").is_file() and bool(
            (Path(LIFECYCLE_CLIENT_ROOT) / "microk8s").stat().st_mode & 0o111
        )

    def credential_authorized(self) -> bool:
        """Bounded positive and mandatory-denial checks for the live credential."""
        command = str(Path(LIFECYCLE_CLIENT_ROOT) / "microk8s")
        environment = {
            "PATH": f"{LIFECYCLE_CLIENT_ROOT}:/usr/sbin:/usr/bin:/sbin:/bin",
            "KUBECONFIG": LIFECYCLE_KUBECONFIG,
        }
        checks = (
            ([command, "kubectl", "auth", "can-i", "get", "configmaps", "-n", self._namespace], "yes"),
            ([command, "kubectl", "auth", "can-i", "get", "secrets", "-n", self._namespace], "no"),
        )
        try:
            for arguments, expected in checks:
                result = subprocess.run(
                    arguments, env=environment, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    text=True, timeout=3, check=False,
                )
                if result.returncode != 0 or result.stdout.strip() != expected:
                    return False
            return True
        except (OSError, subprocess.TimeoutExpired):
            return False

    def execute(
        self, step: Step, *, deadline: float, cancelled: Callable[[], bool]
    ) -> None:
        adapter = self._declared_adapter(step)
        if cancelled():
            raise StepCancelled()
        if self._monotonic() >= deadline:
            raise StepTimedOut()
        try:
            process = self._popen(
                ["/bin/bash", str(adapter)],
                cwd=str(self._root),
                env={
                    "PATH": (
                        f"{LIFECYCLE_CLIENT_ROOT}:"
                        "/usr/sbin:/usr/bin:/sbin:/bin"
                    ),
                    "FORTIFY_HOME_K8S": str(self._root),
                    "NAMESPACE": self._namespace,
                    "KUBECONFIG": LIFECYCLE_KUBECONFIG,
                    "HELM_DRIVER": "configmap",
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as error:
            raise OperationError("declared lifecycle action could not start") from error

        while process.poll() is None:
            if cancelled():
                self._stop(process)
                raise StepCancelled()
            if self._monotonic() >= deadline:
                self._stop(process)
                raise StepTimedOut()
            time.sleep(self._poll_interval)
        if process.returncode:
            raise OperationError("declared lifecycle action failed")

    def _declared_adapter(self, step: Step) -> Path:
        operations = {
            item["id"]: item
            for item in self._registry.lifecycle_operations(step.component_id)
        }
        declared = operations.get(step.operation)
        if declared is None or declared["adapter"] != step.adapter:
            raise OperationError("lifecycle action is outside the registry allow-list")
        relative = Path(step.adapter)
        if relative.is_absolute() or ".." in relative.parts:
            raise OperationError("lifecycle action is outside the registry allow-list")
        adapter = (self._root / relative).resolve()
        try:
            adapter.relative_to(self._root / "apps")
        except ValueError as error:
            raise OperationError("lifecycle action is outside the registry allow-list") from error
        if not adapter.is_file():
            raise OperationError("declared lifecycle action is unavailable")
        return adapter

    @staticmethod
    def _stop(process: subprocess.Popen) -> None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


class RegistryHealthVerifier(HealthVerifier):
    """Verify only a registry-declared check through the protected probe."""

    def __init__(self, registry: ComponentRegistry, probe: HealthProbe) -> None:
        self._registry = registry
        self._probe = probe

    def verify(
        self,
        component_id: str,
        check_id: str,
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> bool:
        checks = {
            item["id"]: item
            for item in self._registry.monitoring_checks(component_id)
        }
        check = checks.get(check_id)
        if check is None:
            raise OperationError("verification check is outside the registry allow-list")
        if cancelled():
            raise StepCancelled()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise StepTimedOut()
        timeout = min(float(check["timeoutSeconds"]), remaining)
        result = self._probe.probe(
            CheckSpec(
                id=check_id,
                subject_id=component_id,
                layer=_LAYERS.get(check["type"], "functional"),
                probe_type=check["type"],
                target=check["target"],
                timeout_seconds=timeout,
                required=bool(check["required"]),
            )
        )
        if check_id.endswith(("-stopped", "-removed")):
            return result.state in {"stopped", "healthy"}
        return result.state == "healthy"
