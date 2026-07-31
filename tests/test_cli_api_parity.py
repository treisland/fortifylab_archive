"""CLI and HTTP contract parity for typed manager operations."""

from __future__ import annotations

import io
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
from email.message import Message
from pathlib import Path

from manager.authorization import ApprovalStore, AuthorizationService
from manager.cli import (
    EXIT_BLOCKED,
    EXIT_CANCELLED,
    EXIT_FAILED,
    EXIT_REJECTED,
    EXIT_TIMED_OUT,
    ClientError,
    OperationClient,
    _result_exit,
)
from manager.component_registry import ComponentRegistry
from manager.dashboard import DashboardApp, password_verifier
from manager.operation_engine import (
    OperationEngine,
    OperationStore,
    StepCancelled,
    StepTimedOut,
)
from manager.web_operations import WebOperationAPI


class Adapter:
    def __init__(self) -> None:
        self.mode = "success"
        self.sources: list[str] = []

    def execute(self, step, *, deadline, cancelled):
        if self.mode == "failed":
            raise RuntimeError("sensitive adapter detail")
        if self.mode == "timed-out":
            raise StepTimedOut()
        while self.mode == "blocked":
            if cancelled():
                raise StepCancelled()
            time.sleep(0.002)


class Verifier:
    def verify(self, component_id, check_id, *, deadline, cancelled):
        return True


class Response:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body


class WSGIOpener:
    """Exercise the real WSGI API without a listener or cluster."""

    def __init__(self, app) -> None:
        self.app = app
        self.cookie: str | None = None

    def __call__(self, request, timeout):
        parsed = urllib.parse.urlsplit(request.full_url)
        raw = request.data or b""
        environ = {
            "REQUEST_METHOD": request.method,
            "PATH_INFO": parsed.path,
            "CONTENT_LENGTH": str(len(raw)),
            "wsgi.input": io.BytesIO(raw),
        }
        if self.cookie:
            environ["HTTP_COOKIE"] = self.cookie
        response = {}

        def start_response(status, headers):
            response["status"] = status
            response["headers"] = dict(headers)

        body = b"".join(self.app(environ, start_response))
        if "Set-Cookie" in response["headers"]:
            self.cookie = response["headers"]["Set-Cookie"].split(";", 1)[0]
        status = int(response["status"].split()[0])
        if status >= 400:
            headers = Message()
            for name, value in response["headers"].items():
                headers[name] = value
            raise urllib.error.HTTPError(
                request.full_url, status, response["status"], headers, io.BytesIO(body)
            )
        return Response(body)


class CLIAPIParityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.operations = OperationStore(root / "operations.sqlite3")
        self.approvals = ApprovalStore(root / "approvals.sqlite3")
        self.authorization = AuthorizationService(self.approvals)
        self.adapter = Adapter()
        self.engine = OperationEngine(
            ComponentRegistry.load(),
            self.operations,
            self.adapter,
            Verifier(),
            authorization=self.authorization,
            state_provider=lambda targets: {target: "running" for target in targets},
        )
        api = WebOperationAPI(
            self.engine,
            self.operations,
            self.authorization,
            lambda targets: {target: "running" for target in targets},
        )
        app = DashboardApp(
            accounts={"operator": password_verifier("password", iterations=1)},
            operation_api=api,
        )
        self.client = OperationClient(
            "http://127.0.0.1:8080", opener=WSGIOpener(app)
        )
        self.client.login("operator", "password")

    def tearDown(self):
        self.assertTrue(
            self.engine.wait_for_idle(2),
            "background operation did not finish its final durable save",
        )
        self.operations.close()
        self.approvals.close()
        self.temp.cleanup()

    def completed(self, operation_id):
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            document = self.client.status(operation_id)
            if document["terminal"]:
                return document
            time.sleep(0.002)
        self.fail("operation did not complete")

    def test_cli_plan_submit_progress_and_health_are_the_http_contract(self):
        plan = self.client.plan("start", ["scancentral-sast"])
        self.assertEqual(plan["kind"], "LifecyclePlan")
        self.assertEqual(plan["components"], ["mysql", "ssc", "scancentral-sast"])
        submitted = self.client.submit("start", ["mysql"])
        result = self.completed(submitted["id"])
        self.assertEqual(result["actor"], "local-cli:operator")
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(result["completionHealth"], "verified")
        self.assertEqual(result["apiVersion"], "fortifylab.io/v1alpha1")
        self.assertNotIn("adapter", json.dumps(result).lower())

    def test_cli_uses_same_approval_and_dependency_rejection(self):
        with self.assertRaises(ClientError) as blocked:
            self.client.plan("stop", ["mysql"])
        self.assertEqual(blocked.exception.exit_status, EXIT_BLOCKED)
        self.assertEqual(blocked.exception.document["kind"], "Error")

        approval = self.client.request_approval(
            "uninstall", ["scancentral-dast-scanner"]
        )
        self.assertEqual(approval["apiVersion"], "fortifylab.io/v1alpha1")
        self.assertEqual(approval["kind"], "LifecycleApproval")
        with self.assertRaises(ClientError) as rejected:
            self.client.submit("uninstall", ["scancentral-dast-scanner"])
        self.assertEqual(rejected.exception.exit_status, EXIT_REJECTED)
        approved = self.client.approve(
            approval["id"], "AUTHORIZE HIGH-RISK OPERATION"
        )
        self.assertEqual(approved["source"], "local-cli")
        submitted = self.client.submit(
            "uninstall", ["scancentral-dast-scanner"], approval["id"]
        )
        self.assertEqual(self.completed(submitted["id"])["state"], "succeeded")

    def test_exit_statuses_distinguish_terminal_outcomes_and_wait_timeout(self):
        self.assertEqual(_result_exit({"state": "failed"}), EXIT_FAILED)
        self.assertEqual(_result_exit({"state": "cancelled"}), EXIT_CANCELLED)
        self.assertEqual(_result_exit({"state": "timed-out"}), EXIT_TIMED_OUT)

        self.adapter.mode = "timed-out"
        timed = self.completed(self.client.submit("start", ["mysql"])["id"])
        self.assertEqual(_result_exit(timed), EXIT_TIMED_OUT)

        self.adapter.mode = "blocked"
        active = self.client.submit("start", ["postgresql"])
        with self.assertRaises(ClientError) as waiting:
            self.client.wait(active["id"], timeout=0.001, interval=0.001)
        self.assertEqual(waiting.exception.exit_status, EXIT_TIMED_OUT)
        self.client.cancel(active["id"])
        self.assertEqual(self.completed(active["id"])["state"], "cancelled")
        self.adapter.mode = "success"

    def test_arbitrary_shell_and_secret_fields_are_rejected_and_redacted(self):
        opener = self.client._open
        unsafe = urllib.request.Request(
            "http://127.0.0.1:8080/api/v1alpha1/operations",
            data=json.dumps(
                {
                    "operation": "start",
                    "components": ["mysql"],
                    "command": "echo token",
                    "secret": "marker",
                }
            ).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as rejected:
            opener(unsafe, timeout=1)
        body = rejected.exception.read().decode()
        rejected.exception.close()
        self.assertNotIn("marker", body)
        self.assertNotIn("echo token", body)

        self.adapter.mode = "failed"
        failed = self.completed(self.client.submit("start", ["mysql"])["id"])
        self.assertEqual(failed["state"], "failed")
        self.assertNotIn("sensitive adapter detail", json.dumps(failed))


if __name__ == "__main__":
    unittest.main()
