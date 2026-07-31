"""Authenticated Web lifecycle API success, safety, and recovery contracts."""

from __future__ import annotations

import io
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from manager.authorization import ApprovalStore, AuthorizationService
from manager.component_registry import ComponentRegistry
from manager.dashboard import DashboardApp, password_verifier
from manager.operation_engine import OperationEngine, OperationStore, StepCancelled, StepTimedOut
from manager.web_operations import WebOperationAPI


class Adapter:
    def __init__(self) -> None:
        self.block = False
        self.timeout = False
        self.entered = threading.Event()

    def execute(self, step, *, deadline, cancelled):
        self.entered.set()
        if self.timeout:
            raise StepTimedOut()
        while self.block:
            if cancelled():
                raise StepCancelled()
            time.sleep(0.002)


class Verifier:
    def verify(self, component_id, check_id, *, deadline, cancelled):
        return True


def request(app, path, method="GET", body=None, cookie=None):
    raw = json.dumps(body).encode() if body is not None else b""
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(raw)),
        "wsgi.input": io.BytesIO(raw),
    }
    if cookie:
        environ["HTTP_COOKIE"] = cookie
    response = {}

    def start_response(status, headers):
        response["status"] = status
        response["headers"] = dict(headers)

    response["body"] = b"".join(app(environ, start_response))
    return response


class WebOperationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.operation_store = OperationStore(root / "operations.sqlite3")
        self.approval_store = ApprovalStore(root / "approvals.sqlite3")
        self.authorization = AuthorizationService(self.approval_store)
        self.adapter = Adapter()
        registry = ComponentRegistry.load()
        self.engine = OperationEngine(
            registry,
            self.operation_store,
            self.adapter,
            Verifier(),
            authorization=self.authorization,
            state_provider=lambda targets: {target: "running" for target in targets},
            preflight_provider=lambda: {"ready": True, "items": []},
            footprint_provider=lambda targets: {
                target: "absent" for target in targets
            },
        )
        operation_api = WebOperationAPI(
            self.engine,
            self.operation_store,
            self.authorization,
            lambda targets: {target: "running" for target in targets},
        )
        self.app = DashboardApp(
            accounts={"operator": password_verifier("password", iterations=1)},
            operation_api=operation_api,
        )
        login = request(
            self.app,
            "/api/v1alpha1/session",
            "POST",
            {"username": "operator", "password": "password"},
        )
        self.cookie = login["headers"]["Set-Cookie"].split(";", 1)[0]

    def tearDown(self):
        self.operation_store.close()
        self.approval_store.close()
        self.temp.cleanup()

    def post(self, path, body):
        return request(self.app, path, "POST", body, self.cookie)

    def completed(self, operation_id):
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            response = request(
                self.app,
                f"/api/v1alpha1/operations/{operation_id}",
                cookie=self.cookie,
            )
            document = json.loads(response["body"])
            if document["terminal"]:
                return document
            time.sleep(0.002)
        self.fail("operation did not reach a terminal state")

    def test_plan_exposes_typed_dependency_risk_and_deletion_boundaries(self):
        response = self.post(
            "/api/v1alpha1/operations/plans",
            {"operation": "start", "components": ["scancentral-sast"]},
        )
        self.assertEqual(response["status"], "200 OK")
        plan = json.loads(response["body"])
        self.assertEqual(plan["components"], ["mysql", "ssc", "scancentral-sast"])
        self.assertEqual(plan["dependencyImpact"], ["mysql", "ssc"])
        self.assertEqual(plan["risk"], "routine")
        self.assertFalse(plan["deletesData"])
        self.assertNotIn("adapter", json.dumps(plan))

        destructive = json.loads(
            self.post(
                "/api/v1alpha1/operations/plans",
                {"operation": "uninstall", "components": ["scancentral-dast-scanner"]},
            )["body"]
        )
        self.assertTrue(destructive["destructive"])
        self.assertFalse(destructive["deletesData"])
        self.assertTrue(destructive["approvalRequired"])

    def test_success_and_refresh_return_progress_health_and_sanitized_events(self):
        created = self.post(
            "/api/v1alpha1/operations",
            {"operation": "start", "components": ["mysql"]},
        )
        self.assertEqual(created["status"], "202 Accepted")
        document = json.loads(created["body"])
        detail = self.completed(document["id"])
        self.assertEqual(detail["state"], "succeeded")
        self.assertEqual(detail["completionHealth"], "verified")
        self.assertTrue(detail["terminal"])
        self.assertEqual(detail["events"][0]["type"], "step-succeeded")
        self.assertNotIn("adapter", json.dumps(detail).lower())

    def test_clean_install_plan_and_submit_share_durable_progress_contract(self):
        plan_response = self.post("/api/v1alpha1/clean-install/plan", {})
        self.assertEqual(plan_response["status"], "200 OK")
        plan = json.loads(plan_response["body"])
        self.assertEqual(plan["workflow"], "clean-install")
        self.assertTrue(plan["ready"])
        self.assertEqual(plan["existingComponents"], [])

        created = self.post("/api/v1alpha1/clean-install", {})
        self.assertEqual(created["status"], "202 Accepted")
        detail = self.completed(json.loads(created["body"])["id"])
        self.assertEqual(detail["workflow"], "clean-install")
        self.assertEqual(detail["profileId"], "fortify-24.4-eval.1")
        self.assertEqual(detail["state"], "succeeded")
        self.assertEqual(detail["completionHealth"], "verified")

    def test_blocked_pending_approval_and_high_risk_confirmation(self):
        blocked = self.post(
            "/api/v1alpha1/operations/plans",
            {"operation": "stop", "components": ["mysql"]},
        )
        self.assertEqual(blocked["status"], "400 Bad Request")
        self.assertEqual(json.loads(blocked["body"])["code"], "DEPENDENCY_BLOCKED")

        request_body = {
            "operation": "uninstall",
            "components": ["scancentral-dast-scanner"],
        }
        approval = json.loads(
            self.post("/api/v1alpha1/approvals", request_body)["body"]
        )
        self.assertEqual(approval["state"], "pending")
        missing = self.post("/api/v1alpha1/operations", request_body)
        self.assertEqual(missing["status"], "409 Conflict")
        self.assertEqual(json.loads(missing["body"])["code"], "AUTHORIZATION_DENIED")
        denied = self.post(
            f"/api/v1alpha1/approvals/{approval['id']}/approve",
            {"confirmation": "delete it"},
        )
        self.assertEqual(denied["status"], "409 Conflict")
        self.assertNotIn("delete it", denied["body"].decode())

    def test_timeout_cancellation_and_retry_recovery(self):
        self.adapter.timeout = True
        queued = json.loads(
            self.post(
                "/api/v1alpha1/operations",
                {"operation": "start", "components": ["mysql"]},
            )["body"]
        )
        timed_out = self.completed(queued["id"])
        self.assertEqual(timed_out["state"], "timed-out")
        self.adapter.timeout = False
        retry = json.loads(
            self.post(
                f"/api/v1alpha1/operations/{timed_out['id']}/retry", {}
            )["body"]
        )
        recovered = self.completed(retry["id"])
        self.assertEqual(recovered["state"], "succeeded")
        self.assertEqual(recovered["retryOf"], timed_out["id"])

        self.adapter.block = True
        running = json.loads(
            self.post(
                "/api/v1alpha1/operations",
                {"operation": "start", "components": ["postgresql"]},
            )["body"]
        )
        cancelled = json.loads(
            self.post(
                f"/api/v1alpha1/operations/{running['id']}/cancel", {}
            )["body"]
        )
        self.assertIn(cancelled["state"], {"cancelling", "cancelled"})
        self.adapter.block = False
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            state = self.operation_store.get(running["id"])["state"]
            if state == "cancelled":
                break
            time.sleep(0.005)
        self.assertEqual(self.operation_store.get(running["id"])["state"], "cancelled")

    def test_authentication_and_request_surface_fail_closed(self):
        denied = request(
            self.app,
            "/api/v1alpha1/operations/plans",
            "POST",
            {"operation": "start", "components": ["mysql"]},
        )
        self.assertEqual(denied["status"], "401 Unauthorized")
        unsafe = self.post(
            "/api/v1alpha1/operations/plans",
            {"operation": "start", "components": ["mysql"], "command": "anything"},
        )
        self.assertEqual(unsafe["status"], "400 Bad Request")


if __name__ == "__main__":
    unittest.main()
