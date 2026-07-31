"""Authentication, API contract, disclosure, and accessibility tests."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from manager.api import HISTORY_PATH, ManagerAPI
from manager.dashboard import DashboardApp, LoginLimiter, SessionStore, password_verifier
from manager.history import StoreHistoryReader
from manager.record_store import CONTRACT_ROOT, LoopRecordStore


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "manager" / "web"


class History:
    def recent(self, limit=20):
        return [
            {
                "id": "operation-1",
                "kind": "Operation",
                "state": "completed",
                "summary": "SSC observation completed",
                "subject": "SSC",
                "occurredAt": "2026-07-30T12:00:00Z",
            }
        ]


def request(app, path="/", method="GET", body=None, cookie=None):
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


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verifier = password_verifier("correct horse battery staple", iterations=1)

    def app(self, **options):
        return DashboardApp(
            accounts={"operator": self.verifier},
            api=ManagerAPI(history_reader=History()),
            **options,
        )

    def login(self, app):
        response = request(
            app,
            "/api/v1alpha1/session",
            "POST",
            {"username": "operator", "password": "correct horse battery staple"},
        )
        return response["headers"]["Set-Cookie"].split(";", 1)[0]

    def test_readiness_is_coarse_and_dashboard_and_api_require_session(self):
        app = self.app()
        readiness = request(app, "/ready")
        self.assertEqual(readiness["status"], "200 OK")
        self.assertEqual(json.loads(readiness["body"]), {"state": "ready"})
        login = request(app)
        self.assertIn(b"Sign in", login["body"])
        denied = request(app, HISTORY_PATH)
        self.assertEqual(denied["status"], "401 Unauthorized")
        self.assertNotIn(b"operation-1", denied["body"])

    def test_login_rotates_to_server_session_and_logout_invalidates_it(self):
        app = self.app(secure_cookies=True)
        cookie = self.login(app)
        header = request(
            app,
            "/api/v1alpha1/session",
            "POST",
            {"username": "operator", "password": "correct horse battery staple"},
        )["headers"]["Set-Cookie"]
        for flag in ("HttpOnly", "SameSite=Strict", "Secure"):
            self.assertIn(flag, header)
        allowed = request(app, HISTORY_PATH, cookie=cookie)
        self.assertEqual(allowed["status"], "200 OK")
        history = json.loads(allowed["body"])
        self.assertEqual(history["items"][0]["id"], "operation-1")
        schema = json.loads(
            (ROOT / "registry/schemas/operation-history.schema.json").read_text()
        )
        Draft202012Validator(schema).validate(history)
        self.assertNotIn("correct horse", allowed["body"].decode())
        self.assertEqual(
            request(app, "/api/v1alpha1/session", "DELETE", cookie=cookie)["status"],
            "204 No Content",
        )
        self.assertEqual(request(app, HISTORY_PATH, cookie=cookie)["status"], "401 Unauthorized")

    def test_authentication_failures_are_generic_and_methods_fail_closed(self):
        app = self.app()
        unknown = request(app, "/api/v1alpha1/session", "POST", {"username": "nobody", "password": "x"})
        bad = request(app, "/api/v1alpha1/session", "POST", {"username": "operator", "password": "x"})
        self.assertEqual(unknown["body"], bad["body"])
        self.assertNotIn(b"operator", bad["body"])
        self.assertEqual(request(app, "/api/v1alpha1/session", "PUT")["status"], "405 Method Not Allowed")
        cookie = self.login(app)
        self.assertEqual(request(app, HISTORY_PATH, "POST", cookie=cookie)["status"], "405 Method Not Allowed")
        self.assertEqual(request(app, "/", "POST")["status"], "405 Method Not Allowed")

    def test_login_is_rate_limited_without_retaining_usernames(self):
        limiter = LoginLimiter(attempts=2, window_seconds=60, clock=lambda: 1.0)
        app = self.app(login_limiter=limiter)
        for _ in range(2):
            self.assertEqual(
                request(app, "/api/v1alpha1/session", "POST", {"username": "nobody", "password": "x"})["status"],
                "401 Unauthorized",
            )
        limited = request(
            app, "/api/v1alpha1/session", "POST",
            {"username": "operator", "password": "correct horse battery staple"},
        )
        self.assertEqual(limited["status"], "401 Unauthorized")
        self.assertNotIn("operator", repr(limiter._attempts))

    def test_expired_session_is_rejected(self):
        now = [100.0]
        sessions = SessionStore(idle_seconds=10, absolute_seconds=20, clock=lambda: now[0])
        app = self.app(sessions=sessions)
        cookie = self.login(app)
        now[0] = 111.0
        self.assertEqual(request(app, HISTORY_PATH, cookie=cookie)["status"], "401 Unauthorized")

    def test_browser_security_headers_and_same_origin_policy_are_present(self):
        response = request(self.app(), "/assets/dashboard.js")
        self.assertEqual(response["status"], "200 OK")
        policy = response["headers"]["Content-Security-Policy"]
        self.assertIn("connect-src 'self'", policy)
        self.assertIn("frame-ancestors 'none'", policy)
        self.assertNotIn("Access-Control-Allow-Origin", response["headers"])

    def test_dashboard_has_landmarks_labels_and_every_health_state(self):
        html = (WEB / "index.html").read_text(encoding="utf-8")
        login = (WEB / "login.html").read_text(encoding="utf-8")
        css = (WEB / "assets/dashboard.css").read_text(encoding="utf-8")
        script = (WEB / "assets/dashboard.js").read_text(encoding="utf-8")
        for fragment in ('href="#main"', 'id="main"', 'role="alert"', '<th scope="col">'):
            self.assertIn(fragment, html)
        for fragment in (
            'id="operation-form"', 'id="operation-confirmation"',
            'aria-live="polite"', 'id="cancel-operation"', 'id="retry-operation"',
        ):
            self.assertIn(fragment, html)
        for field in ('for="username"', 'for="password"', 'role="alert"'):
            self.assertIn(field, login)
        for state in (
            "healthy", "starting", "degraded", "blocked", "misconfigured",
            "stopped", "unreachable", "unknown", "unhealthy", "stale",
        ):
            self.assertIn(state, css + script)
        self.assertNotIn("innerHTML", script)
        self.assertIn("sessionStorage", script)

    def test_loading_empty_failure_and_disconnected_states_are_explicit(self):
        sources = "".join(
            path.read_text(encoding="utf-8")
            for path in (WEB / "index.html", WEB / "assets/dashboard.js")
        )
        for marker in (
            "loading", "empty", "stale", "unavailable", "unauthorized", "error",
            "inventory-empty", "health-empty", "preflight-empty", "history-empty",
            "session-expired", "Disconnected",
        ):
            self.assertIn(marker, sources)

    def test_curated_availability_is_independent_and_links_are_hardened(self):
        sources = "".join(
            path.read_text(encoding="utf-8")
            for path in (WEB / "index.html", WEB / "assets/dashboard.js")
        )
        for marker in (
            "/api/v1alpha1/availability",
            "Open service",
            "independent from health",
            "Manager host",
            "tls-warning",
            "dns-mismatch",
            "not-configured",
            "noopener noreferrer",
        ):
            self.assertIn(marker, sources)

    def test_browser_partial_503_retains_successful_panels_and_sanitizes_errors(self):
        script = (WEB / "assets/dashboard.js").read_text(encoding="utf-8")
        self.assertIn("await Promise.all(requests)", script)
        self.assertIn("panel.render(payload)", script)
        self.assertIn("panelDocuments.has(name)", script)
        self.assertIn("panelDocuments.set(panel.name, payload)", script)
        self.assertIn('response.status === 503 ? "unavailable" : "error"', script)
        self.assertIn("errorCodePattern", script)
        self.assertNotIn("document.message", script)

    def test_populated_documents_execute_against_source_and_packaged_dashboard(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is unavailable; CI supplies it for DOM execution")
        harness = ROOT / "tests/browser/dashboard-populated.mjs"
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate"
            subprocess.run(
                [
                    "python3", "scripts/package-manager-runtime.py", "stage",
                    "--source", str(ROOT), "--target", str(candidate),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            source_asset = WEB / "assets/dashboard.js"
            packaged_asset = candidate / "manager/web/assets/dashboard.js"
            self.assertEqual(source_asset.read_bytes(), packaged_asset.read_bytes())
            for asset in (source_asset, packaged_asset):
                result = subprocess.run(
                    [node, str(harness), str(asset)],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    f"dashboard DOM execution failed for {asset}:\n{result.stderr}",
                )

    def test_api_payload_names_do_not_shadow_the_browser_document(self):
        script = (WEB / "assets/dashboard.js").read_text(encoding="utf-8")
        self.assertNotRegex(script, r"\b(?:const|let|var)\s+document\b")
        self.assertNotRegex(script, r"function\s+\w+\([^)]*\bdocument\b")
        self.assertIn('const link = document.createElement("a")', script)
        self.assertIn('const row = document.createElement("tr")', script)
        self.assertIn('const cell = document.createElement("td")', script)

    def test_browser_disconnected_adapter_empty_cluster_and_live_failures_are_actionable(self):
        sources = "".join(
            path.read_text(encoding="utf-8")
            for path in (WEB / "index.html", WEB / "assets/dashboard.js")
        )
        for marker in (
            "OBSERVER_DISCONNECTED",
            "Desired inventory is available; live observation is unavailable",
            "No managed components are registered",
            "Primary root causes",
            "Blocked consumers",
            "Do not broaden observer permissions",
            "node",
            "kubernetesVersion",
            "ageSeconds",
        ):
            self.assertIn(marker, sources)

    def test_browser_refresh_recovery_and_session_expiry_are_bounded(self):
        script = (WEB / "assets/dashboard.js").read_text(encoding="utf-8")
        html = (WEB / "index.html").read_text(encoding="utf-8")
        for marker in (
            "autoRefreshMilliseconds = 30000",
            "readDeadlineMilliseconds = 8000",
            "AbortController",
            'controller.abort("deadline")',
            "refreshInFlight",
            "refreshGeneration",
            "visibilitychange",
            "document.hidden",
            'controller.abort("hidden")',
            "scheduleAutoRefresh",
            "AUTHENTICATION_REQUIRED",
            "const operation = await readModel({",
        ):
            self.assertIn(marker, script)
        self.assertIn('id="auto-refresh"', html)
        self.assertIn('id="session-expired"', html)
        self.assertNotIn('window.location.assign("/")', script.split("async function readModel", 1)[1].split("async function mutate", 1)[0])

    def test_deploy_control_uses_deployment_readiness_contract(self):
        script = (WEB / "assets/dashboard.js").read_text(encoding="utf-8")
        self.assertIn('action === "deploy" ? "deployment" : action', script)
        failure_handler = script.split(
            "function markPanelFailure", 1
        )[1].split("function renderInventory", 1)[0]
        self.assertIn('if (name === "preflight")', failure_handler)
        self.assertIn("preflightReadiness = null", failure_handler)
        self.assertIn("preflightGeneratedAt = 0", failure_handler)
        self.assertIn("updateSelectedActionControls()", failure_handler)
        operations_reader = script.split(
            "function renderOperationsRead", 1
        )[1].split("function documentNode", 1)[0]
        self.assertIn("setOperationsAvailable(available", operations_reader)
        self.assertIn("updateSelectedActionControls()", operations_reader)

    def test_each_dashboard_panel_has_an_independent_live_state_region(self):
        html = (WEB / "index.html").read_text(encoding="utf-8")
        for panel in ("components", "health", "preflight", "history", "capabilities", "operations"):
            self.assertIn(f'id="{panel}-panel-state"', html)
        self.assertGreaterEqual(html.count('aria-live="polite"'), 7)

    def test_component_explorer_is_filterable_deep_linked_and_accessible(self):
        html = (WEB / "index.html").read_text(encoding="utf-8")
        css = (WEB / "assets/dashboard.css").read_text(encoding="utf-8")
        script = (WEB / "assets/dashboard.js").read_text(encoding="utf-8")
        for marker in (
            'id="component-search"',
            'id="health-filter"',
            'id="state-filter"',
            'id="updates-filter"',
            'id="operations-filter"',
            'role="search"',
            'id="component-inspector"',
            'aria-labelledby="inspector-title"',
            'aria-label="Close component inspector"',
        ):
            self.assertIn(marker, html)
        for marker in (
            'new URLSearchParams(window.location.search).get("component")',
            'url.searchParams.set("component", componentId)',
            'url.searchParams.delete("component")',
            'showModal()',
            'componentOpener.focus()',
            'button.setAttribute("aria-pressed"',
            "renderComponentCards",
            "refreshInspector",
            "blocked-consumer-highlight",
            "dependency-highlight",
        ):
            self.assertIn(marker, script)
        self.assertIn("@media (max-width:520px)", css)
        self.assertIn("width:100vw", css)
        self.assertIn("height:100dvh", css)
        self.assertIn("@media (prefers-reduced-motion:reduce)", css)

    def test_component_inspector_labels_desired_observed_and_safe_metadata(self):
        script = (WEB / "assets/dashboard.js").read_text(encoding="utf-8")
        for marker in (
            "Desired state",
            "Observed state",
            "Health and root cause",
            "Dependencies and consumers",
            "Workloads (desired / observed)",
            "Profile and versions (desired)",
            "Installed release (independent evidence)",
            "Workload-declared metadata and running versions",
            "not proof of an installed Helm release",
            "Ingress and storage (desired metadata)",
            "Supported operations",
            "Recent history",
            "Partially observed or unavailable",
            "Observed deployment:",
        ):
            self.assertIn(marker, script)
        for forbidden in ("kubernetesSecret", ".adapter", "environmentVariables", "helmValues", "manifest"):
            self.assertNotIn(forbidden, script)

    def test_panel_count_and_freshness_are_derived_from_panel_definitions(self):
        script = (WEB / "assets/dashboard.js").read_text(encoding="utf-8")
        html = (WEB / "index.html").read_text(encoding="utf-8")
        self.assertIn("${panels.length} panels settled", script)
        self.assertIn("${panels.length} panels refreshed", script)
        self.assertIn("Observed ${observed} · refreshed", script)
        self.assertNotIn("Loading five independent dashboard panels", html)

    def test_every_durable_record_kind_has_a_bounded_history_projection(self):
        examples = json.loads((CONTRACT_ROOT / "examples.json").read_text())
        schema = json.loads(
            (ROOT / "registry/schemas/operation-history.schema.json").read_text()
        )
        with tempfile.TemporaryDirectory() as directory:
            with LoopRecordStore(Path(directory) / "history.sqlite3") as store:
                for document in examples.values():
                    store.append(document)
                response = {
                    "apiVersion": "fortifylab.io/v1alpha1",
                    "kind": "OperationHistory",
                    "items": StoreHistoryReader(store).recent(),
                }
        Draft202012Validator(schema).validate(response)
        serialized = json.dumps(response)
        for forbidden in ("requestedBy", "planDigest", "entries", "checks", "provenance"):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
