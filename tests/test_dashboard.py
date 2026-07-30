"""Authentication, API contract, disclosure, and accessibility tests."""

from __future__ import annotations

import io
import json
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
        for field in ('for="username"', 'for="password"', 'role="alert"'):
            self.assertIn(field, login)
        for state in (
            "healthy", "starting", "degraded", "blocked", "misconfigured",
            "stopped", "unreachable", "unknown", "unhealthy", "stale",
        ):
            self.assertIn(state, css + script)
        self.assertNotIn("innerHTML", script)

    def test_loading_empty_failure_and_disconnected_states_are_explicit(self):
        sources = "".join(
            path.read_text(encoding="utf-8")
            for path in (WEB / "index.html", WEB / "assets/dashboard.js")
        )
        for marker in ("loading", "inventory-empty", "health-empty", "preflight-empty", "history-empty", "api-error", "Disconnected"):
            self.assertIn(marker, sources)

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
