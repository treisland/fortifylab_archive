"""Authenticated same-origin Web dashboard for the read-only manager API."""

from __future__ import annotations

import hashlib
import hmac
import json
import mimetypes
import secrets
import time
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from typing import Callable, Iterable, Mapping, Protocol

from manager.api import ManagerAPI
from manager.capabilities import CapabilityProvider


ASSET_ROOT = Path(__file__).with_name("web")
SESSION_PATH = "/api/v1alpha1/session"
READINESS_PATH = "/ready"
CAPABILITIES_PATH = "/api/v1alpha1/capabilities"
COOKIE_NAME = "fortifylab_session"
MAX_LOGIN_BODY = 4096


class AuthenticatedAPI(Protocol):
    def __call__(
        self, environ: dict, start_response: Callable, identity: "WebIdentity"
    ) -> Iterable[bytes]: ...


@dataclass(frozen=True)
class WebIdentity:
    username: str
    session_id: str
    authenticated_at: float
    source: str = "web"


def password_verifier(password: str, *, iterations: int = 210_000) -> str:
    """Create a portable PBKDF2 verifier for operator-side account bootstrap."""

    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2-sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, verifier: str) -> bool:
    try:
        algorithm, count, salt, expected = verifier.split("$", 3)
        if algorithm != "pbkdf2-sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), int(count)
        )
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


@dataclass
class _Session:
    username: str
    created: float
    accessed: float
    source: str


class SessionStore:
    """Small server-side session store with idle and absolute expiration."""

    def __init__(
        self,
        *,
        idle_seconds: int = 1800,
        absolute_seconds: int = 28_800,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._idle = idle_seconds
        self._absolute = absolute_seconds
        self._clock = clock
        self._sessions: dict[str, _Session] = {}

    def create(self, username: str, *, source: str = "web") -> str:
        if source not in {"web", "local-cli"}:
            raise ValueError("unsupported session source")
        token = secrets.token_urlsafe(32)
        now = self._clock()
        self._sessions[token] = _Session(username, now, now, source)
        return token

    def authenticated(self, token: str | None) -> bool:
        return self.identity(token) is not None

    def identity(self, token: str | None) -> WebIdentity | None:
        if not token or token not in self._sessions:
            return None
        now = self._clock()
        session = self._sessions[token]
        if now - session.accessed > self._idle or now - session.created > self._absolute:
            self._sessions.pop(token, None)
            return None
        session.accessed = now
        return WebIdentity(
            session.username, token, session.created, source=session.source
        )

    def delete(self, token: str | None) -> None:
        if token:
            self._sessions.pop(token, None)


class LoginLimiter:
    """Bound authentication attempts without retaining credentials or usernames."""

    def __init__(
        self, *, attempts: int = 5, window_seconds: int = 60,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limit = attempts
        self._window = window_seconds
        self._clock = clock
        self._attempts: dict[str, list[float]] = {}

    def allowed(self, client: str) -> bool:
        now = self._clock()
        recent = [stamp for stamp in self._attempts.get(client, []) if now - stamp < self._window]
        if len(recent) >= self._limit:
            self._attempts[client] = recent
            return False
        recent.append(now)
        self._attempts[client] = recent
        return True


class DashboardApp:
    """Fail-closed WSGI composition of static assets, sessions, and read API."""

    def __init__(
        self,
        *,
        accounts: Mapping[str, str],
        api: ManagerAPI | None = None,
        sessions: SessionStore | None = None,
        login_limiter: LoginLimiter | None = None,
        operation_api: AuthenticatedAPI | None = None,
        capability_provider: CapabilityProvider | None = None,
        secure_cookies: bool = False,
    ) -> None:
        self._accounts = dict(accounts)
        self._api = api or ManagerAPI()
        self._sessions = sessions or SessionStore()
        self._login_limiter = login_limiter or LoginLimiter()
        self._operation_api = operation_api
        self._capability_provider = capability_provider or CapabilityProvider()
        self._secure_cookies = secure_cookies

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "")
        if path == READINESS_PATH:
            return self._json(start_response, HTTPStatus.OK, {"state": "ready"}, method)
        if path == SESSION_PATH:
            return self._session(environ, start_response, method)
        if path.startswith("/api/"):
            identity = self._identity(environ)
            if identity is None:
                return self._json(
                    start_response,
                    HTTPStatus.UNAUTHORIZED,
                    {"code": "AUTHENTICATION_REQUIRED", "message": "authentication required"},
                    method,
                )
            if path == CAPABILITIES_PATH:
                if method not in {"GET", "HEAD"}:
                    return self._json(
                        start_response,
                        HTTPStatus.METHOD_NOT_ALLOWED,
                        {"code": "METHOD_NOT_ALLOWED", "message": "method not allowed"},
                        method,
                        (("Allow", "GET, HEAD"),),
                    )
                return self._json(
                    self._security_headers(start_response),
                    HTTPStatus.OK,
                    self._capability_provider.document(identity),
                    method,
                )
            if (
                path.startswith("/api/v1alpha1/operations")
                or path.startswith("/api/v1alpha1/approvals")
                or path.startswith("/api/v1alpha1/clean-install")
                or path.startswith("/api/v1alpha1/recovery")
                or path.startswith("/api/v1alpha1/profile-upgrades")
                or path.startswith("/api/v1alpha1/lab")
            ):
                if self._operation_api is None:
                    return self._json(
                        start_response,
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {
                            "code": "OPERATIONS_UNAVAILABLE",
                            "message": "lifecycle operations are not configured",
                        },
                        method,
                    )
                return self._operation_api(
                    environ, self._security_headers(start_response), identity
                )
            return self._api(environ, self._security_headers(start_response))
        if path.startswith("/assets/"):
            return self._asset(path, start_response, method)
        if path in {"/", "/index.html"}:
            if not self._authorized(environ):
                path = "/login.html"
            return self._asset(path, start_response, method)
        return self._json(
            start_response,
            HTTPStatus.NOT_FOUND,
            {"code": "NOT_FOUND", "message": "resource not found"},
            method,
        )

    def _session(self, environ: dict, start_response: Callable, method: str) -> Iterable[bytes]:
        if method == "POST":
            if not self._login_limiter.allowed(str(environ.get("REMOTE_ADDR", "local"))):
                return self._auth_failed(start_response)
            length = _content_length(environ)
            if length < 1 or length > MAX_LOGIN_BODY:
                return self._auth_failed(start_response)
            try:
                body = environ["wsgi.input"].read(length)
                document = json.loads(body)
                username = str(document.get("username", ""))
                password = str(document.get("password", ""))
                source = str(document.get("client", "web"))
                if source not in {"web", "local-cli"}:
                    raise ValueError
            except (KeyError, ValueError, TypeError, json.JSONDecodeError):
                return self._auth_failed(start_response)
            verifier = self._accounts.get(username, "")
            if not verifier or not verify_password(password, verifier):
                return self._auth_failed(start_response)
            token = self._sessions.create(username, source=source)
            flags = "; HttpOnly; SameSite=Strict; Path=/"
            if self._secure_cookies:
                flags += "; Secure"
            return self._json(
                start_response,
                HTTPStatus.NO_CONTENT,
                {},
                method,
                (("Set-Cookie", f"{COOKIE_NAME}={token}{flags}"),),
                empty=True,
            )
        if method == "DELETE":
            token = _cookie(environ, COOKIE_NAME)
            if not self._sessions.authenticated(token):
                return self._json(
                    start_response,
                    HTTPStatus.UNAUTHORIZED,
                    {"code": "AUTHENTICATION_REQUIRED", "message": "authentication required"},
                    method,
                )
            self._sessions.delete(token)
            flags = "; Max-Age=0; HttpOnly; SameSite=Strict; Path=/"
            if self._secure_cookies:
                flags += "; Secure"
            return self._json(
                start_response,
                HTTPStatus.NO_CONTENT,
                {},
                method,
                (("Set-Cookie", f"{COOKIE_NAME}={flags}"),),
                empty=True,
            )
        return self._json(
            start_response,
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"code": "METHOD_NOT_ALLOWED", "message": "method not allowed"},
            method,
            (("Allow", "POST, DELETE"),),
        )

    def _authorized(self, environ: dict) -> bool:
        return self._identity(environ) is not None

    def _identity(self, environ: dict) -> WebIdentity | None:
        return self._sessions.identity(_cookie(environ, COOKIE_NAME))

    def _auth_failed(self, start_response: Callable) -> Iterable[bytes]:
        # Deliberately identical for unknown users, bad passwords, and malformed bodies.
        return self._json(
            start_response,
            HTTPStatus.UNAUTHORIZED,
            {"code": "AUTHENTICATION_FAILED", "message": "sign-in failed"},
            "POST",
        )

    def _asset(self, path: str, start_response: Callable, method: str) -> Iterable[bytes]:
        if method not in {"GET", "HEAD"}:
            return self._json(
                start_response, HTTPStatus.METHOD_NOT_ALLOWED,
                {"code": "METHOD_NOT_ALLOWED", "message": "method not allowed"}, method,
                (("Allow", "GET, HEAD"),),
            )
        relative = "index.html" if path in {"/", "/index.html"} else path.lstrip("/")
        candidate = (ASSET_ROOT / relative).resolve()
        if ASSET_ROOT.resolve() not in candidate.parents or not candidate.is_file():
            return self._json(
                start_response, HTTPStatus.NOT_FOUND,
                {"code": "NOT_FOUND", "message": "resource not found"}, method,
            )
        body = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        headers = [
            ("Content-Type", f"{content_type}; charset=utf-8" if content_type.startswith("text/") or content_type == "application/javascript" else content_type),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            *_browser_headers(),
        ]
        start_response(f"200 OK", headers)
        return (b"",) if method == "HEAD" else (body,)

    def _security_headers(self, start_response: Callable) -> Callable:
        def wrapped(status: str, headers: list[tuple[str, str]]) -> None:
            start_response(status, [*headers, *_browser_headers()])
        return wrapped

    @staticmethod
    def _json(
        start_response: Callable,
        status: HTTPStatus,
        document: dict,
        method: str,
        extra: tuple[tuple[str, str], ...] = (),
        *,
        empty: bool = False,
    ) -> Iterable[bytes]:
        body = b"" if empty else json.dumps(document, separators=(",", ":")).encode()
        headers = [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            *extra,
            *_browser_headers(),
        ]
        start_response(f"{status.value} {status.phrase}", headers)
        return (b"",) if method == "HEAD" else (body,)


def _browser_headers() -> tuple[tuple[str, str], ...]:
    return (
        ("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    )


def _content_length(environ: dict) -> int:
    try:
        return int(environ.get("CONTENT_LENGTH", "0"))
    except ValueError:
        return 0


def _cookie(environ: dict, name: str) -> str | None:
    for item in environ.get("HTTP_COOKIE", "").split(";"):
        key, separator, value = item.strip().partition("=")
        if separator and key == name:
            return value
    return None
