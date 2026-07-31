"""Secret-safe CLI client for the authenticated typed operation API."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from typing import Any, Callable


API_VERSION = "fortifylab.io/v1alpha1"
EXIT_REJECTED = 20
EXIT_BLOCKED = 21
EXIT_FAILED = 22
EXIT_CANCELLED = 23
EXIT_TIMED_OUT = 24
EXIT_UNAVAILABLE = 25
TERMINAL = frozenset(
    {"succeeded", "failed", "cancelled", "timed-out", "interrupted"}
)


class ClientError(RuntimeError):
    """A bounded API/client failure carrying only a safe response document."""

    def __init__(self, document: dict[str, Any], exit_status: int) -> None:
        super().__init__(str(document.get("message", "request failed")))
        self.document = document
        self.exit_status = exit_status


class OperationClient:
    """Call only the allow-listed lifecycle HTTP resources."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.query
            or parsed.fragment
            or (parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"})
        ):
            raise ValueError("manager URL must use HTTPS or loopback HTTP")
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        if opener is None:
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(CookieJar())
            ).open
        self._open = opener

    def login(self, username: str, password: str) -> None:
        self._request(
            "POST",
            "/api/v1alpha1/session",
            {"username": username, "password": password, "client": "local-cli"},
            empty=True,
        )

    def plan(self, operation: str, components: list[str]) -> dict[str, Any]:
        return self._request(
            "POST", "/api/v1alpha1/operations/plans",
            {"operation": operation, "components": components},
        )

    def request_approval(
        self, operation: str, components: list[str]
    ) -> dict[str, Any]:
        return self._request(
            "POST", "/api/v1alpha1/approvals",
            {"operation": operation, "components": components},
        )

    def approve(
        self, approval_id: str, confirmation: str | None = None
    ) -> dict[str, Any]:
        return self._request(
            "POST", f"/api/v1alpha1/approvals/{approval_id}/approve",
            {"confirmation": confirmation},
        )

    def submit(
        self, operation: str, components: list[str], approval_id: str | None = None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"operation": operation, "components": components}
        if approval_id:
            body["approvalId"] = approval_id
        return self._request("POST", "/api/v1alpha1/operations", body)

    def status(self, operation_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1alpha1/operations/{operation_id}")

    def profile(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1alpha1/platform-profile")

    def clean_install_plan(self) -> dict[str, Any]:
        return self._request("POST", "/api/v1alpha1/clean-install/plan", {})

    def clean_install(self) -> dict[str, Any]:
        return self._request("POST", "/api/v1alpha1/clean-install", {})

    def cancel(self, operation_id: str) -> dict[str, Any]:
        return self._request(
            "POST", f"/api/v1alpha1/operations/{operation_id}/cancel", {}
        )

    def retry(
        self, operation_id: str, approval_id: str | None = None
    ) -> dict[str, Any]:
        body = {"approvalId": approval_id} if approval_id else {}
        return self._request(
            "POST", f"/api/v1alpha1/operations/{operation_id}/retry", body
        )

    def backup_plan(self) -> dict[str, Any]:
        return self._request("POST", "/api/v1alpha1/recovery/backup/plan", {})

    def backup(self) -> dict[str, Any]:
        return self._request("POST", "/api/v1alpha1/recovery/backups", {})

    def restore_plan(self, backup_id: str) -> dict[str, Any]:
        return self._request(
            "POST", "/api/v1alpha1/recovery/restore/plan",
            {"backupId": backup_id},
        )

    def restore(self, backup_id: str, confirmation: str) -> dict[str, Any]:
        return self._request(
            "POST", "/api/v1alpha1/recovery/restores",
            {"backupId": backup_id, "confirmation": confirmation},
        )

    def recovery_status(self, operation_id: str) -> dict[str, Any]:
        return self._request(
            "GET", f"/api/v1alpha1/recovery/operations/{operation_id}"
        )

    def wait(
        self, operation_id: str, *, timeout: float, interval: float = 1
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            document = self.status(operation_id)
            if document.get("state") in TERMINAL:
                return document
            if time.monotonic() >= deadline:
                raise ClientError(
                    _error("CLIENT_WAIT_TIMEOUT", "operation is still running"),
                    EXIT_TIMED_OUT,
                )
            time.sleep(min(interval, max(0, deadline - time.monotonic())))

    def _request(
        self, method: str, path: str, document: dict[str, Any] | None = None,
        *, empty: bool = False,
    ) -> dict[str, Any]:
        data = None if document is None else json.dumps(
            document, separators=(",", ":")
        ).encode()
        request = urllib.request.Request(
            self._base + path,
            data=data,
            method=method,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        try:
            response = self._open(request, timeout=self._timeout)
            payload = response.read()
        except urllib.error.HTTPError as error:
            try:
                payload = error.read()
            finally:
                error.close()
            response_document = _decode(payload)
            raise ClientError(
                response_document, _error_exit(response_document)
            ) from None
        except (OSError, TimeoutError, urllib.error.URLError):
            raise ClientError(
                _error("MANAGER_UNAVAILABLE", "manager API is unavailable"),
                EXIT_UNAVAILABLE,
            ) from None
        if empty and not payload:
            return {"apiVersion": API_VERSION, "kind": "Session", "state": "authenticated"}
        return _decode(payload)


def _decode(payload: bytes) -> dict[str, Any]:
    try:
        document = json.loads(payload)
        if not isinstance(document, dict):
            raise ValueError
        return document
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        raise ClientError(
            _error("INVALID_RESPONSE", "manager returned an invalid response"),
            EXIT_UNAVAILABLE,
        ) from None


def _error(code: str, message: str) -> dict[str, str]:
    return {
        "apiVersion": API_VERSION,
        "kind": "Error",
        "code": code,
        "message": message,
    }


def _error_exit(document: dict[str, Any]) -> int:
    code = document.get("code")
    if code == "DEPENDENCY_BLOCKED":
        return EXIT_BLOCKED
    if code in {"OPERATION_TIMEOUT", "CLIENT_WAIT_TIMEOUT"}:
        return EXIT_TIMED_OUT
    if code == "OPERATION_CANCELLED":
        return EXIT_CANCELLED
    if code == "OPERATION_FAILED":
        return EXIT_FAILED
    return EXIT_REJECTED


def _result_exit(document: dict[str, Any]) -> int:
    return {
        "succeeded": 0,
        "failed": EXIT_FAILED,
        "interrupted": EXIT_FAILED,
        "cancelled": EXIT_CANCELLED,
        "timed-out": EXIT_TIMED_OUT,
    }.get(str(document.get("state")), 0)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fortify-manager-cli",
        description="Invoke typed Fortify Lab Manager operations",
    )
    parser.add_argument("--url", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument(
        "--password-stdin", action="store_true",
        help="read one password line from standard input",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("profile", help="show the selected tested platform profile")
    clean_plan = subparsers.add_parser(
        "clean-install-plan", help="run read-only clean-install gates"
    )
    clean = subparsers.add_parser(
        "clean-install", help="install the complete selected platform profile"
    )
    clean.add_argument("--wait", type=float, metavar="SECONDS")
    for name in ("plan", "submit", "approval-request"):
        command = subparsers.add_parser(name)
        command.add_argument("operation")
        command.add_argument("components", nargs="+")
        if name == "submit":
            command.add_argument("--approval-id")
            command.add_argument(
                "--request-approval", action="store_true",
                help="request and approve the exact plan in this session",
            )
            command.add_argument("--confirm-high-risk", action="store_true")
            command.add_argument("--wait", type=float, metavar="SECONDS")
    approve = subparsers.add_parser("approve")
    approve.add_argument("approval_id")
    approve.add_argument("--confirm-high-risk", action="store_true")
    for name in ("status", "cancel"):
        command = subparsers.add_parser(name)
        command.add_argument("operation_id")
        if name == "status":
            command.add_argument("--wait", type=float, metavar="SECONDS")
    retry = subparsers.add_parser("retry")
    retry.add_argument("operation_id")
    retry.add_argument("--approval-id")
    retry.add_argument("--wait", type=float, metavar="SECONDS")
    subparsers.add_parser("backup-plan", help="show protected platform backup scope")
    backup = subparsers.add_parser("backup", help="create a verified platform backup")
    backup.add_argument("--wait", type=float, metavar="SECONDS")
    restore_plan = subparsers.add_parser(
        "restore-plan", help="check artifact and profile compatibility"
    )
    restore_plan.add_argument("backup_id")
    restore = subparsers.add_parser(
        "restore", help="restore a complete profile-compatible platform backup"
    )
    restore.add_argument("backup_id")
    restore.add_argument(
        "--confirm-restore", action="store_true",
        help="send the exact destructive restore confirmation",
    )
    restore.add_argument("--wait", type=float, metavar="SECONDS")
    recovery_status = subparsers.add_parser("recovery-status")
    recovery_status.add_argument("operation_id")
    return parser


def _wait_recovery(
    client: OperationClient, operation_id: str, timeout: float
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        document = client.recovery_status(operation_id)
        if document.get("state") in TERMINAL:
            return document
        if time.monotonic() >= deadline:
            raise ClientError(
                _error("CLIENT_WAIT_TIMEOUT", "recovery operation is still running"),
                EXIT_TIMED_OUT,
            )
        time.sleep(min(1, max(0, deadline - time.monotonic())))


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    password = (
        sys.stdin.readline().rstrip("\n")
        if args.password_stdin
        else getpass.getpass("Manager password: ")
    )
    try:
        client = OperationClient(args.url)
        client.login(args.username, password)
        password = ""
        if args.command == "profile":
            result = client.profile()
        elif args.command == "clean-install-plan":
            result = client.clean_install_plan()
        elif args.command == "clean-install":
            result = client.clean_install()
            if args.wait is not None:
                result = client.wait(result["id"], timeout=args.wait)
        elif args.command == "plan":
            result = client.plan(args.operation, args.components)
        elif args.command == "approval-request":
            result = client.request_approval(args.operation, args.components)
        elif args.command == "approve":
            confirmation = (
                "AUTHORIZE HIGH-RISK OPERATION" if args.confirm_high_risk else None
            )
            result = client.approve(args.approval_id, confirmation)
        elif args.command == "submit":
            approval_id = args.approval_id
            if args.request_approval:
                if approval_id:
                    raise ValueError(
                        "--approval-id and --request-approval are mutually exclusive"
                    )
                approval = client.request_approval(
                    args.operation, args.components
                )
                confirmation = (
                    "AUTHORIZE HIGH-RISK OPERATION"
                    if args.confirm_high_risk else None
                )
                client.approve(approval["id"], confirmation)
                approval_id = approval["id"]
            result = client.submit(
                args.operation, args.components, approval_id
            )
            if args.wait is not None:
                result = client.wait(result["id"], timeout=args.wait)
        elif args.command == "status":
            result = client.status(args.operation_id)
            if args.wait is not None:
                result = client.wait(args.operation_id, timeout=args.wait)
        elif args.command == "cancel":
            result = client.cancel(args.operation_id)
        elif args.command == "backup-plan":
            result = client.backup_plan()
        elif args.command == "backup":
            result = client.backup()
            if args.wait is not None:
                result = _wait_recovery(client, result["id"], args.wait)
        elif args.command == "restore-plan":
            result = client.restore_plan(args.backup_id)
        elif args.command == "restore":
            if not args.confirm_restore:
                raise ValueError("restore requires --confirm-restore")
            result = client.restore(
                args.backup_id, "RESTORE VERIFIED PLATFORM BACKUP"
            )
            if args.wait is not None:
                result = _wait_recovery(client, result["id"], args.wait)
        elif args.command == "recovery-status":
            result = client.recovery_status(args.operation_id)
        else:
            result = client.retry(args.operation_id, args.approval_id)
            if args.wait is not None:
                result = client.wait(result["id"], timeout=args.wait)
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return _result_exit(result)
    except (ClientError, ValueError) as error:
        document = (
            error.document
            if isinstance(error, ClientError)
            else _error("INVALID_CLIENT_CONFIGURATION", str(error))
        )
        print(json.dumps(document, separators=(",", ":"), sort_keys=True))
        return error.exit_status if isinstance(error, ClientError) else EXIT_REJECTED
    finally:
        password = ""


if __name__ == "__main__":
    raise SystemExit(main())
