"""Credential-owning, allowlisted functional-health Unix service."""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import re
import signal
import socket
import ssl
import struct
import subprocess
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from manager.component_registry import ComponentRegistry
from manager.functional_health import FunctionalProbeError, UnixFunctionalHealthProbe
from manager.health import API_VERSION, HEALTH_STATES

PROTOCOL_VERSION = "1.0"
MAX_MESSAGE = 4096
MAX_TIMEOUT_MS = 30_000
FUNCTIONAL_TYPES = frozenset({
    "dns-lookup", "ingress-ready", "tls-valid", "native-readiness",
    "database-query", "https", "application-ready",
    "dependency-connectivity", "configuration", "registration", "tcp",
})
HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
ROOT_CHECKS = {
    ("dns", "dns-resolution", "dns-lookup", "kubernetes.default"),
    ("ingress", "ingress-controller", "ingress-ready", "ingress"),
    ("tls", "managed-host-certificates", "tls-valid", "managed-hosts"),
}


class ProbeProtocolError(ValueError):
    pass


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ProbeRegistry:
    """Exact identities the peer may request; targets never become instructions."""

    def __init__(self, registry: ComponentRegistry) -> None:
        identities = set(ROOT_CHECKS)
        for subject in registry.component_ids:
            for check in registry.monitoring_checks(subject):
                if check["type"] in FUNCTIONAL_TYPES:
                    identities.add((subject, check["id"], check["type"], check["target"]))
        self.identities = frozenset(identities)

    def validate(self, request: dict) -> tuple[tuple[str, str, str, str], float]:
        if set(request) != {"apiVersion", "kind", "check"}:
            raise ProbeProtocolError
        if request["apiVersion"] != API_VERSION or request["kind"] != "FunctionalHealthProbeRequest":
            raise ProbeProtocolError
        check = request["check"]
        if not isinstance(check, dict) or set(check) != {"id", "subjectId", "type", "target", "timeoutMs"}:
            raise ProbeProtocolError
        identity = (check["subjectId"], check["id"], check["type"], check["target"])
        timeout = check["timeoutMs"]
        if identity not in self.identities or not isinstance(timeout, int) or isinstance(timeout, bool):
            raise ProbeProtocolError
        return identity, min(max(timeout, 1), MAX_TIMEOUT_MS) / 1000


class FunctionalProbeService:
    """One-request-per-connection server with injectable, fixed handlers."""

    def __init__(
        self,
        socket_path: Path,
        registry: ProbeRegistry,
        handlers: dict[tuple[str, str, str, str], Callable[[float], tuple[str, str]]],
    ) -> None:
        self.socket_path = socket_path
        self.registry = registry
        self.handlers = handlers
        self._stop = threading.Event()

    def handle(self, payload: bytes) -> dict:
        try:
            request = json.loads(payload)
            if request == {
                "apiVersion": API_VERSION,
                "kind": "FunctionalHealthProbeHandshake",
                "protocolVersion": PROTOCOL_VERSION,
            }:
                return {
                    "apiVersion": API_VERSION,
                    "kind": "FunctionalHealthProbeHandshakeResult",
                    "protocolVersion": PROTOCOL_VERSION,
                    "status": "ready",
                }
            identity, timeout = self.registry.validate(request)
            handler = self.handlers.get(identity)
            if handler is None:
                return self._result("misconfigured", "PROBE_EXTERNAL_INPUT_NOT_CONFIGURED")
            context = multiprocessing.get_context("fork")
            receiver, sender = context.Pipe(duplex=False)
            process = context.Process(
                target=_run_handler,
                args=(handler, timeout, sender),
                name="functional-probe-check",
            )
            process.start()
            sender.close()
            if not receiver.poll(timeout):
                process.terminate()
                process.join(1)
                if process.is_alive():
                    process.kill()
                    process.join()
                return self._result("unknown", "PROBE_TIMEOUT")
            outcome = receiver.recv()
            receiver.close()
            process.join()
            if outcome[0] == "timeout":
                return self._result("unknown", "PROBE_TIMEOUT")
            if outcome[0] == "unreachable":
                return self._result("unreachable", "PROBE_TARGET_UNREACHABLE")
            if outcome[0] != "ok":
                return self._result("unknown", "PROBE_FAILED_SAFELY")
            state, summary = outcome[1:]
            if state not in HEALTH_STATES - {"blocked", "stale"} or not isinstance(summary, str):
                raise ProbeProtocolError
            return self._result(state, summary[:160])
        except (json.JSONDecodeError, KeyError, TypeError, ProbeProtocolError):
            return self._result("unknown", "PROBE_REQUEST_MALFORMED")
        except TimeoutError:
            return self._result("unknown", "PROBE_TIMEOUT")
        except (OSError, ssl.SSLError, urllib.error.URLError):
            return self._result("unreachable", "PROBE_TARGET_UNREACHABLE")
        except Exception:
            return self._result("unknown", "PROBE_FAILED_SAFELY")

    @staticmethod
    def _result(state: str, summary: str) -> dict:
        return {
            "apiVersion": API_VERSION,
            "kind": "FunctionalHealthProbeResult",
            "state": state,
            "summary": summary,
            "observedAt": _timestamp(),
        }

    def serve_forever(self) -> None:
        self.socket_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        try:
            self.socket_path.unlink(missing_ok=True)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(self.socket_path))
                os.chmod(self.socket_path, 0o660)
                server.listen(16)
                server.settimeout(0.5)
                while not self._stop.is_set():
                    try:
                        connection, _ = server.accept()
                    except socket.timeout:
                        continue
                    with connection:
                        connection.settimeout(2)
                        payload = b""
                        while not payload.endswith(b"\n") and len(payload) <= MAX_MESSAGE:
                            chunk = connection.recv(MAX_MESSAGE + 1 - len(payload))
                            if not chunk:
                                break
                            payload += chunk
                        response = self.handle(payload)
                        connection.sendall(json.dumps(response, separators=(",", ":")).encode() + b"\n")
        finally:
            self.socket_path.unlink(missing_ok=True)

    def stop(self, *_args: object) -> None:
        self._stop.set()


def _run_handler(handler: Callable, timeout: float, sender) -> None:
    """Return only typed, sanitized outcomes across the process boundary."""
    try:
        state, summary = handler(timeout)
        sender.send(("ok", state, summary))
    except TimeoutError:
        sender.send(("timeout",))
    except (OSError, ssl.SSLError, urllib.error.URLError):
        sender.send(("unreachable",))
    except Exception:
        sender.send(("failed",))
    finally:
        sender.close()


def default_handlers(registry: ProbeRegistry) -> dict:
    """Build fixed implementations; external values can only supply credentials."""
    handlers: dict = {}
    dns_identity = ("dns", "dns-resolution", "dns-lookup", "kubernetes.default")
    if dns_identity in registry.identities:
        def dns(timeout: float) -> tuple[str, str]:
            server = os.environ.get("FORTIFY_PROBE_DNS_SERVER", "10.152.183.10")
            socket.inet_pton(socket.AF_INET, server)
            transaction = os.getpid() & 0xFFFF
            question = b"".join(
                bytes((len(label),)) + label.encode("ascii")
                for label in "kubernetes.default.svc.cluster.local".split(".")
            ) + b"\0" + struct.pack("!HH", 1, 1)
            packet = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + question
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(timeout)
                client.sendto(packet, (server, 53))
                response, _ = client.recvfrom(512)
            if len(response) < 12:
                raise OSError
            response_id, flags, _questions, answers, _authority, _additional = struct.unpack(
                "!HHHHHH", response[:12]
            )
            if response_id != transaction or flags & 0xF or answers < 1:
                raise OSError
            return "healthy", "DNS_RESOLUTION_SUCCEEDED"
        handlers[dns_identity] = dns
    domain = os.environ.get("FORTIFY_PROBE_DOMAIN", "")
    fixed_hosts = {
        "ssc": ("ssc", 443),
        "scancentral-sast": ("scancentral", 443),
        "lim": ("lim", 443),
        "scancentral-dast-core": ("dast", 443),
    }

    def tcp_handler(host: str, port: int, *, qualified: bool = False):
        def run(timeout: float) -> tuple[str, str]:
            destination = host if qualified else f"{host}.{domain}"
            with socket.create_connection((destination, port), timeout):
                return "healthy", "TCP_CONNECTION_SUCCEEDED"
        return run

    def https_handler(host: str, path: str = "/", *, qualified: bool = False):
        def run(timeout: float) -> tuple[str, str]:
            destination = host if qualified else f"{host}.{domain}"
            request = urllib.request.Request(
                f"https://{destination}{path}", method="HEAD",
                headers={"Authorization": f"Bearer {os.environ.get('FORTIFY_PROBE_TOKEN', '')}"},
            )
            try:
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    status = response.status
            except urllib.error.HTTPError as error:
                status = error.code
                error.close()
            return (
                ("healthy", "HTTPS_APPLICATION_RESPONDED")
                if status < 500 else ("unhealthy", "HTTPS_APPLICATION_FAILED")
            )
        return run

    def command_handler(argv: tuple[str, ...], required_env: tuple[str, ...]):
        def run(timeout: float) -> tuple[str, str]:
            if any(not os.environ.get(name) for name in required_env):
                return "misconfigured", "PROBE_EXTERNAL_INPUT_NOT_CONFIGURED"
            try:
                result = subprocess.run(
                    argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=timeout, check=False,
                    env={name: os.environ[name] for name in required_env},
                )
            except FileNotFoundError:
                return "misconfigured", "PROBE_CLIENT_UNAVAILABLE"
            return (
                ("healthy", "AUTHENTICATED_PROBE_SUCCEEDED")
                if result.returncode == 0 else ("unhealthy", "AUTHENTICATED_PROBE_FAILED")
            )
        return run

    for identity in registry.identities:
        subject, _check_id, probe_type, target = identity
        if identity in handlers:
            continue
        if probe_type == "ingress-ready":
            host = os.environ.get("FORTIFY_PROBE_MANAGED_HOST")
            if host and HOSTNAME.fullmatch(host):
                handlers[identity] = tcp_handler(host, 443, qualified=True)
        elif probe_type == "tls-valid":
            host = os.environ.get("FORTIFY_PROBE_MANAGED_HOST")
            if host and HOSTNAME.fullmatch(host):
                handlers[identity] = https_handler(host, qualified=True)
        elif probe_type == "tcp" and target == "scanner:8080":
            handlers[identity] = tcp_handler("scancentral-dast-scanner.fortify.svc", 8080, qualified=True)
        elif probe_type in {
            "https", "application-ready", "dependency-connectivity",
            "configuration", "registration",
        }:
            destination = target
            if target in {"ssc-initialization", "expected-sast-workers"}:
                destination = "ssc" if target == "ssc-initialization" else "scancentral-sast"
            elif target in {"default-dast-pool"}:
                destination = "lim"
            elif target in {"expected-dast-scanners"}:
                destination = "scancentral-dast-core"
            if destination in fixed_hosts and HOSTNAME.fullmatch(domain):
                handlers[identity] = https_handler(fixed_hosts[destination][0])
        elif probe_type == "native-readiness" and target == "mysql":
            handlers[identity] = command_handler(
                ("/usr/bin/mysqladmin", "--protocol=TCP", "ping", "--silent"),
                ("MYSQL_PWD", "MYSQL_USER", "MYSQL_HOST"),
            )
        elif probe_type == "database-query" and target == "mysql":
            handlers[identity] = command_handler(
                ("/usr/bin/mysql", "--protocol=TCP", "--batch", "--skip-column-names", "-e", "SELECT 1"),
                ("MYSQL_PWD", "MYSQL_USER", "MYSQL_HOST"),
            )
        elif probe_type == "native-readiness" and target == "postgresql":
            handlers[identity] = command_handler(
                ("/usr/bin/pg_isready", "--quiet"),
                ("PGPASSWORD", "PGUSER", "PGHOST"),
            )
        elif probe_type == "database-query" and target in {"postgresql", "dast-schema"}:
            handlers[identity] = command_handler(
                ("/usr/bin/psql", "--no-psqlrc", "--tuples-only", "--command", "SELECT 1"),
                ("PGPASSWORD", "PGUSER", "PGHOST", "PGDATABASE"),
            )
    return handlers


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("serve", "check", "ping"))
    parser.add_argument("--socket", type=Path, default=Path("/run/fortify-lab-manager/health-probe.sock"))
    args = parser.parse_args()
    registry = ProbeRegistry(ComponentRegistry.load())
    if args.command == "check":
        return 0
    if args.command == "ping":
        try:
            UnixFunctionalHealthProbe(args.socket).handshake()
        except FunctionalProbeError:
            return 1
        return 0
    service = FunctionalProbeService(args.socket, registry, default_handlers(registry))
    signal.signal(signal.SIGTERM, service.stop)
    signal.signal(signal.SIGINT, service.stop)
    service.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
