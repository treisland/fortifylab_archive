"""Contracts for the protected credential-bearing functional probe boundary."""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from manager.functional_health import FunctionalProbeError, UnixFunctionalHealthProbe
from manager.functional_probe_service import (
    FUNCTIONAL_TYPES,
    FunctionalProbeService,
    ProbeRegistry,
    default_handlers,
)
from manager.component_registry import ComponentRegistry
from manager.health import CheckSpec


NOW = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)


def check(timeout: float = 0.2) -> CheckSpec:
    return CheckSpec(
        "database-query", "mysql", "application", "database-query",
        "mysql", timeout,
    )


class ProbeServer:
    def __init__(self, path: Path, response: dict | bytes):
        self.path = path
        self.response = (
            response if isinstance(response, bytes)
            else json.dumps(response, separators=(",", ":")).encode() + b"\n"
        )
        self.request = None
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(self.path))
            os.chmod(self.path, 0o660)
            server.listen(1)
            self.ready.set()
            connection, _ = server.accept()
            with connection:
                self.request = json.loads(connection.recv(4096))
                try:
                    connection.sendall(self.response)
                except BrokenPipeError:
                    pass

    def start(self):
        self.thread.start()
        self.ready.wait(1)
        return self


class UnixFunctionalHealthProbeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "health.sock"

    def tearDown(self):
        self.temporary.cleanup()

    def test_typed_request_and_sanitized_result(self):
        server = ProbeServer(
            self.path,
            {
                "apiVersion": "fortifylab.io/v1alpha1",
                "kind": "FunctionalHealthProbeResult",
                "state": "healthy",
                "summary": "Authenticated constant query succeeded",
                "observedAt": "2026-07-31T12:00:00Z",
            },
        ).start()
        result = UnixFunctionalHealthProbe(self.path).probe(check())
        server.thread.join(1)
        self.assertEqual(result.state, "healthy")
        self.assertEqual(result.observed_at, NOW)
        self.assertGreaterEqual(result.latency_ms, 0)
        self.assertEqual(
            server.request["check"],
            {
                "id": "database-query",
                "subjectId": "mysql",
                "type": "database-query",
                "target": "mysql",
                "timeoutMs": 200,
            },
        )
        self.assertNotIn("credential", json.dumps(server.request))

    def test_successful_versioned_handshake(self):
        server = ProbeServer(
            self.path,
            {
                "apiVersion": "fortifylab.io/v1alpha1",
                "kind": "FunctionalHealthProbeHandshakeResult",
                "protocolVersion": "1.0",
                "status": "ready",
            },
        ).start()
        self.assertTrue(UnixFunctionalHealthProbe(self.path).handshake())
        server.thread.join(1)

    def test_socket_with_unexpected_owner_is_rejected(self):
        server = ProbeServer(
            self.path,
            {
                "apiVersion": "fortifylab.io/v1alpha1",
                "kind": "FunctionalHealthProbeHandshakeResult",
                "protocolVersion": "1.0",
                "status": "ready",
            },
        ).start()
        with self.assertRaisesRegex(FunctionalProbeError, "not protected"):
            UnixFunctionalHealthProbe(
                self.path,
                expected_uid=os.geteuid() + 1,
            ).handshake()
        server.thread.join(1)

    def test_malformed_or_oversized_response_is_rejected_without_detail(self):
        for response in (b"not-json\n", b"x" * 4097):
            with self.subTest(size=len(response)):
                path = Path(self.temporary.name) / f"health-{len(response)}.sock"
                ProbeServer(path, response).start()
                with self.assertRaisesRegex(
                    FunctionalProbeError, "response is invalid"
                ) as caught:
                    UnixFunctionalHealthProbe(path).probe(check())
                self.assertNotIn("not-json", str(caught.exception))

    def test_world_accessible_socket_is_rejected(self):
        server = ProbeServer(self.path, b"{}\n").start()
        os.chmod(self.path, 0o666)
        with self.assertRaisesRegex(FunctionalProbeError, "not protected"):
            UnixFunctionalHealthProbe(self.path).probe(check())
        # Unblock the daemon so TemporaryDirectory cleanup is deterministic.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(self.path))
            connection.sendall(b"{}\n")
        server.thread.join(1)


class FunctionalProbeServiceTests(unittest.TestCase):
    def setUp(self):
        self.registry = ProbeRegistry(ComponentRegistry.load())

    @staticmethod
    def request(identity, timeout_ms=100):
        subject, check_id, probe_type, target = identity
        return {
            "apiVersion": "fortifylab.io/v1alpha1",
            "kind": "FunctionalHealthProbeRequest",
            "check": {
                "id": check_id,
                "subjectId": subject,
                "type": probe_type,
                "target": target,
                "timeoutMs": timeout_ms,
            },
        }

    def test_every_allowlisted_functional_category_is_dispatchable(self):
        handlers = {
            identity: (lambda _timeout: ("healthy", "PROBE_SUCCEEDED"))
            for identity in self.registry.identities
        }
        service = FunctionalProbeService(Path("/unused"), self.registry, handlers)
        seen = set()
        for identity in self.registry.identities:
            result = service.handle(json.dumps(self.request(identity)).encode())
            self.assertEqual(result["state"], "healthy", identity)
            seen.add(identity[2])
        self.assertEqual(seen, FUNCTIONAL_TYPES)

    def test_packaged_handlers_cover_every_identity_with_external_inputs(self):
        environment = {
            "FORTIFY_PROBE_DOMAIN": "fortify.example",
            "FORTIFY_PROBE_MANAGED_HOST": "lab.fortify.example",
            "MYSQL_PWD": "fixture-only",
            "MYSQL_USER": "probe",
            "MYSQL_HOST": "mysql.fortify.svc",
            "PGPASSWORD": "fixture-only",
            "PGUSER": "probe",
            "PGHOST": "postgresql.fortify.svc",
            "PGDATABASE": "probe",
        }
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(
                set(default_handlers(self.registry)),
                set(self.registry.identities),
            )

    def test_unknown_identity_and_malformed_requests_fail_closed(self):
        service = FunctionalProbeService(Path("/unused"), self.registry, {})
        unknown = ("mysql", "database-query", "database-query", "arbitrary")
        result = service.handle(json.dumps(self.request(unknown)).encode())
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["summary"], "PROBE_REQUEST_MALFORMED")
        malformed = service.handle(b'{"credential":"do-not-reflect"}')
        self.assertEqual(malformed["summary"], "PROBE_REQUEST_MALFORMED")
        self.assertNotIn("credential", json.dumps(malformed))

    def test_unconfigured_timeout_restart_and_recovery_paths(self):
        identity = next(iter(self.registry.identities))
        service = FunctionalProbeService(Path("/unused"), self.registry, {})
        unavailable = service.handle(json.dumps(self.request(identity)).encode())
        self.assertEqual(unavailable["state"], "misconfigured")
        service.handlers[identity] = lambda _timeout: (
            time.sleep(0.05) or ("healthy", "TOO_LATE")
        )
        timed_out = service.handle(
            json.dumps(self.request(identity, timeout_ms=5)).encode()
        )
        self.assertEqual(timed_out["summary"], "PROBE_TIMEOUT")
        with tempfile.TemporaryDirectory() as directory:
            completion = Path(directory) / "completed"

            def outlive_timeout(_timeout):
                time.sleep(0.1)
                completion.touch()
                return "healthy", "TOO_LATE"

            service.handlers[identity] = outlive_timeout
            timed_out = service.handle(
                json.dumps(self.request(identity, timeout_ms=5)).encode()
            )
            self.assertEqual(timed_out["summary"], "PROBE_TIMEOUT")
            time.sleep(0.15)
            self.assertFalse(completion.exists())
        service.handlers[identity] = lambda _timeout: ("healthy", "PROBE_RECOVERED")
        recovered = service.handle(json.dumps(self.request(identity)).encode())
        self.assertEqual(recovered["state"], "healthy")
        self.assertEqual(recovered["summary"], "PROBE_RECOVERED")


if __name__ == "__main__":
    unittest.main()
