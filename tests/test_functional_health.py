"""Contracts for the protected credential-bearing functional probe boundary."""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from manager.functional_health import FunctionalProbeError, UnixFunctionalHealthProbe
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


if __name__ == "__main__":
    unittest.main()
