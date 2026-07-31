"""Protected Unix-socket client for credential-bearing functional probes."""

from __future__ import annotations

import json
import os
import socket
import stat
import time
from datetime import datetime
from pathlib import Path

from manager.health import API_VERSION, CheckSpec, ProbeResult


class FunctionalProbeError(RuntimeError):
    """A functional probe failed without exposing its response."""


class UnixFunctionalHealthProbe:
    """Request one allow-listed check from a locally protected probe service.

    The service, rather than the Manager, owns database/application credentials.
    Only a small, versioned, sanitized result crosses the socket boundary.
    """

    _MAX_RESPONSE = 4096

    def __init__(self, socket_path: Path, *, expected_gid: int | None = None) -> None:
        self._path = socket_path
        self._expected_gid = os.getegid() if expected_gid is None else expected_gid

    def handshake(self, timeout_seconds: float = 1.0) -> bool:
        """Prove that a protected peer speaks the supported protocol."""
        response = self._exchange(
            {
                "apiVersion": API_VERSION,
                "kind": "FunctionalHealthProbeHandshake",
                "protocolVersion": "1.0",
            },
            timeout_seconds,
        )
        if response != {
            "apiVersion": API_VERSION,
            "kind": "FunctionalHealthProbeHandshakeResult",
            "protocolVersion": "1.0",
            "status": "ready",
        }:
            raise FunctionalProbeError("functional probe handshake is invalid")
        return True

    def probe(self, check: CheckSpec) -> ProbeResult:
        request = {
            "apiVersion": API_VERSION,
            "kind": "FunctionalHealthProbeRequest",
            "check": {
                "id": check.id,
                "subjectId": check.subject_id,
                "type": check.probe_type,
                "target": check.target,
                "timeoutMs": max(1, round(check.timeout_seconds * 1000)),
            },
        }
        started = time.monotonic()
        document = self._exchange(request, check.timeout_seconds)
        try:
            if (
                not isinstance(document, dict)
                or set(document) != {
                    "apiVersion", "kind", "state", "summary", "observedAt"
                }
                or document["apiVersion"] != API_VERSION
                or document["kind"] != "FunctionalHealthProbeResult"
                or not isinstance(document["summary"], str)
                or len(document["summary"]) > 160
            ):
                raise ValueError
            observed_at = datetime.fromisoformat(
                document["observedAt"].replace("Z", "+00:00")
            )
            return ProbeResult(
                document["state"],
                document["summary"],
                observed_at,
                max(0, round((time.monotonic() - started) * 1000)),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise FunctionalProbeError("functional probe response is invalid") from error

    def _exchange(self, request: dict, timeout_seconds: float) -> dict:
        try:
            metadata = self._path.stat()
        except OSError as error:
            raise FunctionalProbeError("functional probe is unavailable") from error
        mode = metadata.st_mode
        if (
            not stat.S_ISSOCK(mode)
            or stat.S_IMODE(mode) != 0o660
            or metadata.st_gid != self._expected_gid
        ):
            raise FunctionalProbeError("functional probe socket is not protected")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(timeout_seconds)
                connection.connect(str(self._path))
                connection.sendall(
                    json.dumps(request, separators=(",", ":")).encode() + b"\n"
                )
                response = b""
                while not response.endswith(b"\n"):
                    chunk = connection.recv(self._MAX_RESPONSE + 1 - len(response))
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > self._MAX_RESPONSE:
                        raise FunctionalProbeError("functional probe response is invalid")
        except (OSError, TimeoutError) as error:
            raise FunctionalProbeError("functional probe is unavailable") from error
        try:
            document = json.loads(response)
            if not isinstance(document, dict):
                raise ValueError
            return document
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise FunctionalProbeError("functional probe response is invalid") from error
