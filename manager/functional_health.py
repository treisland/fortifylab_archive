"""Protected Unix-socket client for credential-bearing functional probes."""

from __future__ import annotations

import json
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

    def __init__(self, socket_path: Path) -> None:
        self._path = socket_path

    def probe(self, check: CheckSpec) -> ProbeResult:
        mode = self._path.stat().st_mode
        if not stat.S_ISSOCK(mode) or mode & 0o007:
            raise FunctionalProbeError("functional probe socket is not protected")
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
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(check.timeout_seconds)
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
            if (
                not isinstance(document, dict)
                or set(document) != {
                    "apiVersion", "kind", "state", "summary", "observedAt"
                }
                or document["apiVersion"] != API_VERSION
                or document["kind"] != "FunctionalHealthProbeResult"
                or not isinstance(document["summary"], str)
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
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise FunctionalProbeError("functional probe response is invalid") from error
