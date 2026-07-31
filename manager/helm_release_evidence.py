"""Protected, sanitized Helm release snapshot boundary."""

from __future__ import annotations

import argparse
import grp
import json
import os
import re
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from manager.component_registry import ComponentRegistry


API_VERSION = "fortifylab.io/v1alpha1"
DEFAULT_PATH = Path("/var/lib/fortify-lab-manager/helm-release-snapshot.json")
MAX_BYTES = 65536
MAX_AGE_SECONDS = 300
SAFE = re.compile(r"^[A-Za-z0-9._:+-]{1,160}$")
STATUSES = frozenset(
    {
        "unknown",
        "deployed",
        "uninstalled",
        "superseded",
        "failed",
        "uninstalling",
        "pending-install",
        "pending-upgrade",
        "pending-rollback",
    }
)


class HelmEvidenceUnavailable(RuntimeError):
    """The protected snapshot is absent, stale, or invalid."""


class HelmEvidenceStale(HelmEvidenceUnavailable):
    """The protected snapshot is valid but outside its freshness window."""


class ProtectedHelmSnapshot:
    def __init__(
        self,
        path: Path = DEFAULT_PATH,
        *,
        expected_uid: int = 0,
        expected_gid: int | None = None,
        now=lambda: datetime.now(timezone.utc),
    ) -> None:
        self._path = path
        self._uid = expected_uid
        self._gid = os.getegid() if expected_gid is None else expected_gid
        self._now = now

    def document(self) -> dict:
        try:
            metadata = self._path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o640
                or metadata.st_uid != self._uid
                or metadata.st_gid != self._gid
                or metadata.st_size > MAX_BYTES
            ):
                raise HelmEvidenceUnavailable("Helm release evidence is unavailable")
            raw = self._path.read_bytes()
            if len(raw) > MAX_BYTES:
                raise HelmEvidenceUnavailable("Helm release evidence is unavailable")
            document = json.loads(raw)
            self._validate(document)
            observed = datetime.fromisoformat(document["observedAt"].replace("Z", "+00:00"))
            age = (self._now() - observed).total_seconds()
            if observed.tzinfo is None or age < -30 or age > MAX_AGE_SECONDS:
                raise HelmEvidenceStale("Helm release evidence is stale")
            return document
        except HelmEvidenceUnavailable:
            raise
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise HelmEvidenceUnavailable("Helm release evidence is unavailable") from error

    @staticmethod
    def _validate(document: object) -> None:
        if not isinstance(document, dict) or set(document) != {
            "apiVersion", "kind", "observedAt", "releases"
        }:
            raise HelmEvidenceUnavailable("Helm release evidence is unavailable")
        if document["apiVersion"] != API_VERSION or document["kind"] != "HelmReleaseSnapshot":
            raise HelmEvidenceUnavailable("Helm release evidence is unavailable")
        if not isinstance(document["observedAt"], str) or not isinstance(document["releases"], list) or len(document["releases"]) > 128:
            raise HelmEvidenceUnavailable("Helm release evidence is unavailable")
        seen: set[tuple[str, int]] = set()
        for item in document["releases"]:
            if not isinstance(item, dict) or set(item) != {
                "name", "revision", "status", "chartVersion", "appVersion"
            }:
                raise HelmEvidenceUnavailable("Helm release evidence is unavailable")
            if (
                not all(isinstance(item[key], str) and SAFE.fullmatch(item[key]) for key in ("name", "chartVersion", "appVersion"))
                or item["status"] not in STATUSES
                or isinstance(item["revision"], bool)
                or not isinstance(item["revision"], int)
                or not 1 <= item["revision"] <= 1_000_000
                or (item["name"], item["revision"]) in seen
            ):
                raise HelmEvidenceUnavailable("Helm release evidence is unavailable")
            seen.add((item["name"], item["revision"]))


def _chart_version(value: str) -> str | None:
    match = re.search(r"-(\d[0-9A-Za-z.+_-]*)$", value)
    return match.group(1) if match else None


def collect(path: Path, registry: ComponentRegistry) -> None:
    """Run fixed Helm history reads and atomically publish only safe fields."""
    releases = []
    for component_id in registry.component_ids:
        name = registry.component(component_id)["helmRelease"]
        try:
            result = subprocess.run(
                ["/snap/bin/microk8s", "helm3", "history", name, "-n", "fortify", "-o", "json", "--max", "20"],
                env={key: value for key, value in os.environ.items() if key != "HELM_DRIVER"},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise HelmEvidenceUnavailable("Helm release observation failed") from error
        if result.returncode != 0:
            if b"release: not found" in result.stderr.lower() and len(result.stderr) <= 4096:
                continue
            raise HelmEvidenceUnavailable("Helm release observation failed")
        if len(result.stdout) > MAX_BYTES or len(result.stderr) > 4096:
            raise HelmEvidenceUnavailable("Helm release observation is oversized")
        try:
            history = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise HelmEvidenceUnavailable("Helm release observation is invalid") from error
        if not isinstance(history, list) or len(history) > 20:
            raise HelmEvidenceUnavailable("Helm release observation is invalid")
        for item in history:
            chart = _chart_version(item.get("chart", "")) if isinstance(item, dict) else None
            record = {
                "name": name,
                "revision": item.get("revision") if isinstance(item, dict) else None,
                "status": item.get("status") if isinstance(item, dict) else None,
                "chartVersion": chart,
                "appVersion": item.get("app_version") if isinstance(item, dict) else None,
            }
            releases.append(record)
    document = {
        "apiVersion": API_VERSION,
        "kind": "HelmReleaseSnapshot",
        "observedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "releases": releases,
    }
    ProtectedHelmSnapshot._validate(document)
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    fd, candidate = tempfile.mkstemp(prefix=".helm-release-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, separators=(",", ":"), sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(candidate, 0o640)
        os.chown(candidate, 0, grp.getgrnam("fortify-manager").gr_gid)
        os.replace(candidate, path)
    finally:
        try:
            os.unlink(candidate)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_PATH)
    args = parser.parse_args()
    collect(args.output, ComponentRegistry.load())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
