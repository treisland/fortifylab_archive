"""Protected, sanitized host-discovery evidence for deployment preflight."""

from __future__ import annotations

import json
import os
import argparse
import grp
import platform
import pwd
import re
import shutil
import socket
import ssl
import stat
import subprocess
from pathlib import Path
from typing import Any, Callable
from datetime import datetime, timezone, timedelta

from manager.component_registry import ComponentRegistry
from manager.preflight import PreflightCheck, PreflightResult


API_VERSION = "fortifylab.io/v1alpha1"
EVIDENCE_KIND = "HostPreflightEvidence"
CHECK_IDS = frozenset({
    "host-capacity", "microk8s", "microk8s-addons", "storage", "ingress",
    "dns", "tls", "external-license", "registry-authentication",
    "image-reachability", "configuration", "compatibility",
})
SAFE_FACTS = frozenset({
    "cpuCores", "memoryGiB", "storageGiB", "remainingCpuCores",
    "remainingMemoryGiB", "remainingStorageGiB", "osFamily", "osVersion",
    "kernel", "architecture", "microk8sVersion", "ec2",
})
SAFE_VALUE = re.compile(r"^[A-Za-z0-9._+-]{1,80}$")


class HostPreflightEvidence:
    """Read a root-produced document without exposing its collection inputs."""

    def __init__(self, path: Path, *, expected_uid: int | None = None,
                 expected_gid: int | None = None) -> None:
        self._path = path
        self._expected_uid = pwd.getpwnam("root").pw_uid if expected_uid is None else expected_uid
        self._expected_gid = grp.getgrnam("fortify-manager").gr_gid if expected_gid is None else expected_gid

    def document(self) -> dict[str, Any]:
        metadata = self._path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o640
            or metadata.st_uid != self._expected_uid
            or metadata.st_gid != self._expected_gid
            or metadata.st_size > 8192
        ):
            raise ValueError("host preflight evidence is not protected")
        document = json.loads(self._path.read_text(encoding="utf-8"))
        if set(document) != {"apiVersion", "kind", "generatedAt", "checks", "facts"}:
            raise ValueError("host preflight evidence is malformed")
        if document["apiVersion"] != API_VERSION or document["kind"] != EVIDENCE_KIND:
            raise ValueError("host preflight evidence is unsupported")
        try:
            generated = datetime.fromisoformat(
                document["generatedAt"].replace("Z", "+00:00")
            )
        except (AttributeError, ValueError):
            raise ValueError("host preflight evidence is malformed") from None
        now = datetime.now(timezone.utc)
        if (
            generated.tzinfo is None
            or generated > now + timedelta(minutes=1)
            or now - generated > timedelta(minutes=15)
        ):
            raise ValueError("host preflight evidence is stale")
        checks = document["checks"]
        facts = document["facts"]
        if (
            not isinstance(checks, dict) or set(checks) != CHECK_IDS
            or any(value not in {"pass", "warning", "fail"} for value in checks.values())
            or not isinstance(facts, dict) or not set(facts) <= SAFE_FACTS
            or any(not _safe_fact(value) for value in facts.values())
        ):
            raise ValueError("host preflight evidence is malformed")
        return document


class HostPreflightProbe:
    """Serve only allow-listed states and facts from protected evidence."""

    def __init__(self, evidence: HostPreflightEvidence) -> None:
        self._evidence = evidence

    def probe(self, check: PreflightCheck) -> PreflightResult:
        if check.id not in CHECK_IDS:
            raise ValueError("preflight check is outside the host allow-list")
        document = self._evidence.document()
        facts = document["facts"] if check.id == "host-capacity" else {}
        return PreflightResult(document["checks"][check.id], facts)


def collect(registry: ComponentRegistry, *, environ: dict[str, str] | None = None,
            runner: Callable[[tuple[str, ...]], tuple[bool, str]] | None = None) -> dict:
    """Collect bounded state only; command output and configured paths never escape."""
    env = os.environ if environ is None else environ
    run = runner or _run
    profile = registry.profile.document
    required = profile["capacity"]
    cpu = os.cpu_count() or 0
    memory = _memory_gib()
    disk = shutil.disk_usage("/").free // (1024 ** 3)
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(
        platform.machine().lower(), platform.machine().lower()
    )
    os_family, os_version = _os_release()
    microk8s_ok, version_output = run(("microk8s", "version"))
    version_match = re.search(r"v?(\d+\.\d+)(?:\.\d+)?", version_output)
    microk8s_version = version_match.group(1) if version_match else "unavailable"
    status_ok, status_output = run(("microk8s", "status", "--wait-ready", "--timeout", "2"))
    enabled_addons = _enabled_addons(status_output)
    addons = {addon: addon in enabled_addons for addon in profile["microk8s"]["addons"]}
    storage_ok, storage_output = run(("microk8s", "kubectl", "get", "storageclass", "-o", "name"))
    ingress_ok, ingress_output = run(("microk8s", "kubectl", "get", "ingressclass", "-o", "name"))
    storage_ok = storage_ok and bool(storage_output.strip())
    ingress_ok = ingress_ok and bool(ingress_output.strip())
    license_ok = _protected_regular(env.get("FORTIFY_LICENSE_FILE"))
    docker_root = env.get("DOCKER_CONFIG")
    registry_ok = _protected_regular(
        str(Path(docker_root) / "config.json") if docker_root else None
    )
    tls_ok = _certificate_ready(env.get("FORTIFY_SERVER_CERT"), env.get("DOMAIN"))
    dns_configured = _dns_matches(env.get("DOMAIN"), env.get("FORTIFY_PUBLIC_ADDRESS"))
    compatible = (
        _os_supported(os_family, os_version)
        and platform.system() == "Linux"
        and architecture == profile["microk8s"]["architecture"]
        and _version_in_range(microk8s_version, profile["microk8s"]["versionRange"])
    )
    capacity_ok = cpu >= required["cpuCores"] and memory >= required["memoryGiB"] and disk >= required["storageGiB"]
    checks = {
        "host-capacity": "pass" if capacity_ok else "fail",
        "microk8s": "pass" if microk8s_ok and status_ok else "fail",
        "microk8s-addons": "pass" if addons and all(addons.values()) else "fail",
        "storage": "pass" if storage_ok else "fail",
        "ingress": "pass" if ingress_ok and _ports_reachable() else "fail",
        "dns": "pass" if dns_configured else "fail",
        "tls": "pass" if tls_ok else "fail",
        "external-license": "pass" if license_ok else "fail",
        "registry-authentication": "pass" if registry_ok else "fail",
        # Repository metadata currently has tags, not complete repository origins.
        "image-reachability": "warning" if registry_ok else "fail",
        "configuration": "pass",
        "compatibility": "pass" if compatible else "fail",
    }
    facts = {
        "cpuCores": cpu, "memoryGiB": memory, "storageGiB": disk,
        "remainingCpuCores": max(0, cpu - required["cpuCores"]),
        "remainingMemoryGiB": max(0, memory - required["memoryGiB"]),
        "remainingStorageGiB": max(0, disk - required["storageGiB"]),
        "osFamily": os_family, "osVersion": os_version,
        "kernel": _safe_text(platform.release()), "architecture": architecture,
        "microk8sVersion": microk8s_version, "ec2": _is_ec2(),
    }
    return {
        "apiVersion": API_VERSION, "kind": EVIDENCE_KIND,
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "checks": checks, "facts": facts,
    }


def write(path: Path, document: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    candidate = path.parent / f".{path.name}.{os.getpid()}"
    candidate.write_text(json.dumps(document, separators=(",", ":")) + "\n", encoding="utf-8")
    candidate.chmod(0o640)
    try:
        os.chown(candidate, 0, grp.getgrnam("fortify-manager").gr_gid)
    except KeyError:
        pass
    candidate.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="collect sanitized host preflight evidence")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    write(args.output, collect(ComponentRegistry.load()))
    return 0


def _run(command: tuple[str, ...]) -> tuple[bool, str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
        output = (result.stdout or "")[:16384]
        return result.returncode == 0, output
    except (OSError, subprocess.TimeoutExpired):
        return False, ""


def _memory_gib() -> int:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // (1024 * 1024)
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _os_release() -> tuple[str, str]:
    try:
        values = dict(
            line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines()
            if "=" in line
        )
        return _safe_text(values.get("ID", "unknown").strip('"')), _safe_text(values.get("VERSION_ID", "unknown").strip('"'))
    except OSError:
        return "unknown", "unknown"


def _safe_text(value: str) -> str:
    return value if SAFE_VALUE.fullmatch(value) else "unknown"


def _safe_fact(value: Any) -> bool:
    return (isinstance(value, bool) or isinstance(value, int) and value >= 0
            or isinstance(value, str) and bool(SAFE_VALUE.fullmatch(value)))


def _protected_regular(value: str | None) -> bool:
    if not value:
        return False
    try:
        metadata = Path(value).stat(follow_symlinks=False)
        return stat.S_ISREG(metadata.st_mode) and metadata.st_size > 0 and not metadata.st_mode & 0o077
    except OSError:
        return False


def _regular_nonempty(value: str | None) -> bool:
    if not value:
        return False


def _certificate_ready(value: str | None, domain: str | None) -> bool:
    if not _regular_nonempty(value) or not domain:
        return False
    try:
        certificate = ssl._ssl._test_decode_cert(str(Path(value)))
        expires = datetime.strptime(
            certificate["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
        names = {
            entry for kind, entry in certificate.get("subjectAltName", ())
            if kind == "DNS"
        }
        required = {domain, *(f"{name}.{domain}" for name in ("lab", "ssc", "lim", "sast", "dast"))}
        covered = all(
            name in names or any(
                candidate.startswith("*.") and name.endswith(candidate[1:])
                for candidate in names
            )
            for name in required
        )
        return expires > datetime.now(timezone.utc) + timedelta(days=7) and covered
    except (KeyError, OSError, ValueError, ssl.SSLError):
        return False
    try:
        metadata = Path(value).stat(follow_symlinks=False)
        return stat.S_ISREG(metadata.st_mode) and metadata.st_size > 0
    except OSError:
        return False


def _ports_reachable() -> bool:
    for port in (80, 443):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                pass
        except OSError:
            return False
    return True


def _enabled_addons(output: str) -> set[str]:
    enabled: set[str] = set()
    in_enabled = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped == "enabled:":
            in_enabled = True
            continue
        if stripped == "disabled:":
            in_enabled = False
            continue
        direct = re.fullmatch(r"([a-z0-9-]+):\s*enabled", stripped)
        if direct:
            enabled.add(direct.group(1))
        elif in_enabled and stripped and not stripped.endswith(":"):
            value = stripped.split()[0]
            if re.fullmatch(r"[a-z0-9-]+", value):
                enabled.add(value)
    return enabled


def _version_in_range(version: str, expression: str) -> bool:
    try:
        current = tuple(map(int, version.split(".")[:2]))
        lower, upper = re.findall(r"[<>]=?(\d+\.\d+)", expression)
        return tuple(map(int, lower.split("."))) <= current < tuple(map(int, upper.split(".")))
    except (ValueError, AttributeError):
        return False


def _os_supported(family: str, version: str) -> bool:
    try:
        return family == "ubuntu" and int(version.split(".", 1)[0]) >= 22
    except (ValueError, IndexError):
        return False


def _dns_matches(domain: str | None, expected: str | None) -> bool:
    if not domain or not expected:
        return False
    try:
        addresses = {
            item[4][0] for item in socket.getaddrinfo(f"lab.{domain}", 443, type=socket.SOCK_STREAM)
        }
        return addresses == {expected}
    except (OSError, TypeError):
        return False


def _is_ec2() -> bool:
    for path in (Path("/sys/class/dmi/id/sys_vendor"), Path("/sys/hypervisor/uuid")):
        try:
            value = path.read_text(encoding="utf-8").lower()
            if "amazon" in value or value.startswith("ec2"):
                return True
        except OSError:
            continue
    return False


if __name__ == "__main__":
    raise SystemExit(main())
