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
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from datetime import datetime, timezone, timedelta

from manager.component_registry import ComponentRegistry
from manager.preflight import PreflightCheck, PreflightResult
from manager.config_migration import MigrationError, validate_document


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
DEFAULT_MICROK8S = Path("/snap/bin/microk8s")


@dataclass(frozen=True)
class CollectionSettings:
    domain: str | None
    public_address: str | None
    license_file: Path
    registry_auth_file: Path
    tls_certificate_file: Path
    trusted_uids: frozenset[int]
    configuration_valid: bool = True


class HostPreflightEvidence:
    """Read a root-produced document without exposing its collection inputs."""

    def __init__(self, path: Path, *, expected_uid: int | None = None,
                 expected_gid: int | None = None) -> None:
        self._path = path
        self._expected_uid = expected_uid
        self._expected_gid = expected_gid

    def document(self) -> dict[str, Any]:
        try:
            expected_uid = pwd.getpwnam("root").pw_uid if self._expected_uid is None else self._expected_uid
            expected_gid = grp.getgrnam("fortify-manager").gr_gid if self._expected_gid is None else self._expected_gid
            metadata = self._path.stat(follow_symlinks=False)
        except (KeyError, OSError):
            raise ValueError("host preflight evidence is unavailable") from None
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o640
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
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


def collect(registry: ComponentRegistry, settings: CollectionSettings, *,
            runner: Callable[[tuple[str, ...]], tuple[bool, str]] | None = None) -> dict:
    """Collect bounded state only; command output and configured paths never escape."""
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
    microk8s = str(DEFAULT_MICROK8S)
    microk8s_ok, version_output = run((microk8s, "version"))
    version_match = re.search(r"v?(\d+\.\d+)(?:\.\d+)?", version_output)
    microk8s_version = version_match.group(1) if version_match else "unavailable"
    status_ok, status_output = run((microk8s, "status", "--wait-ready", "--timeout", "2"))
    enabled_addons = _enabled_addons(status_output)
    addons = {addon: addon in enabled_addons for addon in profile["microk8s"]["addons"]}
    storage_ok, storage_output = run((microk8s, "kubectl", "get", "storageclass", "-o", "json"))
    ingress_ok, ingress_output = run((microk8s, "kubectl", "get", "ingressclass", "-o", "name"))
    storage_ok = storage_ok and _default_storage_ready(storage_output)
    ingress_ok = ingress_ok and bool(ingress_output.strip())
    license_ok = _protected_regular(settings.license_file, settings.trusted_uids)
    registry_ok = _registry_auth_ready(settings.registry_auth_file, settings.trusted_uids)
    tls_ok = _certificate_ready(settings.tls_certificate_file, settings.domain)
    dns_configured = _dns_matches(settings.domain, settings.public_address)
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
        "configuration": "pass" if settings.configuration_valid else "fail",
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


def write(path: Path, document: dict, *, staging: Path,
          expected_uid: int | None = None, expected_gid: int | None = None) -> None:
    root_uid = pwd.getpwnam("root").pw_uid if expected_uid is None else expected_uid
    root_gid = pwd.getpwnam("root").pw_gid if expected_gid is None else expected_gid
    manager_gid = grp.getgrnam("fortify-manager").gr_gid if expected_gid is None else expected_gid
    staging_meta = staging.stat(follow_symlinks=False)
    parent_meta = path.parent.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(staging_meta.st_mode) or staging_meta.st_uid != root_uid
            or staging_meta.st_gid != root_gid
            or stat.S_IMODE(staging_meta.st_mode) != 0o700
            or not stat.S_ISDIR(parent_meta.st_mode)):
        raise ValueError("host preflight staging is not protected")
    descriptor, candidate_name = tempfile.mkstemp(prefix="host-preflight-", dir=staging)
    candidate = Path(candidate_name)
    try:
        payload = json.dumps(document, separators=(",", ":")) + "\n"
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(candidate, root_uid, manager_gid, follow_symlinks=False)
        candidate.chmod(0o640, follow_symlinks=False)
        HostPreflightEvidence(
            candidate, expected_uid=root_uid, expected_gid=manager_gid
        ).document()
        os.replace(candidate, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        candidate.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="collect sanitized host preflight evidence")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    args = parser.parse_args()
    settings = load_settings(args.config, args.repository_root)
    write(args.output, collect(ComponentRegistry.load(), settings), staging=args.staging)
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


def load_settings(config_path: Path, repository_root: Path) -> CollectionSettings:
    """Load validated, non-secret collector references from Manager config."""
    try:
        document = tomllib.loads(config_path.read_text(encoding="utf-8"))
        validate_document(document)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, MigrationError) as error:
        raise ValueError("manager configuration is unavailable or invalid") from error
    network = document.get("network", {})
    preflight = document.get("preflight", {})
    trusted = {0}
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid and sudo_uid.isdecimal():
        trusted.add(int(sudo_uid))
    return CollectionSettings(
        domain=network.get("domain"),
        public_address=network.get("public_address"),
        license_file=Path(preflight.get(
            "license_file", repository_root / "secrets/input/fortify.license"
        )),
        registry_auth_file=Path(preflight.get(
            "registry_auth_file", repository_root / "secrets/input/dockerconfig.json"
        )),
        tls_certificate_file=Path(preflight.get(
            "tls_certificate_file", repository_root / "certs/tls.crt"
        )),
        trusted_uids=frozenset(trusted),
    )


def _protected_regular(value: Path, trusted_uids: frozenset[int]) -> bool:
    if not value:
        return False
    try:
        metadata = value.stat(follow_symlinks=False)
        return (
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_size > 0
            and metadata.st_uid in trusted_uids
            and not metadata.st_mode & 0o077
        )
    except OSError:
        return False


def _regular_nonempty(value: Path | None) -> bool:
    if not value:
        return False
    try:
        metadata = value.stat(follow_symlinks=False)
        return stat.S_ISREG(metadata.st_mode) and metadata.st_size > 0
    except OSError:
        return False


def _registry_auth_ready(value: Path, trusted_uids: frozenset[int]) -> bool:
    if not _protected_regular(value, trusted_uids):
        return False
    try:
        if value.stat(follow_symlinks=False).st_size > 1024 * 1024:
            return False
        document = json.loads(value.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            return False
        auths = document.get("auths", {})
        stores = document.get("credsStore") or document.get("credHelpers")
        return (isinstance(auths, dict) and bool(auths)) or bool(stores)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False


def _default_storage_ready(output: str) -> bool:
    try:
        document = json.loads(output)
        items = document.get("items", [])
        if not isinstance(items, list):
            return False
        default_keys = (
            "storageclass.kubernetes.io/is-default-class",
            "storageclass.beta.kubernetes.io/is-default-class",
        )
        return any(
            isinstance(item, dict)
            and bool(item.get("provisioner"))
            and any(
                item.get("metadata", {}).get("annotations", {}).get(key) == "true"
                for key in default_keys
            )
            for item in items
        )
    except (AttributeError, json.JSONDecodeError):
        return False


def _certificate_ready(value: Path | None, domain: str | None) -> bool:
    if not _regular_nonempty(value) or not domain:
        return False
    try:
        certificate = ssl._ssl._test_decode_cert(str(value))
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
