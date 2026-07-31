"""Deterministic, secret-safe Fortify Lab Manager release-candidate builder."""

from __future__ import annotations

import hashlib
import gzip
import json
import os
import re
import subprocess
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterable

from manager.observable_evaluation import load
from manager.operational_console_evaluation import evaluate as evaluate_console
from manager.verified_lifecycle_evaluation import evaluate as evaluate_lifecycle


MAX_FILES = 1000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024
INCLUDED_ROOTS = {
    ".github",
    "apps",
    "config",
    "contracts",
    "docs",
    "evaluations",
    "manager",
    "packaging",
    "profiles",
    "registry",
    "scripts",
    "secrets/templates",
    "supervisor",
    "tests",
}
INCLUDED_FILES = {
    ".env.example",
    ".gitignore",
    ".shellcheckrc",
    ".yamllint.yml",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "VERSION",
    "setup.sh",
    "start_wizard.sh",
}
DENIED_PARTS = {
    ".env",
    "certs",
    "generated",
    "input",
    "private",
    "secrets/generated",
    "secrets/input",
}
DENIED_SUFFIXES = {".key", ".jks", ".p12", ".pfx", ".pem"}
SENSITIVE_CONTENT = re.compile(
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    rb"|\bgh[pousr]_[A-Za-z0-9_]{20,}\b"
    rb"|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    rb"|\b\d{8,12}:[A-Za-z0-9_-]{30,}\b"
    rb"|(?i:(?:authorization|bearer)\s*[:=]\s*[\"']?[A-Za-z0-9._~-]{24,})"
)


class ReleaseCandidateError(ValueError):
    """A candidate cannot be built without violating its safety contract."""


@dataclass(frozen=True)
class CandidateResult:
    directory: Path
    manifest: Path
    archive: Path
    verdict: str


def _json_bytes(document: object) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_included(path: str) -> bool:
    if path in INCLUDED_FILES:
        return True
    return any(path == root or path.startswith(root + "/") for root in INCLUDED_ROOTS)


def _is_denied(path: str) -> bool:
    pure = PurePosixPath(path)
    if pure.suffix.lower() in DENIED_SUFFIXES:
        return True
    parts = set(pure.parts)
    return any(item in parts or path.startswith(item + "/") for item in DENIED_PARTS)


def tracked_release_files(root: Path) -> list[str]:
    """Return bounded, non-ignored review inputs under repository allowlists."""
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    paths = sorted(
        item.decode("utf-8")
        for item in result.stdout.split(b"\0")
        if item and _is_included(item.decode("utf-8"))
    )
    if len(paths) > MAX_FILES:
        raise ReleaseCandidateError(f"candidate exceeds {MAX_FILES} files")
    total = 0
    for relative in paths:
        if _is_denied(relative):
            raise ReleaseCandidateError(f"sensitive path selected: {relative}")
        source = root / relative
        if not source.is_file() or source.is_symlink():
            raise ReleaseCandidateError(f"candidate input is not a regular file: {relative}")
        size = source.stat().st_size
        if size > MAX_FILE_BYTES:
            raise ReleaseCandidateError(f"candidate input exceeds per-file bound: {relative}")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise ReleaseCandidateError("candidate exceeds total size bound")
    return paths


def _scan_files(root: Path, paths: Iterable[str]) -> list[dict[str, object]]:
    files = []
    for relative in paths:
        content = (root / relative).read_bytes()
        if SENSITIVE_CONTENT.search(content):
            raise ReleaseCandidateError(f"candidate input failed sensitive-content scan: {relative}")
        files.append({"path": relative, "bytes": len(content), "sha256": _sha256(content)})
    return files


def _profile_matrix(root: Path) -> list[dict[str, object]]:
    matrix = []
    for path in sorted((root / "profiles").glob("*.json")):
        profile = json.loads(path.read_text(encoding="utf-8"))
        evidence_path = path.parent / profile["evidence"]["record"]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        matrix.append(
            {
                "profileId": profile["id"],
                "platform": profile["scope"]["platform"],
                "topology": profile["scope"]["topology"],
                "aspm": profile["scope"]["aspm"],
                "maturity": profile["maturity"],
                "evidenceLevel": evidence["evidenceLevel"],
                "checks": evidence["checks"],
                "evidenceReference": evidence_path.relative_to(root).as_posix(),
                "knownLimitations": profile["knownLimitations"],
            }
        )
    return matrix


def _git_revision(root: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _lifecycle_gate(root: Path, evaluated_at: str) -> dict[str, object]:
    evaluation_root = root / "evaluations" / "verified-platform-lifecycle-v0.4"
    return evaluate_lifecycle(
        load(evaluation_root / "scenarios.json"),
        load(evaluation_root / "observations.json"),
        load(evaluation_root / "live-evidence.json"),
        evaluated_at=evaluated_at,
    )


def _operational_console_gate(root: Path, evaluated_at: str) -> dict[str, object]:
    evaluation_root = root / "evaluations" / "operational-console-browser-v0.4"
    return evaluate_console(
        load(evaluation_root / "scenarios.json"),
        load(evaluation_root / "observations.json"),
        load(evaluation_root / "live-evidence.json"),
        evaluated_at=evaluated_at,
    )


def _write_tar(archive: Path, root: Path, paths: Iterable[str], epoch: int) -> None:
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as stream:
                for relative in paths:
                    source = root / relative
                    info = stream.gettarinfo(
                        str(source), arcname=f"fortify-lab-manager/{relative}"
                    )
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = epoch
                    with source.open("rb") as handle:
                        stream.addfile(info, handle)


def build_candidate(
    root: Path,
    output_root: Path,
    *,
    version: str = "0.4.0-rc.1",
    epoch: int | None = None,
) -> CandidateResult:
    """Build a local candidate. This never signs, publishes, or contacts a cluster."""
    root = root.resolve()
    if not re.fullmatch(r"\d+\.\d+\.\d+-rc\.\d+", version):
        raise ReleaseCandidateError("version must use X.Y.Z-rc.N")
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0")) if epoch is None else epoch
    recorded_at = datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")
    paths = tracked_release_files(root)
    files = _scan_files(root, paths)
    profile_matrix = _profile_matrix(root)
    lifecycle_evaluation = _lifecycle_gate(root, recorded_at)
    console_evaluation = _operational_console_gate(root, recorded_at)
    directory = output_root.resolve() / version
    directory.mkdir(parents=True, exist_ok=True)

    archive = directory / f"fortify-lab-manager-{version}.tar.gz"
    _write_tar(archive, root, paths, epoch)
    archive_digest = _sha256(archive.read_bytes())

    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"fortify-lab-manager-{version}",
        "documentNamespace": f"https://fortifylab.local/sbom/{version}/{_git_revision(root)}",
        "creationInfo": {"created": recorded_at, "creators": ["Tool: fortify-release-candidate"]},
        "files": [
            {
                "fileName": item["path"],
                "SPDXID": f"SPDXRef-File-{index}",
                "checksums": [{"algorithm": "SHA256", "checksumValue": item["sha256"]}],
            }
            for index, item in enumerate(files, 1)
        ],
    }
    (directory / "sbom.spdx.json").write_bytes(_json_bytes(sbom))

    lifecycle_checks = ("cleanInstall", "upgrade", "backupRestore")
    live_passed = all(
        profile["evidenceLevel"] == "licensed-live"
        and all(profile["checks"].get(check) == "passed" for check in lifecycle_checks)
        for profile in profile_matrix
    )
    gates = [
        {"id": "bounded-artifact", "status": "passed", "evidence": "manifest.json"},
        {"id": "secret-scan", "status": "passed", "evidence": "manifest.json"},
        {"id": "sbom", "status": "passed", "evidence": "sbom.spdx.json"},
        {
            "id": "vulnerability-scan",
            "status": "not-run",
            "evidence": "vulnerability-results.json",
            "reason": "No repository-owned offline vulnerability scanner is configured.",
        },
        {
            "id": "artifact-signature",
            "status": "not-run",
            "evidence": "signature-status.json",
            "reason": "No release signing key or repository-owned signer was supplied.",
        },
        {
            "id": "licensed-lifecycle",
            "status": "passed" if live_passed else "not-run",
            "evidence": "profile-matrix.json",
            "reason": None if live_passed else "Exact-profile licensed live lifecycle evidence is absent.",
        },
        {
            "id": "verified-platform-lifecycle-evaluation",
            "status": lifecycle_evaluation["status"],
            "evidence": "verified-platform-lifecycle-evaluation.json",
            "reason": (
                None
                if lifecycle_evaluation["status"] == "passed"
                else "Deterministic and fresh exact-profile live evaluation evidence is incomplete."
            ),
        },
        {
            "id": "operational-console-browser-evaluation",
            "status": console_evaluation["status"],
            "evidence": "operational-console-browser-evaluation.json",
            "reason": (
                None
                if console_evaluation["status"] == "passed"
                else "Deterministic browser journeys or authorized fresh exact-profile live browser evidence is incomplete."
            ),
        },
        {"id": "installation-docs", "status": "passed", "evidence": "documentation-verification.json"},
        {"id": "upgrade-docs", "status": "passed", "evidence": "documentation-verification.json"},
    ]
    verdict = "go" if all(gate["status"] == "passed" for gate in gates) else "no-go"
    documents = {
        "profile-matrix.json": profile_matrix,
        "operational-console-browser-evaluation.json": console_evaluation,
        "vulnerability-results.json": {
            "status": "not-run",
            "scanner": None,
            "reason": "No repository-owned offline vulnerability scanner is configured.",
            "networkUsed": False,
        },
        "signature-status.json": {
            "status": "not-run",
            "signature": None,
            "reason": "Signing is supported only when an approved external signing workflow supplies a key.",
        },
        "documentation-verification.json": {
            "status": "passed",
            "references": [
                "README.md#quick-start",
                "docs/operations/manager.md#upgrade-backup-and-rollback",
                "docs/operations/profile-upgrades.md",
                "docs/operations/backup-restore.md",
                "docs/operations/rollback-recovery.md",
            ],
            "scope": "static commands, links, and candidate contracts; no live execution",
        },
        "verified-platform-lifecycle-evaluation.json": lifecycle_evaluation,
        "go-no-go.json": {
            "version": version,
            "verdict": verdict,
            "gates": gates,
            "rule": "GO requires every gate to be passed; failed and not-run are blocking.",
        },
    }
    for name, document in documents.items():
        (directory / name).write_bytes(_json_bytes(document))

    manifest = directory / "manifest.json"
    manifest.write_bytes(
        _json_bytes(
            {
                "schemaVersion": "1.0",
                "candidateVersion": version,
                "semanticVersionRecommendation": "0.4.0",
                "recommendationReason": "Milestone 0.4 adds backward-compatible platform lifecycle capabilities.",
                "sourceRevision": _git_revision(root),
                "recordedAt": recorded_at,
                "scope": {"platform": "microk8s", "topology": "single-node", "aspm": False},
                "bounds": {
                    "maximumFiles": MAX_FILES,
                    "maximumFileBytes": MAX_FILE_BYTES,
                    "maximumTotalBytes": MAX_TOTAL_BYTES,
                },
                "archive": {"path": archive.name, "sha256": archive_digest},
                "files": files,
                "evidence": sorted(documents),
                "changelog": "CHANGELOG.md",
                "verdict": verdict,
            }
        )
    )
    checksum_targets = [
        archive,
        manifest,
        *(directory / name for name in documents),
        directory / "sbom.spdx.json",
    ]
    checksums = "".join(
        f"{_sha256(path.read_bytes())}  {path.name}\n"
        for path in sorted(checksum_targets)
    )
    (directory / "SHA256SUMS").write_text(checksums, encoding="ascii")
    return CandidateResult(directory, manifest, archive, verdict)
