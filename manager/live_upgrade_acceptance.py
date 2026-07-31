"""Sanitized evidence support for the opt-in EC2 Manager upgrade gate."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path


LAYERS = (
    "package", "configuration", "service", "cluster-tls", "authorization",
    "observation", "ingress", "dns", "remote-access",
)
CHECKS = (
    "prerequisites", "account-preservation", "history-preservation",
    "session-invalidation", "immutable-activation", "rollback-evidence",
    "configuration-migration", "legacy-ca", "rbac-positive", "rbac-negative",
    "inventory", "node-version", "health", "preflight", "partial-failure",
    "recovery", "private-https", "no-public-backend",
    "dns-resolution",
)
SAFE_TOKEN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$")


class EvidenceError(ValueError):
    """Evidence would violate the bounded sanitized contract."""


def write_evidence(
    output: Path, *, status: str, profile_id: str, release_before: str,
    release_after: str, results: dict[str, str], failure_layer: str | None = None,
    expires_days: int = 7,
) -> None:
    """Write categorical evidence atomically; never accept raw command output."""
    if status not in {"passed", "failed"}:
        raise EvidenceError("unsupported gate status")
    if set(results) != set(CHECKS) or any(
        value not in {"passed", "failed", "not-run"} for value in results.values()
    ):
        raise EvidenceError("every bounded check must have a categorical result")
    if failure_layer is not None and failure_layer not in LAYERS:
        raise EvidenceError("unsupported failure layer")
    if status == "passed" and (failure_layer is not None or set(results.values()) != {"passed"}):
        raise EvidenceError("passed evidence requires every check and no failure layer")
    if status == "failed" and failure_layer is None:
        raise EvidenceError("failed evidence requires the earliest failure layer")
    for value in (profile_id, release_before, release_after):
        if not SAFE_TOKEN.fullmatch(value):
            raise EvidenceError("identifier is not safe evidence")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    document = {
        "apiVersion": "fortifylab.io/evaluations/v1alpha1",
        "kind": "ManagerUpgradeAcceptanceEvidence",
        "status": status,
        "profileId": profile_id,
        "platform": "single-node MicroK8s",
        "target": "EC2 lab",
        "recordedAt": now.isoformat().replace("+00:00", "Z"),
        "expiresAt": (now + timedelta(days=expires_days)).isoformat().replace("+00:00", "Z"),
        "releaseBefore": release_before,
        "releaseAfter": release_after,
        "failureLayer": failure_layer,
        "checks": results,
        "collection": {
            "rawOutput": False,
            "licensedArtifacts": False,
            "applicationSecrets": False,
            "credentials": False,
        },
        "limitations": [
            "Lab validation only; this is not production certification.",
            "Single-node MicroK8s on EC2 only; ASPM is excluded.",
        ],
    }
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(output)


def main() -> int:
    parser = argparse.ArgumentParser(description="Write sanitized live-upgrade evidence")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--status", required=True, choices=("passed", "failed"))
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--release-before", required=True)
    parser.add_argument("--release-after", required=True)
    parser.add_argument("--failure-layer", choices=LAYERS)
    parser.add_argument("--results", required=True, type=Path,
                        help="gate-owned categorical check file")
    args = parser.parse_args()
    results = dict(
        line.rstrip("\n").split("=", 1)
        for line in args.results.read_text(encoding="utf-8").splitlines() if line
    )
    write_evidence(
        args.output, status=args.status, profile_id=args.profile_id,
        release_before=args.release_before, release_after=args.release_after,
        failure_layer=args.failure_layer, results=results,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
