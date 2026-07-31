"""Static and evidence-contract coverage for the opt-in live upgrade gate."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from manager.live_upgrade_acceptance import CHECKS, EvidenceError, write_evidence


ROOT = Path(__file__).resolve().parents[1]


class LiveUpgradeAcceptanceTests(unittest.TestCase):
    def results(self, state: str = "passed") -> dict[str, str]:
        return {check: state for check in CHECKS}

    def test_success_evidence_is_bounded_sanitized_and_schema_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.json"
            write_evidence(
                output, status="passed", profile_id="fortify-24.4-eval.1",
                release_before="build-" + "a" * 64,
                release_after="build-" + "b" * 64, results=self.results(),
                failure_layer=None,
            )
            document = json.loads(output.read_text())
            schema = json.loads((ROOT / "evaluations/manager-upgrade-ec2-v0.4/evidence.schema.json").read_text())
            Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(document["collection"], {
                "rawOutput": False, "licensedArtifacts": False,
                "applicationSecrets": False, "credentials": False,
            })

    def test_failure_timeout_and_recovery_results_remain_explicit(self):
        results = self.results("not-run")
        results["prerequisites"] = "passed"
        results["immutable-activation"] = "failed"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.json"
            write_evidence(
                output, status="failed", profile_id="profile",
                release_before="build-old", release_after="unknown",
                results=results, failure_layer="service",
            )
            document = json.loads(output.read_text())
        self.assertEqual(document["failureLayer"], "service")
        self.assertEqual(document["checks"]["recovery"], "not-run")

    def test_missing_check_unsafe_identifier_and_unknown_layer_are_rejected(self):
        cases = []
        missing = self.results(); missing.pop("health")
        cases.append(dict(results=missing, profile_id="profile", failure_layer="service"))
        cases.append(dict(results=self.results(), profile_id="unsafe/value", failure_layer="service"))
        cases.append(dict(results=self.results(), profile_id="profile", failure_layer="database"))
        for case in cases:
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory() as directory, self.assertRaises(EvidenceError):
                    write_evidence(
                        Path(directory) / "result.json", status="failed",
                        release_before="build-old", release_after="unknown", **case,
                    )

    def test_passed_status_cannot_hide_failed_or_not_run_checks(self):
        results = self.results()
        results["recovery"] = "not-run"
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(EvidenceError):
            write_evidence(
                Path(directory) / "result.json", status="passed",
                profile_id="profile", release_before="build-old",
                release_after="build-new", results=results,
            )

    def test_checked_in_not_run_evidence_and_script_contract(self):
        evidence = json.loads((ROOT / "evaluations/manager-upgrade-ec2-v0.4/evidence.json").read_text())
        schema = json.loads((ROOT / "evaluations/manager-upgrade-ec2-v0.4/evidence.schema.json").read_text())
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(evidence)
        script = (ROOT / "scripts/live-manager-upgrade-acceptance.sh").read_text()
        for contract in (
            "timeout --foreground", "trap cleanup", "ROLLBACK_REQUIRED",
            "rbac-preflight", "diagnose-cluster", "config-diagnose",
            "/api/v1alpha1/components", "for endpoint in components health preflight",
            "/api/v1alpha1/history", "HISTORY_VIEW_AFTER", "getent ahosts",
            "resolved == {expected}", "fortify-manager-host", "ENDPOINT_ADDRESSES",
            "no-public-backend",
        ):
            self.assertIn(contract, script)
        syntax = subprocess.run(["bash", "-n", str(ROOT / "scripts/live-manager-upgrade-acceptance.sh")], capture_output=True, text=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)


if __name__ == "__main__":
    unittest.main()
