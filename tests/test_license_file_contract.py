"""Regression tests for external Fortify license file references."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/lib/fortify-license.sh"


class LicenseFileContractTests(unittest.TestCase):
    def run_resolver(self, license_path: Path) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "FORTIFY_LICENSE_FILE": str(license_path),
                "FORTIFY_SECRETS_INPUT": str(ROOT / "secrets/input"),
            }
        )
        return subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; fortify_resolve_license_file && printf "%s" "$FORTIFY_LICENSE_FILE"',
                "resolver-test",
                str(HELPER),
            ],
            check=False,
            capture_output=True,
            encoding="utf-8",
            env=environment,
        )

    def test_external_license_path_is_canonicalized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            license_file = Path(directory) / "license"
            license_file.write_text("synthetic-test-data", encoding="utf-8")

            result = self.run_resolver(license_file.parent / "." / license_file.name)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, str(license_file.resolve()))
            self.assertNotIn("synthetic-test-data", result.stdout + result.stderr)

    def test_repository_local_default_remains_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            input_directory = Path(directory) / "secrets/input"
            input_directory.mkdir(parents=True)
            license_file = input_directory / "fortify.license"
            license_file.write_text("synthetic-default-data", encoding="utf-8")
            environment = os.environ.copy()
            environment.pop("FORTIFY_LICENSE_FILE", None)
            environment["FORTIFY_SECRETS_INPUT"] = str(input_directory)

            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; fortify_resolve_license_file && printf "%s" "$FORTIFY_LICENSE_FILE"',
                    "resolver-test",
                    str(HELPER),
                ],
                check=False,
                capture_output=True,
                encoding="utf-8",
                env=environment,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, str(license_file.resolve()))

    def test_invalid_path_fails_without_disclosing_path(self) -> None:
        sensitive_path = Path("/private/customer/location/fortify.license")

        result = self.run_resolver(sensitive_path)

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(str(sensitive_path), result.stdout + result.stderr)
        self.assertIn("configured Fortify license file", result.stderr)

    def test_default_and_consumers_share_the_contract(self) -> None:
        environment = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn(
            'FORTIFY_LICENSE_FILE="${FORTIFY_LICENSE_FILE:-$FORTIFY_SECRETS_INPUT/fortify.license}"',
            environment,
        )
        secret_creation = (ROOT / "scripts/create-secrets.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("fortify_resolve_license_file", secret_creation)

    def test_helm_consumers_use_existing_secret_without_license_values(self) -> None:
        for relative_path in (
            "apps/ssc/start.sh",
            "apps/scsast/start.sh",
            "apps/sast-sensor/deploy.sh",
        ):
            script = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertRegex(
                script, r"(?:secretRef\.name|secrets\.secretName)=fortify-secrets"
            )
            self.assertNotIn("fortifyLicense", script)
            self.assertNotIn("FORTIFY_LICENSE_FILE", script)

    def test_secret_creation_validates_before_cluster_mutation(self) -> None:
        script = (ROOT / "scripts/create-secrets.sh").read_text(encoding="utf-8")
        validation = script.index("fortify_resolve_license_file || exit 1")
        namespace_mutation = script.index('$KUBECTL create namespace "$NAMESPACE"')
        generated_mutation = script.index('rm -rf "$GENERATED_DIR"')
        secret_mutation = script.index('$KUBECTL -n "$NAMESPACE" delete secret')
        self.assertLess(validation, namespace_mutation)
        self.assertLess(validation, generated_mutation)
        self.assertLess(validation, secret_mutation)


if __name__ == "__main__":
    unittest.main()
