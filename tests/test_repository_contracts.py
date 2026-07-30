"""Regression checks for documented fresh-clone repository contracts."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from manager.component_registry import ComponentRegistry


ROOT = Path(__file__).resolve().parents[1]


class RepositoryContractTests(unittest.TestCase):
    def test_license_exists_and_readme_links_to_it(self) -> None:
        self.assertTrue((ROOT / "LICENSE").is_file())
        self.assertIn("](LICENSE)", (ROOT / "README.md").read_text(encoding="utf-8"))

    def test_documented_evaluation_bundle_matches_env_example(self) -> None:
        environment = (ROOT / ".env.example").read_text(encoding="utf-8")
        compatibility = (ROOT / "docs/platform-compatibility.md").read_text(
            encoding="utf-8"
        )
        values = dict(
            re.findall(r'^export (FORTIFY_[A-Z0-9_]+)="([^"]+)"$', environment, re.M)
        )
        values = {
            name: value
            for name, value in values.items()
            if name.endswith(("_CHART_VERSION", "_IMAGE_TAG"))
        }
        expected = {
            "FORTIFY_SSC_CHART_VERSION": "24.4.2-1",
            "FORTIFY_SSC_IMAGE_TAG": "24.4.2.0009",
            "FORTIFY_SCSAST_CHART_VERSION": "24.4.0-2",
            "FORTIFY_SCSAST_CTRL_IMAGE_TAG": "24.4.0.0060",
            "FORTIFY_SCSAST_WORKER_IMAGE_TAG": "24.4.1",
            "FORTIFY_SCDAST_CHART_VERSION": "24.4.0-2",
            "FORTIFY_LIM_CHART_VERSION": "24.4.0-3",
            "FORTIFY_MYSQL_CHART_VERSION": "9.19.0",
            "FORTIFY_POSTGRES_CHART_VERSION": "18.6.2",
            "FORTIFY_POSTGRES_IMAGE_TAG": "17.6.0-debian-12-r4",
            "FORTIFY_MYSQL_IMAGE_TAG": "8.0.36-debian-11-r2",
        }
        self.assertEqual(values, expected)
        for version in expected.values():
            self.assertIn(f"`{version}`", compatibility)
        self.assertIn("**unverified**", compatibility)

        registry = ComponentRegistry.load()
        registered_pins = {
            pin
            for component_id in registry.component_ids
            for pin in (
                registry.component(component_id)["version"]["chart"],
                *registry.component(component_id)["version"]["images"].values(),
            )
        }
        self.assertEqual(registered_pins, set(expected.values()))

    def test_secret_key_is_saved_before_generated_directory_is_removed(self) -> None:
        script = (ROOT / "scripts/create-secrets.sh").read_text(encoding="utf-8")
        preserve = script.index('cp "$SSC_GEN_DIR/secret.key"')
        rebuild = script.index('rm -rf "$GENERATED_DIR"')
        restore = script.index(
            'cp "$PRESERVED_SSC_KEY/secret.key" "$SSC_GEN_DIR/secret.key"'
        )
        self.assertLess(preserve, rebuild)
        self.assertLess(rebuild, restore)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("rotates on every `create-secrets.sh` run", readme)
        self.assertIn("preserved across `create-secrets.sh` runs", readme)

    def test_supervisor_installer_copies_every_runtime_module(self) -> None:
        script = (ROOT / "scripts/install-supervisor.sh").read_text(encoding="utf-8")
        self.assertIn(
            '"$REPOSITORY_ROOT/supervisor/fortify_supervisor.py"', script
        )
        self.assertIn('"$REPOSITORY_ROOT/supervisor/workflow_status.py"', script)
        self.assertIn('"$REPOSITORY_ROOT/manager/runner_heartbeat.py"', script)


if __name__ == "__main__":
    unittest.main()
