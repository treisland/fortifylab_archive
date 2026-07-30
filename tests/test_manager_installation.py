"""Static and in-process contracts for the supported manager installation."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from manager.dashboard import password_verifier
from manager.server import ConfigurationError, build_app, load_config


ROOT = Path(__file__).resolve().parents[1]


class ManagerInstallationTests(unittest.TestCase):
    def test_rendered_ingress_has_host_tls_and_backend_symmetry(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "ingress.yaml"
            subprocess.run(
                [
                    "bash",
                    "scripts/fortify-manager",
                    "render-ingress",
                    "fortifydemo.com",
                    "10.0.0.10",
                    "8080",
                    str(output),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            service, endpoints, ingress = list(yaml.safe_load_all(output.read_text()))
        self.assertEqual(service["spec"]["ports"][0]["port"], 8080)
        self.assertEqual(endpoints["subsets"][0]["ports"][0]["port"], 8080)
        self.assertEqual(endpoints["subsets"][0]["addresses"][0]["ip"], "10.0.0.10")
        self.assertEqual(ingress["spec"]["rules"][0]["host"], "lab.fortifydemo.com")
        self.assertEqual(
            ingress["spec"]["tls"][0],
            {"hosts": ["lab.fortifydemo.com"], "secretName": "fortify-tls"},
        )
        self.assertEqual(
            ingress["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"],
            {"name": "fortify-manager-host", "port": {"number": 8080}},
        )

    def test_renderer_rejects_public_backend_and_invalid_port(self):
        for address, port in (("8.8.8.8", "8080"), ("10.0.0.10", "0")):
            result = subprocess.run(
                [
                    "bash",
                    "scripts/fortify-manager",
                    "render-ingress",
                    "fortifydemo.com",
                    address,
                    port,
                    "/dev/null",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_external_config_and_account_verifier_build_secure_app(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            accounts = root / "accounts.json"
            database = root / "history.sqlite3"
            config_path = root / "manager.toml"
            accounts.write_text(json.dumps({"operator": password_verifier("long password")}))
            accounts.chmod(0o600)
            config_path.write_text(
                "[server]\nhost = \"0.0.0.0\"\nport = 9080\n"
                f"[storage]\ndatabase = \"{database}\"\n"
                f"[authentication]\naccounts = \"{accounts}\"\n"
            )
            config = load_config(config_path)
            app, store = build_app(config)
            try:
                self.assertTrue(app._secure_cookies)
                self.assertEqual(store.migration_version(), 2)
                self.assertEqual(oct(database.stat().st_mode & 0o777), "0o600")
            finally:
                store.close()

    def test_listener_fails_closed_when_not_ingress_reachable(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "manager.toml"
            config_path.write_text('[server]\nhost = "127.0.0.1"\nport = 8080\n')
            with self.assertRaisesRegex(ConfigurationError, "0.0.0.0"):
                load_config(config_path)

    def test_systemd_and_lifecycle_boundaries_are_explicit(self):
        unit = (ROOT / "packaging/systemd/fortify-manager.service").read_text()
        script = (ROOT / "scripts/fortify-manager").read_text()
        for fragment in (
            "User=fortify-manager",
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "ReadWritePaths=/var/lib/fortify-lab-manager",
        ):
            self.assertIn(fragment, unit)
        self.assertIn("Configuration and state preserved", script)
        self.assertIn("DELETE MANAGER STATE", script)
        self.assertIn('port = $port', script)
        self.assertNotIn("create-certs.sh", script)


if __name__ == "__main__":
    unittest.main()
