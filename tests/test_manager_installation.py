"""Static and in-process contracts for the supported manager installation."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from datetime import datetime, timezone

import yaml

from manager.dashboard import password_verifier
from manager.health import ProbeResult
from manager.server import ConfigurationError, build_app, load_config


ROOT = Path(__file__).resolve().parents[1]


class ManagerInstallationTests(unittest.TestCase):
    def test_manifest_stages_complete_runtime_with_policy_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate"
            subprocess.run(
                [
                    "python3",
                    "scripts/package-manager-runtime.py",
                    "stage",
                    "--source",
                    str(ROOT),
                    "--target",
                    str(candidate),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue((candidate / "apps/mysql/start.sh").is_file())
            self.assertTrue((candidate / "manager/web/assets/dashboard.js").is_file())
            self.assertTrue((candidate / "registry/schemas/component.schema.json").is_file())
            self.assertTrue((candidate / "packaging/microk8s/manager-ingress.yaml.in").is_file())
            self.assertEqual(
                oct((candidate / "apps/mysql/start.sh").stat().st_mode & 0o777),
                "0o755",
            )
            self.assertEqual(
                oct((candidate / "manager/server.py").stat().st_mode & 0o777),
                "0o644",
            )
            self.assertEqual(
                oct((candidate / "bin/fortify-manager-server").stat().st_mode & 0o777),
                "0o755",
            )
            manifest = json.loads(
                (ROOT / "packaging/manager-runtime.json").read_text(encoding="utf-8")
            )
            source_files = {
                str(path.relative_to(ROOT))
                for directory in manifest["directories"]
                for path in (ROOT / directory).rglob("*")
                if path.is_file()
            }
            source_files.update(manifest["files"])
            expected = (
                source_files
                | set(manifest["launchers"])
                | {"packaging/runtime-files.json"}
            )
            packaged = {
                str(path.relative_to(candidate))
                for path in candidate.rglob("*")
                if path.is_file()
            }
            self.assertEqual(packaged, expected)

    def test_staged_validation_rejects_omitted_runtime_classes(self):
        omissions = (
            "apps/mysql/start.sh",
            "registry/schemas/component.schema.json",
            "manager/web/assets/dashboard.js",
            "packaging/microk8s/manager-ingress.yaml.in",
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            candidate = base / "candidate"
            subprocess.run(
                [
                    "python3",
                    "scripts/package-manager-runtime.py",
                    "stage",
                    "--source",
                    str(ROOT),
                    "--target",
                    str(candidate),
                ],
                cwd=ROOT,
                check=True,
            )
            for index, omission in enumerate(omissions):
                broken = base / f"broken-{index}"
                shutil.copytree(candidate, broken)
                (broken / omission).unlink()
                result = subprocess.run(
                    [
                        "python3",
                        "scripts/package-manager-runtime.py",
                        "validate",
                        "--target",
                        str(broken),
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0, omission)
                self.assertIn("differ from the packaging inventory", result.stderr)

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
            {"hosts": ["lab.fortifydemo.com"], "secretName": "tls"},
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

    def test_failed_route_apply_preserves_external_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_root = root / "config"
            state_root = root / "state"
            install_root = root / "install"
            bin_root = root / "bin"
            for path in (config_root, state_root, install_root, bin_root):
                path.mkdir()
            config = config_root / "manager.toml"
            original = (
                '[server]\nhost = "0.0.0.0"\nport = 8080\n'
                f'[storage]\ndatabase = "{state_root / "history.sqlite3"}"\n'
                f'[authentication]\naccounts = "{state_root / "accounts.json"}"\n'
            )
            config.write_text(original)
            microk8s = bin_root / "microk8s"
            microk8s.write_text("#!/bin/sh\nexit 1\n")
            microk8s.chmod(0o755)
            fake_id = bin_root / "id"
            fake_id.write_text("#!/bin/sh\n[ \"$1\" = \"-u\" ] && echo 0\n")
            fake_id.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": f"{bin_root}:{os.environ['PATH']}",
                "FORTIFY_MANAGER_CONFIG_ROOT": str(config_root),
                "FORTIFY_MANAGER_STATE_ROOT": str(state_root),
                "FORTIFY_MANAGER_INSTALL_ROOT": str(install_root),
                "FORTIFY_MANAGER_MANIFEST_PATH": str(state_root / "route.yaml"),
            }
            result = subprocess.run(
                [
                    "bash",
                    "scripts/fortify-manager",
                    "configure",
                    "fortifydemo.com",
                    "10.0.0.10",
                    "9080",
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("existing configuration was preserved", result.stderr)
            self.assertEqual(config.read_text(), original)
            self.assertFalse((state_root / "route.yaml").exists())

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

    def test_explicit_lifecycle_enablement_composes_authenticated_service(self):
        class Observer:
            def __init__(self, *_args, **_kwargs):
                pass

            def probe(self, _check):
                return ProbeResult(
                    "healthy", "sanitized", datetime.now(timezone.utc), 1
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            accounts = root / "accounts.json"
            accounts.write_text(json.dumps(
                {"operator": password_verifier("long password")}
            ))
            accounts.chmod(0o600)
            config = {
                "host": "0.0.0.0",
                "port": 8080,
                "state_database": str(root / "history.sqlite3"),
                "accounts": str(accounts),
                "cluster": {
                    "server": "https://127.0.0.1:16443",
                    "token_file": str(root / "token"),
                    "ca_file": str(root / "ca.crt"),
                },
                "lifecycle_enabled": True,
            }
            with patch("manager.server.KubernetesObserver", Observer):
                app, store = build_app(config)
            try:
                self.assertIsNotNone(app._operation_api)
                self.assertEqual(len(store._lifecycle_stores), 2)
            finally:
                for lifecycle_store in store._lifecycle_stores:
                    lifecycle_store.close()
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
        self.assertIn("kubectl diff", script)
        self.assertIn("FORTIFY_MANAGER_TLS_SECRET", script)
        self.assertIn("for _ in {1..15}", script)
        self.assertIn("prior manager release could not be restarted", script)
        self.assertLess(
            script.index("prepare_runtime_candidate", script.index("upgrade)")),
            script.index('systemctl stop "$SERVICE_NAME"', script.index("upgrade)")),
        )
        self.assertNotIn('find "$release" -type f -exec chmod', script)
        self.assertIn("fortify-manager-cli", script)
        self.assertNotIn("create-certs.sh", script)

    def test_observer_rbac_is_read_only_and_secret_safe(self):
        documents = list(yaml.safe_load_all(
            (ROOT / "packaging/microk8s/manager-observer-rbac.yaml").read_text()
        ))
        role = next(item for item in documents if item["kind"] == "Role")
        cluster_role = next(item for item in documents if item["kind"] == "ClusterRole")
        role_binding = next(item for item in documents if item["kind"] == "RoleBinding")
        rules = role["rules"] + cluster_role["rules"]
        verbs = {verb for rule in rules for verb in rule["verbs"]}
        resources = {
            resource for rule in rules for resource in rule.get("resources", [])
        }
        self.assertEqual(verbs, {"get", "list"})
        self.assertNotIn("secrets", resources)
        self.assertNotIn("pods/log", resources)
        self.assertNotIn("namespaces", resources)
        self.assertIn("persistentvolumeclaims", resources)
        self.assertEqual(role["metadata"]["namespace"], "fortify")
        self.assertEqual(role_binding["metadata"]["namespace"], "fortify")

    def test_lifecycle_rbac_is_namespace_scoped_and_cannot_read_secrets(self):
        documents = list(yaml.safe_load_all(
            (ROOT / "packaging/microk8s/manager-lifecycle-rbac.yaml").read_text()
        ))
        self.assertFalse(any(item["kind"].endswith("ClusterRole") for item in documents))
        role = next(item for item in documents if item["kind"] == "Role")
        binding = next(item for item in documents if item["kind"] == "RoleBinding")
        resources = {
            resource for rule in role["rules"] for resource in rule["resources"]
        }
        self.assertNotIn("secrets", resources)
        self.assertNotIn("pods", resources)
        self.assertNotIn("pods/exec", resources)
        self.assertNotIn("namespaces", resources)
        self.assertEqual(role["metadata"]["namespace"], "fortify")
        self.assertEqual(binding["metadata"]["namespace"], "fortify")


if __name__ == "__main__":
    unittest.main()
