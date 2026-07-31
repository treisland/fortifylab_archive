"""Static and in-process contracts for the supported manager installation."""

from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import tomllib
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
    def lifecycle_activation_fixture(self, root: Path):
        config_root = root / "config"
        state_root = root / "state"
        install_root = root / "install"
        bin_root = root / "bin"
        for path in (
            config_root,
            state_root / "cluster-access",
            install_root / "current" / "bin",
            bin_root,
        ):
            path.mkdir(parents=True)
        health_socket = state_root / "health-probe.sock"
        config = config_root / "manager.toml"
        config.write_text(
            '[server]\nhost = "0.0.0.0"\nport = 8080\n'
            f'[storage]\ndatabase = "{state_root / "history.sqlite3"}"\n'
            f'[authentication]\naccounts = "{state_root / "accounts.json"}"\n'
            '[cluster]\nserver = "https://127.0.0.1:16443"\n'
            f'token_file = "{state_root / "cluster-access/token"}"\n'
            f'ca_file = "{state_root / "cluster-access/ca.crt"}"\n'
            f'health_probe_socket = "{health_socket}"\n'
            "[lifecycle]\nenabled = false\n"
        )
        validator = root / "validate-runtime.py"
        validator.write_text("raise SystemExit(0)\n")
        server = install_root / "current/bin/fortify-manager-server"
        server.write_text(
            "#!/usr/bin/env bash\n"
            '[ "${FAKE_SERVER_FAILURE:-0}" = 0 ]\n'
        )
        server.chmod(0o755)
        (bin_root / "id").write_text(
            "#!/usr/bin/env bash\n"
            '[ "$1" = "-u" ] && printf "0\\n"\n'
        )
        (bin_root / "chown").write_text("#!/usr/bin/env bash\nexit 0\n")
        (bin_root / "sleep").write_text("#!/usr/bin/env bash\nexit 0\n")
        (bin_root / "runuser").write_text(
            "#!/usr/bin/env bash\nshift 3\nexec \"$@\"\n"
        )
        (bin_root / "systemctl").write_text(
            "#!/usr/bin/env bash\n"
            'if [ "$1" = restart ] && [ "${FAKE_RESTART_FAILURE:-0}" = 1 ]; '
            "then exit 1; fi\n"
            "exit 0\n"
        )
        (bin_root / "microk8s").write_text(
            "#!/usr/bin/env bash\n"
            'arguments="$*"\n'
            'if [[ "$arguments" == *"auth can-i"* ]]; then\n'
            '  [ -s "${KUBECONFIG:-}" ] || exit 1\n'
            '  if [[ "$arguments" =~ secrets|subresource=log|subresource=exec|'
            'subresource=attach|subresource=portforward|"-n default"|namespaces|'
            'persistentvolumes|roles.rbac|clusterroles.rbac ]]; then\n'
            '    [ "${FAKE_EXCESS_PERMISSION:-0}" = 1 ] && echo yes || echo no\n'
            "  else echo yes; fi\n"
            'elif [[ "$arguments" == *"data.token"* ]]; then\n'
            '  [ "${FAKE_TOKEN_READY:-1}" = 1 ] && printf "bGlmZWN5Y2xlLXRva2Vu"\n'
            'elif [[ "$arguments" == *"data.ca"* ]]; then\n'
            '  printf "bGFiLWNh"\n'
            "else exit 0; fi\n"
        )
        for executable in bin_root.iterdir():
            executable.chmod(0o755)
        environment = os.environ | {
            "PATH": f"{bin_root}:{os.environ['PATH']}",
            "FORTIFY_MANAGER_CONFIG_ROOT": str(config_root),
            "FORTIFY_MANAGER_STATE_ROOT": str(state_root),
            "FORTIFY_MANAGER_INSTALL_ROOT": str(install_root),
            "FORTIFY_MANAGER_CLUSTER_ACCESS_ROOT": str(
                state_root / "cluster-access"
            ),
            "FORTIFY_MANAGER_PACKAGE_VALIDATOR": str(validator),
            "FORTIFY_MANAGER_LIFECYCLE_CLIENT_ROOT": str(
                state_root / "lifecycle-bin"
            ),
            "FORTIFY_MANAGER_KUBECTL_CLIENT": str(bin_root / "microk8s"),
            "FORTIFY_MANAGER_HELM_CLIENT": str(bin_root / "microk8s"),
        }
        return config, state_root / "cluster-access/lifecycle.kubeconfig", health_socket, environment

    def run_lifecycle_command(self, command: str, environment: dict):
        return subprocess.run(
            ["bash", "scripts/fortify-manager", command],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
        )

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

    def test_runtime_digest_is_repeatable_and_binds_content_and_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidates = [root / "first", root / "second"]
            for candidate in candidates:
                subprocess.run(
                    [
                        "python3", "scripts/package-manager-runtime.py", "stage",
                        "--source", str(ROOT), "--target", str(candidate),
                    ],
                    cwd=ROOT,
                    check=True,
                    capture_output=True,
                )

            def digest(candidate: Path) -> subprocess.CompletedProcess:
                return subprocess.run(
                    [
                        "python3", "scripts/package-manager-runtime.py", "digest",
                        "--target", str(candidate),
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )

            first = digest(candidates[0])
            second = digest(candidates[1])
            self.assertEqual(first.returncode, 0)
            self.assertEqual(first.stdout, second.stdout)
            (candidates[1] / "manager/server.py").write_text("changed\n")
            changed = digest(candidates[1])
            self.assertEqual(changed.returncode, 0)
            self.assertNotEqual(first.stdout, changed.stdout)

            shutil.rmtree(candidates[1])
            shutil.copytree(candidates[0], candidates[1])
            (candidates[1] / "bin/fortify-manager-server").chmod(0o644)
            wrong_mode = digest(candidates[1])
            self.assertNotEqual(wrong_mode.returncode, 0)
            self.assertIn("mode is invalid", wrong_mode.stderr)

            shutil.rmtree(candidates[1])
            shutil.copytree(candidates[0], candidates[1])
            candidates[1].chmod(0o700)
            wrong_root_mode = digest(candidates[1])
            self.assertNotEqual(wrong_root_mode.returncode, 0)
            self.assertIn("root mode is invalid", wrong_root_mode.stderr)

    def test_runtime_staging_normalizes_root_mode_despite_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate"
            staged = subprocess.run(
                [
                    "bash", "-c", "umask 077; exec python3 \"$@\"", "stage",
                    "scripts/package-manager-runtime.py", "stage", "--source",
                    str(ROOT), "--target", str(candidate),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(staged.returncode, 0, staged.stderr)
            self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o755)

    def test_immutable_release_reinstall_collision_and_atomic_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            install_root = root / "install"
            releases = install_root / "releases"
            releases.mkdir(parents=True)
            candidates = [releases / f"candidate-{index}" for index in range(3)]
            for candidate in candidates:
                subprocess.run(
                    [
                        "python3", "scripts/package-manager-runtime.py", "stage",
                        "--source", str(ROOT), "--target", str(candidate),
                    ],
                    cwd=ROOT,
                    check=True,
                    capture_output=True,
                )
            digest = subprocess.run(
                [
                    "python3", "scripts/package-manager-runtime.py", "digest",
                    "--target", str(candidates[0]),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            release = releases / f"build-{digest}"
            candidates[0].rename(release)
            environment = os.environ | {
                "FORTIFY_MANAGER_LIBRARY_ONLY": "1",
                "FORTIFY_MANAGER_INSTALL_ROOT": str(install_root),
            }

            identical = subprocess.run(
                [
                    "bash", "-c",
                    'source scripts/fortify-manager; '
                    'publish_runtime_candidate "$1" "$2"',
                    "publish", str(candidates[1]), digest,
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(identical.returncode, 0, identical.stderr)
            self.assertFalse(candidates[1].exists())
            self.assertTrue(release.is_dir())

            (release / "manager/server.py").write_text("collision\n")
            collision = subprocess.run(
                [
                    "bash", "-c",
                    'source scripts/fortify-manager; '
                    'publish_runtime_candidate "$1" "$2"',
                    "publish", str(candidates[2]), digest,
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(collision.returncode, 0)
            self.assertIn("collision", collision.stderr)
            self.assertTrue(candidates[2].is_dir())
            self.assertEqual((release / "manager/server.py").read_text(), "collision\n")

            prior = releases / "prior"
            candidate = releases / "candidate"
            prior.mkdir()
            candidate.mkdir()
            (install_root / "current").symlink_to(prior)
            rollback = subprocess.run(
                [
                    "bash", "-c",
                    'source scripts/fortify-manager; prior=$(readlink "$INSTALL_ROOT/current"); '
                    'atomic_current "$1"; restore_current "$prior"',
                    "rollback", str(candidate),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(rollback.returncode, 0, rollback.stderr)
            self.assertEqual((install_root / "current").resolve(), prior.resolve())

    def test_activation_rollback_restores_prior_service_states(self):
        environment = os.environ | {"FORTIFY_MANAGER_LIBRARY_ONLY": "1"}
        restored = subprocess.run(
            [
                "bash", "-c",
                'source scripts/fortify-manager; '
                'systemctl() { printf "%s\\n" "$*"; }; '
                'restore_service_state manager.service 1; '
                'restore_service_state probe.service 0',
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
        )
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(
            restored.stdout.splitlines(),
            ["restart manager.service", "stop probe.service"],
        )

        failed = subprocess.run(
            [
                "bash", "-c",
                'source scripts/fortify-manager; systemctl() { return 1; }; '
                'restore_service_state manager.service 1',
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(failed.returncode, 0)

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
        self.assertEqual(endpoints["kind"], "EndpointSlice")
        self.assertEqual(endpoints["apiVersion"], "discovery.k8s.io/v1")
        self.assertEqual(endpoints["addressType"], "IPv4")
        self.assertEqual(endpoints["ports"][0]["port"], 8080)
        self.assertEqual(endpoints["endpoints"][0]["addresses"], ["10.0.0.10"])
        self.assertEqual(
            endpoints["metadata"]["labels"]["kubernetes.io/service-name"],
            "fortify-manager-host",
        )
        self.assertEqual(ingress["spec"]["rules"][0]["host"], "lab.fortifydemo.com")
        self.assertEqual(
            ingress["spec"]["tls"][0],
            {"hosts": ["lab.fortifydemo.com"], "secretName": "tls"},
        )
        self.assertEqual(
            ingress["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"],
            {"name": "fortify-manager-host", "port": {"number": 8080}},
        )

    def test_legacy_endpoint_renderer_is_explicit_compatibility_path(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "ingress.yaml"
            result = subprocess.run(
                [
                    "bash", "scripts/fortify-manager", "render-ingress",
                    "fortifydemo.com", "10.0.0.10", "8080", str(output),
                ],
                cwd=ROOT,
                env=os.environ | {"FORTIFY_MANAGER_ENDPOINT_API": "legacy"},
                capture_output=True,
                text=True,
            )
            documents = list(yaml.safe_load_all(output.read_text()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(documents[1]["kind"], "Endpoints")

    def test_backend_transition_removes_only_the_obsolete_named_resource(self):
        command = r'''
export FORTIFY_MANAGER_LIBRARY_ONLY=1
source scripts/fortify-manager
microk8s() { printf '%s\n' "$*" >>"$CALL_LOG"; }
remove_obsolete_backend "$ENDPOINT_API"
'''
        for endpoint_api, obsolete in (
            ("endpointslice", "delete endpoints fortify-manager-host"),
            ("legacy", "delete endpointslice fortify-manager-host"),
        ):
            with self.subTest(endpoint_api=endpoint_api):
                with tempfile.TemporaryDirectory() as directory:
                    call_log = Path(directory) / "calls"
                    result = subprocess.run(
                        ["bash", "-c", command], cwd=ROOT,
                        env=os.environ | {
                            "ENDPOINT_API": endpoint_api,
                            "CALL_LOG": str(call_log),
                        }, capture_output=True, text=True,
                    )
                    calls = call_log.read_text()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(obsolete, calls)
                self.assertIn("--ignore-not-found", calls)

    def test_uninstall_removes_both_backend_api_variants(self):
        script = (ROOT / "scripts/fortify-manager").read_text()
        self.assertIn(
            "service fortify-manager-host endpoints fortify-manager-host \\\n"
            "            endpointslice fortify-manager-host",
            script,
        )

    def run_route_diagnostic(
        self, dns_address="184.33.159.224", external_code="200"
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manager-ingress.yaml"
            subprocess.run(
                [
                    "bash", "scripts/fortify-manager", "render-ingress",
                    "fortifydemo.com", "10.0.0.10", "8080", str(manifest),
                ],
                cwd=ROOT, check=True, capture_output=True, text=True,
            )
            config_root = root / "config"
            config_root.mkdir()
            (config_root / "manager.toml").write_text(
                '[network]\npublic_address = "184.33.159.224"\n',
                encoding="utf-8",
            )
            command = r'''
export FORTIFY_MANAGER_LIBRARY_ONLY=1
source scripts/fortify-manager
microk8s() {
  case "$*" in
    *"get endpointslices"*) printf '%s\n' '{"items":[{"endpoints":[{"addresses":["10.0.0.10"],"conditions":{"ready":true}}],"ports":[{"port":8080}]}]}' ;;
    *"get ingress"*) printf '%s\n' '{"spec":{"ingressClassName":"public","tls":[{"hosts":["lab.fortifydemo.com"],"secretName":"tls"}],"rules":[{"host":"lab.fortifydemo.com","http":{"paths":[{"backend":{"service":{"name":"fortify-manager-host","port":{"number":8080}}}}]}}]}}' ;;
    *"get secret"*) printf '%s\n' 'secret/tls' ;;
    *) return 1 ;;
  esac
}
getent() { printf '%s STREAM lab.fortifydemo.com\n' "$FAKE_DNS_ADDRESS"; }
curl() {
  case " $* " in
    *" --resolve "*) printf '200' ;;
    *) printf '%s' "$FAKE_EXTERNAL_CODE" ;;
  esac
}
diagnose_manager_route
'''
            return subprocess.run(
                ["bash", "-c", command], cwd=ROOT,
                env=os.environ | {
                    "FORTIFY_MANAGER_MANIFEST_PATH": str(manifest),
                    "FORTIFY_MANAGER_CONFIG_ROOT": str(config_root),
                    "FAKE_DNS_ADDRESS": dns_address,
                    "FAKE_EXTERNAL_CODE": external_code,
                }, capture_output=True, text=True,
            )

    def test_route_diagnostics_report_five_independent_healthy_layers(self):
        result = self.run_route_diagnostic()
        self.assertEqual(result.returncode, 0, result.stderr)
        for layer in (
            "private-backend", "ingress-routing", "tls", "public-dns",
            "external-reachability",
        ):
            self.assertIn(f"layer={layer} state=healthy", result.stdout)

    def test_dns_mismatch_blocks_external_route_despite_private_https(self):
        result = self.run_route_diagnostic(dns_address="203.0.113.44")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("layer=tls state=healthy", result.stdout)
        self.assertIn("layer=public-dns state=failed", result.stdout)
        self.assertIn(
            "layer=external-reachability state=blocked detail=dns-mismatch",
            result.stdout,
        )

    def test_external_timeout_does_not_hide_healthy_private_layers(self):
        result = self.run_route_diagnostic(external_code="000")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("layer=private-backend state=healthy", result.stdout)
        self.assertIn("layer=tls state=healthy", result.stdout)
        self.assertIn("layer=public-dns state=healthy", result.stdout)
        self.assertIn(
            "layer=external-reachability state=unreachable",
            result.stdout,
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
            microk8s.write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                "  *api-resources*) echo endpointslices.discovery.k8s.io; exit 0 ;;\n"
                "  *) exit 1 ;;\n"
                "esac\n"
            )
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

    def test_network_config_records_distinct_addresses_idempotently(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.toml"
            first = root / "first.toml"
            second = root / "second.toml"
            source.write_text(
                '[server]\nhost = "0.0.0.0"\nport = 8080\n', encoding="utf-8"
            )
            command = r'''
export FORTIFY_MANAGER_LIBRARY_ONLY=1
source scripts/fortify-manager
write_network_config "$SOURCE" "$FIRST" fortifydemo.com 172.31.30.41 184.33.159.224
write_network_config "$FIRST" "$SECOND" fortifydemo.com 172.31.30.41 184.33.159.224
'''
            result = subprocess.run(
                ["bash", "-c", command],
                cwd=ROOT,
                env=os.environ
                | {"SOURCE": str(source), "FIRST": str(first), "SECOND": str(second)},
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(first.read_text(), second.read_text())
            document = tomllib.loads(second.read_text())
            self.assertEqual(document["network"]["domain"], "fortifydemo.com")
            self.assertEqual(
                document["network"]["private_backend_address"], "172.31.30.41"
            )
            self.assertEqual(document["network"]["public_address"], "184.33.159.224")

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
                preflight = app._operation_api._engine._preflight_provider()
                self.assertNotIn(
                    "LIFECYCLE_EVIDENCE_UNAVAILABLE",
                    preflight["readiness"]["deployment"]["blockers"],
                )
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
        self.assertIn("prior release and service were restored", script)
        self.assertIn('RUNTIME_ID="build-$RUNTIME_DIGEST"', script)
        self.assertIn('mv -Tf "$link" "$INSTALL_ROOT/current"', script)
        self.assertIn("immutable Manager release identity collision", script)
        upgrade = script[script.index("upgrade_runtime()") : script.index(
            'command="${1:-}"'
        )]
        self.assertLess(
            upgrade.index('"$CONFIG_ROOT/manager.toml" "$backup_root/manager.toml"'),
            upgrade.index('manager_config migrate'),
        )
        self.assertLess(
            upgrade.index('manager_config migrate'),
            upgrade.index('validate_release_start "$RUNTIME_RELEASE" 1'),
        )
        self.assertLess(
            upgrade.index('validate_release_start "$RUNTIME_RELEASE" 1'),
            upgrade.index('systemctl stop "$SERVICE_NAME"'),
        )
        rollback = upgrade[upgrade.index('restore_current "$prior"') :]
        self.assertLess(
            rollback.index('restore_current "$prior"'),
            rollback.index(
                'restore_service_state "$SERVICE_NAME" "$was_active"'
            ),
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

    def test_cluster_access_activation_is_verified_and_fail_closed(self):
        script = (ROOT / "scripts/fortify-manager").read_text()
        activation = script[script.index("install_cluster_access() {"):]
        for fragment in (
            "--approve-enable-rbac",
            "--approve-restart",
            "restart-required",
            "effective API-server authorization is ambiguous",
            "get secrets -n fortify",
            "get pods --subresource=log -n fortify",
            "get services -n default",
            "get --non-resource-url=/version",
            "list nodes",
            "list storageclasses.storage.k8s.io",
        ):
            self.assertIn(fragment, script)
        self.assertLess(
            activation.index('mv -f "$CLUSTER_ACCESS_ROOT/token"'),
            activation.index("microk8s enable rbac"),
        )
        self.assertLess(
            activation.index("verify_observer_authorization"),
            activation.index('mv -f "$token_candidate" "$CLUSTER_ACCESS_ROOT/token"'),
        )
        self.assertNotIn("kubectl get secret", activation.split("verify_observer_authorization")[0])

    def test_rbac_preflight_distinguishes_desired_and_restart_state(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            arguments = temporary / "kube-apiserver"
            fake_id = temporary / "id"
            fake_id.write_text("#!/usr/bin/env bash\nprintf '0\\n'\n")
            fake_id.chmod(0o755)
            environment = os.environ | {
                "PATH": f"{temporary}:{os.environ['PATH']}",
                "FORTIFY_MANAGER_APISERVER_ARGS": str(arguments),
                "FORTIFY_MANAGER_APISERVER_PID": str(os.getpid()),
            }

            arguments.write_text("--authorization-mode=AlwaysAllow\n")
            permissive = subprocess.run(
                ["bash", "scripts/fortify-manager", "rbac-preflight"],
                cwd=ROOT, env=environment, capture_output=True, text=True,
            )
            self.assertEqual(permissive.returncode, 2)
            self.assertIn("desired=permissive", permissive.stdout)

            arguments.write_text("--authorization-mode=Node,RBAC\n")
            os.utime(arguments, (1, 1))
            candidate = subprocess.run(
                ["bash", "scripts/fortify-manager", "rbac-preflight"],
                cwd=ROOT, env=environment, capture_output=True, text=True,
            )
            self.assertEqual(candidate.returncode, 0)
            self.assertIn("effective=verification-required", candidate.stdout)

            future = int(datetime.now(tz=timezone.utc).timestamp()) + 60
            os.utime(arguments, (future, future))
            restart = subprocess.run(
                ["bash", "scripts/fortify-manager", "rbac-preflight"],
                cwd=ROOT, env=environment, capture_output=True, text=True,
            )
            self.assertEqual(restart.returncode, 3)
            self.assertIn("action=restart-required", restart.stdout)

    def test_lifecycle_rbac_is_namespace_scoped_and_cannot_read_secrets(self):
        documents = list(yaml.safe_load_all(
            (ROOT / "packaging/microk8s/manager-lifecycle-rbac.yaml").read_text()
        ))
        self.assertFalse(any(item["kind"].endswith("ClusterRole") for item in documents))
        role = next(item for item in documents if item["kind"] == "Role")
        binding = next(item for item in documents if item["kind"] == "RoleBinding")
        token = next(
            item
            for item in documents
            if item["kind"] == "Secret"
            and item["metadata"]["name"] == "fortify-manager-lifecycle-token"
        )
        resources = {
            resource for rule in role["rules"] for resource in rule["resources"]
        }
        self.assertNotIn("secrets", resources)
        self.assertNotIn("pods", resources)
        self.assertNotIn("pods/exec", resources)
        self.assertNotIn("namespaces", resources)
        self.assertEqual(role["metadata"]["namespace"], "fortify")
        self.assertEqual(binding["metadata"]["namespace"], "fortify")
        self.assertEqual(token["type"], "kubernetes.io/service-account-token")

    def test_lifecycle_activation_success_is_idempotent_and_secret_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            config, kubeconfig, health_path, environment = (
                self.lifecycle_activation_fixture(Path(directory))
            )
            probe = socket.socket(socket.AF_UNIX)
            probe.bind(str(health_path))
            try:
                first = self.run_lifecycle_command("activate-lifecycle", environment)
                second = self.run_lifecycle_command("activate-lifecycle", environment)
            finally:
                probe.close()
            for result in (first, second):
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("lifecycle-execution: available", result.stdout)
                self.assertNotIn("lifecycle-token", result.stdout + result.stderr)
            self.assertIn("enabled = true", config.read_text())
            self.assertTrue(kubeconfig.is_file())
            self.assertEqual(kubeconfig.stat().st_mode & 0o777, 0o600)
            lifecycle_client = Path(directory) / "state/lifecycle-bin/microk8s"
            self.assertTrue(lifecycle_client.is_file())
            self.assertEqual(lifecycle_client.stat().st_mode & 0o777, 0o755)

    def test_lifecycle_activation_denial_partial_retry_and_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            config, kubeconfig, health_path, environment = (
                self.lifecycle_activation_fixture(Path(directory))
            )
            probe = socket.socket(socket.AF_UNIX)
            probe.bind(str(health_path))
            try:
                partial = self.run_lifecycle_command(
                    "activate-lifecycle", environment | {"FAKE_TOKEN_READY": "0"}
                )
                partial_config = config.read_text()
                denied = self.run_lifecycle_command(
                    "activate-lifecycle",
                    environment | {"FAKE_EXCESS_PERMISSION": "1"},
                )
                denied_config = config.read_text()
                rollback = self.run_lifecycle_command(
                    "activate-lifecycle",
                    environment | {"FAKE_RESTART_FAILURE": "1"},
                )
                rollback_config = config.read_text()
                retry = self.run_lifecycle_command("activate-lifecycle", environment)
            finally:
                probe.close()
            for result, failed_config in (
                (partial, partial_config),
                (denied, denied_config),
                (rollback, rollback_config),
            ):
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("enabled = false", failed_config)
            self.assertIn("credential was not issued", partial.stderr)
            self.assertIn("mandatory denial", denied.stderr)
            self.assertIn("rolled back", rollback.stderr)
            self.assertEqual(retry.returncode, 0, retry.stderr)
            self.assertTrue(kubeconfig.exists())

    def test_lifecycle_deactivation_revokes_mutation_without_state_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            config, kubeconfig, health_path, environment = (
                self.lifecycle_activation_fixture(Path(directory))
            )
            history = Path(directory) / "state/history.sqlite3"
            history.write_text("preserved")
            probe = socket.socket(socket.AF_UNIX)
            probe.bind(str(health_path))
            try:
                activated = self.run_lifecycle_command(
                    "activate-lifecycle", environment
                )
                deactivated = self.run_lifecycle_command(
                    "deactivate-lifecycle", environment
                )
            finally:
                probe.close()
            self.assertEqual(activated.returncode, 0, activated.stderr)
            self.assertEqual(deactivated.returncode, 0, deactivated.stderr)
            self.assertIn("enabled = false", config.read_text())
            self.assertFalse(kubeconfig.exists())
            self.assertFalse(
                (Path(directory) / "state/lifecycle-bin/microk8s").exists()
            )
            self.assertEqual(history.read_text(), "preserved")
            self.assertIn("operation history were preserved", deactivated.stdout)


if __name__ == "__main__":
    unittest.main()
