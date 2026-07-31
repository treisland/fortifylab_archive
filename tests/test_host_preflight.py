"""Concrete, sanitized host preflight collection and projection tests."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

from manager.component_registry import ComponentRegistry
from manager.host_preflight import (
    CHECK_IDS, CollectionSettings, HostPreflightEvidence, HostPreflightProbe,
    _certificate_ready, _protected_regular, _registry_auth_ready, collect, write,
)
from manager.preflight import PreflightEngine


class HostPreflightTests(unittest.TestCase):
    def setUp(self):
        self.registry = ComponentRegistry.load()

    def document(self, *, states=None, facts=None):
        return {
            "apiVersion": "fortifylab.io/v1alpha1",
            "kind": "HostPreflightEvidence",
            "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "checks": {item: "pass" for item in CHECK_IDS} | (states or {}),
            "facts": facts or {
                "cpuCores": 16, "memoryGiB": 64, "storageGiB": 200,
                "remainingCpuCores": 8, "remainingMemoryGiB": 32,
                "remainingStorageGiB": 100, "osFamily": "ubuntu",
                "osVersion": "24.04", "kernel": "6.8.0", "architecture": "amd64",
                "microk8sVersion": "1.28", "ec2": True,
            },
        }

    def probe(self, document):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "host-preflight.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        path.chmod(0o640)
        return HostPreflightProbe(HostPreflightEvidence(
            path, expected_uid=os.geteuid(), expected_gid=os.getegid()
        ))

    def test_report_separates_platform_capacity_and_mutation_authorization(self):
        report = PreflightEngine(
            self.registry, self.probe(self.document()), capability_provider=None
        ).document()
        self.assertTrue(report["platformReadiness"]["ready"])
        self.assertFalse(report["mutationAuthorization"]["ready"])
        self.assertEqual(
            report["mutationAuthorization"]["blockers"],
            ["LIFECYCLE_EVIDENCE_UNAVAILABLE"],
        )
        self.assertEqual(report["capacity"]["remainingMemoryGiB"], 32)
        self.assertEqual(report["host"]["architecture"], "amd64")
        self.assertTrue(report["host"]["ec2"])

    def test_capacity_addon_port_and_compatibility_failures_recover(self):
        states = {
            "host-capacity": "fail", "microk8s-addons": "fail",
            "ingress": "fail", "compatibility": "fail",
        }
        first = PreflightEngine(self.registry, self.probe(self.document(states=states))).document()
        self.assertFalse(first["platformReadiness"]["ready"])
        self.assertEqual(len(first["platformReadiness"]["blockers"]), 4)
        recovered = PreflightEngine(self.registry, self.probe(self.document())).document()
        self.assertTrue(recovered["platformReadiness"]["ready"])

    def test_evidence_rejects_weak_permissions_paths_and_extra_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            document = self.document()
            document["hostname"] = "must-not-escape"
            path.write_text(json.dumps(document), encoding="utf-8")
            path.chmod(0o640)
            with self.assertRaisesRegex(ValueError, "malformed"):
                HostPreflightEvidence(path, expected_uid=os.geteuid(), expected_gid=os.getegid()).document()
            path.write_text(json.dumps(self.document()), encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "protected"):
                HostPreflightEvidence(path, expected_uid=os.geteuid(), expected_gid=os.getegid()).document()
            path.chmod(0o640)
            with self.assertRaisesRegex(ValueError, "protected"):
                HostPreflightEvidence(path, expected_uid=os.geteuid() + 1,
                                      expected_gid=os.getegid()).document()

    def test_stale_evidence_fails_closed(self):
        document = self.document()
        document["generatedAt"] = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).isoformat().replace("+00:00", "Z")
        probe = self.probe(document)
        report = PreflightEngine(self.registry, probe).document()
        self.assertFalse(report["platformReadiness"]["ready"])
        self.assertTrue(all(item["status"] == "fail" for item in report["items"]))

    def test_group_lookup_is_deferred_and_missing_group_fails_evidence_closed(self):
        evidence = HostPreflightEvidence(Path("/not/read/during/construction"))
        with patch("manager.host_preflight.grp.getgrnam", side_effect=KeyError):
            with self.assertRaisesRegex(ValueError, "unavailable"):
                evidence.document()

    def test_atomic_write_ignores_hostile_destination_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = root / "staging"
            destination_dir = root / "state"
            staging.mkdir(mode=0o700)
            destination_dir.mkdir()
            victim = root / "victim"
            victim.write_text("unchanged", encoding="utf-8")
            destination = destination_dir / "host-preflight.json"
            destination.symlink_to(victim)
            write(
                destination, self.document(), staging=staging,
                expected_uid=os.geteuid(), expected_gid=os.getegid(),
            )
            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")
            self.assertFalse(destination.is_symlink())
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o640)

    def test_secret_inputs_require_regular_private_trusted_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input"
            path.write_text("value", encoding="utf-8")
            path.chmod(0o600)
            trusted = frozenset({os.geteuid()})
            self.assertTrue(_protected_regular(path, trusted))
            path.chmod(0o644)
            self.assertFalse(_protected_regular(path, trusted))
            path.unlink()
            path.symlink_to("missing")
            self.assertFalse(_protected_regular(path, trusted))

    def test_registry_auth_requires_structural_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            trusted = frozenset({os.geteuid()})
            path.write_text('{"auths":{"registry.example":{"auth":"redacted"}}}', encoding="utf-8")
            path.chmod(0o600)
            self.assertTrue(_registry_auth_ready(path, trusted))
            path.write_text("{}", encoding="utf-8")
            self.assertFalse(_registry_auth_ready(path, trusted))

    def test_certificate_requires_valid_unexpired_domain_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "tls.crt"
            path.write_text("not a certificate", encoding="utf-8")
            self.assertFalse(_certificate_ready(path, "example.test"))
            names = tuple(("DNS", name) for name in (
                "example.test", "lab.example.test", "ssc.example.test",
                "lim.example.test", "sast.example.test", "dast.example.test",
            ))
            valid = {
                "notAfter": (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%b %d %H:%M:%S %Y GMT"),
                "subjectAltName": names,
            }
            with patch("manager.host_preflight.ssl._ssl._test_decode_cert", return_value=valid):
                self.assertTrue(_certificate_ready(path, "example.test"))
            expired = valid | {
                "notAfter": (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%b %d %H:%M:%S %Y GMT")
            }
            with patch("manager.host_preflight.ssl._ssl._test_decode_cert", return_value=expired):
                self.assertFalse(_certificate_ready(path, "example.test"))

    def test_collector_maps_insufficient_and_unsupported_host_without_output(self):
        def runner(command):
            if command[1:] == ("version",):
                return True, "MicroK8s v1.30.2 host=private"
            if command[1] == "status":
                return True, "dns: enabled\nhostpath-storage: enabled\nhelm3: enabled\ningress: enabled\nregistry: enabled\n"
            if command[-3:] == ("storageclass", "-o", "json"):
                return True, '{"items":[]}'
            return True, "private command output"

        settings = CollectionSettings(
            domain="example.test", public_address="192.0.2.1",
            license_file=Path("/missing/license"),
            registry_auth_file=Path("/missing/auth"),
            tls_certificate_file=Path("/missing/cert"),
            trusted_uids=frozenset({os.geteuid()}),
        )

        with patch("manager.host_preflight.os.cpu_count", return_value=2), \
             patch("manager.host_preflight._memory_gib", return_value=4), \
             patch("manager.host_preflight.shutil.disk_usage", return_value=type("D", (), {"free": 10 * 1024**3})()), \
             patch("manager.host_preflight._os_release", return_value=("unsupported", "1")), \
             patch("manager.host_preflight.platform.machine", return_value="aarch64"), \
             patch("manager.host_preflight._ports_reachable", return_value=False), \
             patch("manager.host_preflight._dns_matches", return_value=False):
            document = collect(self.registry, settings, runner=runner)
        self.assertEqual(document["checks"]["host-capacity"], "fail")
        self.assertEqual(document["checks"]["compatibility"], "fail")
        self.assertEqual(document["checks"]["ingress"], "fail")
        serialized = json.dumps(document)
        self.assertNotIn("private", serialized)
        self.assertNotIn("path", serialized.lower())


if __name__ == "__main__":
    unittest.main()
