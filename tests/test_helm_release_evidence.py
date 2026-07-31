"""Protection and collection contracts for sanitized Helm evidence."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from manager.component_registry import ComponentRegistry
from manager.helm_release_evidence import (
    API_VERSION,
    HelmEvidenceUnavailable,
    ProtectedHelmSnapshot,
    collect,
)


NOW = datetime(2026, 7, 31, 16, 0, tzinfo=timezone.utc)


def document(observed=NOW.isoformat().replace("+00:00", "Z")):
    return {
        "apiVersion": API_VERSION,
        "kind": "HelmReleaseSnapshot",
        "observedAt": observed,
        "releases": [{
            "name": "mysql", "revision": 1, "status": "deployed",
            "chartVersion": "9.19.0", "appVersion": "8.0.36",
        }],
    }


class HelmReleaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "snapshot.json"

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, value):
        self.path.write_text(json.dumps(value), encoding="utf-8")
        self.path.chmod(0o640)

    def loader(self):
        return ProtectedHelmSnapshot(
            self.path, expected_uid=os.getuid(), expected_gid=os.getgid(), now=lambda: NOW
        )

    def test_valid_snapshot_and_history_are_accepted(self):
        self.write(document())
        self.assertEqual(self.loader().document()["releases"][0]["revision"], 1)

    def test_stale_wrong_mode_symlink_and_extra_fields_fail_closed(self):
        cases = []
        stale = document((NOW - timedelta(seconds=301)).isoformat().replace("+00:00", "Z"))
        cases.append(("stale", stale, None))
        malicious = document()
        malicious["releases"][0]["values"] = {"password": "secret"}
        cases.append(("extra", malicious, None))
        cases.append(("mode", document(), 0o644))
        for name, value, mode in cases:
            with self.subTest(name=name):
                self.write(value)
                if mode is not None:
                    self.path.chmod(mode)
                with self.assertRaises(HelmEvidenceUnavailable):
                    self.loader().document()
        target = Path(self.temporary.name) / "target"
        target.write_text(json.dumps(document()), encoding="utf-8")
        target.chmod(0o640)
        self.path.unlink(missing_ok=True)
        self.path.symlink_to(target)
        with self.assertRaises(HelmEvidenceUnavailable):
            self.loader().document()
        self.path.unlink()
        self.path.write_bytes(b"{" + b"x" * 65536)
        self.path.chmod(0o640)
        with self.assertRaises(HelmEvidenceUnavailable):
            self.loader().document()

        self.write(document())
        wrong_owner = ProtectedHelmSnapshot(
            self.path,
            expected_uid=os.getuid() + 1,
            expected_gid=os.getgid(),
            now=lambda: NOW,
        )
        with self.assertRaises(HelmEvidenceUnavailable):
            wrong_owner.document()

    def test_collector_uses_default_driver_and_projects_only_safe_history(self):
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            if command[3] != "mysql":
                return SimpleNamespace(
                    returncode=1, stdout=b"", stderr=b"Error: release: not found"
                )
            payload = [{
                "revision": 1, "status": "deployed", "chart": "mysql-9.19.0",
                "app_version": "8.0.36", "description": "must-not-project",
            }]
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload).encode(), stderr=b"")

        with patch.dict(os.environ, {"HELM_DRIVER": "configmap"}), patch(
            "manager.helm_release_evidence.subprocess.run", side_effect=run
        ), patch("manager.helm_release_evidence.grp.getgrnam", return_value=SimpleNamespace(gr_gid=os.getgid())), patch(
            "manager.helm_release_evidence.os.chown"
        ):
            collect(self.path, ComponentRegistry.load())
        self.assertTrue(all("HELM_DRIVER" not in kwargs["env"] for _, kwargs in calls))
        snapshot = json.loads(self.path.read_text())
        self.assertEqual(set(snapshot["releases"][0]), {"name", "revision", "status", "chartVersion", "appVersion"})
        self.assertNotIn("description", json.dumps(snapshot))

    def test_collector_does_not_turn_authorization_failure_into_absence(self):
        denied = SimpleNamespace(returncode=1, stdout=b"", stderr=b"forbidden")
        with patch(
            "manager.helm_release_evidence.subprocess.run", return_value=denied
        ):
            with self.assertRaises(HelmEvidenceUnavailable):
                collect(self.path, ComponentRegistry.load())
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
