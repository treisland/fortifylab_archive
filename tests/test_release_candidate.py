"""Release candidate safety, evidence, and reproducibility tests."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from manager.release_candidate import (
    ReleaseCandidateError,
    _scan_files,
    build_candidate,
)


ROOT = Path(__file__).resolve().parents[1]


class ReleaseCandidateTests(unittest.TestCase):
    def test_candidate_is_bounded_deterministic_and_no_go_without_live_evidence(self):
        with tempfile.TemporaryDirectory() as first_name, tempfile.TemporaryDirectory() as second_name:
            first = build_candidate(ROOT, Path(first_name), epoch=0)
            second = build_candidate(ROOT, Path(second_name), epoch=0)
            self.assertEqual(first.verdict, "no-go")
            self.assertEqual(
                hashlib.sha256(first.archive.read_bytes()).hexdigest(),
                hashlib.sha256(second.archive.read_bytes()).hexdigest(),
            )
            manifest = json.loads(first.manifest.read_text(encoding="utf-8"))
            self.assertEqual(manifest["semanticVersionRecommendation"], "0.4.0")
            self.assertFalse(manifest["scope"]["aspm"])
            self.assertLessEqual(
                sum(item["bytes"] for item in manifest["files"]),
                manifest["bounds"]["maximumTotalBytes"],
            )
            gates = json.loads(
                (first.directory / "go-no-go.json").read_text(encoding="utf-8")
            )
            self.assertEqual(gates["verdict"], "no-go")
            self.assertEqual(
                next(item for item in gates["gates"] if item["id"] == "licensed-lifecycle")["status"],
                "not-run",
            )
            evaluation_gate = next(
                item for item in gates["gates"]
                if item["id"] == "verified-platform-lifecycle-evaluation"
            )
            self.assertEqual(evaluation_gate["status"], "failed")
            evaluation = json.loads(
                (
                    first.directory
                    / "verified-platform-lifecycle-evaluation.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(evaluation["deterministicEvidence"]["status"], "passed")
            self.assertEqual(evaluation["liveEvidence"]["status"], "failed")

    def test_sensitive_content_is_rejected_without_echoing_it(self):
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            secret = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456"
            (directory / "unsafe.txt").write_text(secret, encoding="utf-8")
            with self.assertRaises(ReleaseCandidateError) as raised:
                _scan_files(directory, ["unsafe.txt"])
            self.assertNotIn(secret, str(raised.exception))

    def test_live_gate_requires_every_exact_profile_check(self):
        profile = {
            "profileId": "test",
            "evidenceLevel": "licensed-live",
            "checks": {
                "cleanInstall": "passed",
                "upgrade": "passed",
                "backupRestore": "passed",
            },
            "knownLimitations": ["fixture"],
        }
        with tempfile.TemporaryDirectory() as directory_name:
            with patch("manager.release_candidate._profile_matrix", return_value=[profile]):
                result = build_candidate(ROOT, Path(directory_name), epoch=0)
            gates = json.loads(
                (result.directory / "go-no-go.json").read_text(encoding="utf-8")
            )
            lifecycle = next(
                item for item in gates["gates"] if item["id"] == "licensed-lifecycle"
            )
            self.assertEqual(lifecycle["status"], "passed")
            self.assertEqual(result.verdict, "no-go")


if __name__ == "__main__":
    unittest.main()
