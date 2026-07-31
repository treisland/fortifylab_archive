"""Unit tests for the shared supervisor autonomy policy contract."""

from __future__ import annotations

import datetime
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "supervisor"))

from autonomy_policy import (  # noqa: E402
    ACTIONS,
    AutonomyPolicyError,
    load_policy,
    migration_policy,
)


class AutonomyPolicyTests(unittest.TestCase):
    NOW = datetime.datetime(2026, 7, 31, tzinfo=datetime.timezone.utc)

    def write_policy(self, document: dict[str, object]) -> Path:
        path = Path(self.temporary.name) / "autonomy-policy.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        path.chmod(0o600)
        return path

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_missing_configuration_preserves_assisted_migration_behavior(self) -> None:
        policy = migration_policy()
        self.assertFalse(policy.configured)
        self.assertEqual(policy.profile, "assisted")
        self.assertEqual(policy.generation, 0)
        self.assertEqual(policy.decision("start_next_issue"), "auto")
        self.assertEqual(policy.decision("close_completed_issue"), "auto")
        self.assertEqual(policy.decision("advance_milestone"), "auto")
        self.assertEqual(policy.decision("retry_idempotent_failure"), "auto")
        self.assertEqual(policy.decision("merge_pull_request"), "approval")

    def test_manual_profile_and_safe_override(self) -> None:
        policy = load_policy(
            self.write_policy(
                {
                    "schema_version": "fortify.autonomy/v1alpha1",
                    "profile": "manual",
                    "generation": 4,
                    "actions": {"start_next_issue": "disabled"},
                }
            ),
            now=self.NOW,
        )
        self.assertEqual(policy.decision("start_next_issue"), "disabled")
        self.assertEqual(policy.decision("merge_pull_request"), "approval")
        self.assertEqual(set(policy.status()["decisions"]), set(ACTIONS))

    def test_autonomous_profile_is_time_bounded(self) -> None:
        base = {
            "schema_version": "fortify.autonomy/v1alpha1",
            "profile": "autonomous",
            "generation": 8,
        }
        with self.assertRaisesRegex(AutonomyPolicyError, "future expires_at"):
            load_policy(self.write_policy(base), now=self.NOW)
        base["expires_at"] = "2026-08-01T00:00:00Z"
        policy = load_policy(self.write_policy(base), now=self.NOW)
        self.assertEqual(policy.decision("merge_pull_request"), "auto")
        base["expires_at"] = "2026-07-30T00:00:00Z"
        with self.assertRaisesRegex(AutonomyPolicyError, "expired"):
            load_policy(self.write_policy(base), now=self.NOW)

    def test_unknown_and_unsafe_values_fail_closed_without_path_or_value(self) -> None:
        base: dict[str, object] = {
            "schema_version": "fortify.autonomy/v1alpha1",
            "profile": "assisted",
            "generation": 1,
        }
        base["actions"] = {"launch_aspm": "auto"}
        with self.assertRaisesRegex(AutonomyPolicyError, "Unknown autonomy action"):
            load_policy(self.write_policy(base), now=self.NOW)
        base["actions"] = {"secret_operations": "auto"}
        with self.assertRaisesRegex(
            AutonomyPolicyError, "secret_operations must require approval"
        ):
            load_policy(self.write_policy(base), now=self.NOW)
        base["profile"] = "unrestricted"
        base["actions"] = {}
        with self.assertRaisesRegex(AutonomyPolicyError, "Unknown autonomy profile"):
            load_policy(self.write_policy(base), now=self.NOW)

    def test_digest_is_stable_across_key_order_and_loads(self) -> None:
        first = {
            "schema_version": "fortify.autonomy/v1alpha1",
            "profile": "assisted",
            "generation": 2,
            "actions": {
                "merge_pull_request": "disabled",
                "start_next_issue": "approval",
            },
        }
        second = {
            "actions": {
                "start_next_issue": "approval",
                "merge_pull_request": "disabled",
            },
            "generation": 2,
            "profile": "assisted",
            "schema_version": "fortify.autonomy/v1alpha1",
        }
        first_digest = load_policy(self.write_policy(first), now=self.NOW).digest
        second_digest = load_policy(self.write_policy(second), now=self.NOW).digest
        self.assertEqual(first_digest, second_digest)
        self.assertRegex(first_digest, r"^[0-9a-f]{64}$")

    def test_file_permissions_are_enforced(self) -> None:
        path = self.write_policy(
            {
                "schema_version": "fortify.autonomy/v1alpha1",
                "profile": "assisted",
                "generation": 1,
            }
        )
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(AutonomyPolicyError, "group/world"):
            load_policy(path, now=self.NOW)


if __name__ == "__main__":
    unittest.main()
