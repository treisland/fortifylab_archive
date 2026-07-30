"""Contract and semantic regression tests for all four control loops."""

from __future__ import annotations

import copy
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker, RefResolver

from manager.loop_contract_validation import validate_semantics


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = ROOT / "contracts" / "v1alpha1"
SCHEMA_ROOT = CONTRACT_ROOT / "schemas"
SCHEMAS = ("progress", "health", "event", "incident", "approval", "trace")


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


class LoopContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.examples = load_json(CONTRACT_ROOT / "examples.json")
        cls.common = load_json(SCHEMA_ROOT / "common.schema.json")

    def validator(self, name: str) -> Draft202012Validator:
        schema = load_json(SCHEMA_ROOT / f"{name}.schema.json")
        Draft202012Validator.check_schema(schema)
        resolver = RefResolver.from_schema(
            schema, store={self.common["$id"]: self.common}
        )
        return Draft202012Validator(
            schema, resolver=resolver, format_checker=FormatChecker()
        )

    def test_examples_cover_every_versioned_schema(self) -> None:
        self.assertEqual(set(self.examples), set(SCHEMAS))
        for name in SCHEMAS:
            with self.subTest(contract=name):
                self.validator(name).validate(self.examples[name])
                self.assertEqual(validate_semantics(self.examples[name]), [])

    def test_all_four_loops_are_allowed_and_unknown_loops_are_rejected(self) -> None:
        for loop in ("lifecycle", "health", "development", "improvement"):
            document = copy.deepcopy(self.examples["event"])
            document["loop"] = loop
            self.validator("event").validate(document)
        invalid = copy.deepcopy(self.examples["event"])
        invalid["loop"] = "aspm"
        self.assertTrue(list(self.validator("event").iter_errors(invalid)))

    def test_retry_timeout_cancellation_and_idempotency_are_bounded(self) -> None:
        progress = copy.deepcopy(self.examples["progress"])
        progress["attempt"] = 4
        self.assertIn("bounded retry", " ".join(validate_semantics(progress)))
        progress["attempt"] = 1
        progress["idempotency"] = {"mode": "non-idempotent", "key": None}
        self.assertIn("cannot be retried", " ".join(validate_semantics(progress)))
        progress["policy"]["timeoutSeconds"] = 0
        self.assertTrue(list(self.validator("progress").iter_errors(progress)))
        progress["policy"]["timeoutSeconds"] = 60
        progress["cancellation"] = {"requested": True, "supported": True}
        self.assertIn("request time", " ".join(validate_semantics(progress)))

    def test_root_causes_must_reference_observed_evidence(self) -> None:
        health = copy.deepcopy(self.examples["health"])
        health["rootCauseCheckId"] = "not-observed"
        self.assertIn("included check", " ".join(validate_semantics(health)))
        incident = copy.deepcopy(self.examples["incident"])
        incident["rootCause"]["eventId"] = "not-in-evidence"
        self.assertIn("included evidence", " ".join(validate_semantics(incident)))

    def test_approval_is_digest_bound_expiring_and_single_use(self) -> None:
        approval = copy.deepcopy(self.examples["approval"])
        approval["planDigest"] = "sha256:short"
        self.assertTrue(list(self.validator("approval").iter_errors(approval)))
        approval = copy.deepcopy(self.examples["approval"])
        approval["singleUse"] = False
        self.assertTrue(list(self.validator("approval").iter_errors(approval)))
        approval = copy.deepcopy(self.examples["approval"])
        approval["expiresAt"] = approval["createdAt"]
        self.assertIn("expiry", " ".join(validate_semantics(approval)))
        approval = copy.deepcopy(self.examples["approval"])
        other_digest = "sha256:" + ("b" * 64)
        self.assertIn(
            "requested plan digest",
            " ".join(
                validate_semantics(approval, expected_plan_digest=other_digest)
            ),
        )
        after_expiry = datetime(2026, 7, 30, 13, 2, tzinfo=timezone.utc)
        self.assertIn(
            "cannot authorize",
            " ".join(validate_semantics(approval, at=after_expiry)),
        )
        approval["state"] = "consumed"
        self.assertIn("consumption time", " ".join(validate_semantics(approval)))

    def test_redaction_and_provenance_fail_closed(self) -> None:
        trace = copy.deepcopy(self.examples["trace"])
        trace["entries"][0]["fields"]["password"] = "example"
        self.assertTrue(list(self.validator("trace").iter_errors(trace)))
        self.assertIn("sensitive key", " ".join(validate_semantics(trace)))
        trace = copy.deepcopy(self.examples["trace"])
        trace["entries"][0]["message"] = "Authorization: Bearer abc.def.ghi"
        self.assertIn("sensitive value", " ".join(validate_semantics(trace)))
        trace = copy.deepcopy(self.examples["trace"])
        del trace["provenance"]
        self.assertTrue(list(self.validator("trace").iter_errors(trace)))


if __name__ == "__main__":
    unittest.main()
