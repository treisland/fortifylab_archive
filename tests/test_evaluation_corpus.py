"""Deterministic validation for the versioned loop evaluation corpus."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
EVALUATION_ROOT = ROOT / "evaluations" / "v1alpha1"
REQUIRED_CASES = {
    "healthy-component",
    "database-unavailable",
    "database-authentication-failure",
    "application-not-ready",
    "slow-initialization",
    "path-symlink-attack",
    "tls-verification-failure",
    "missing-lim-pool",
    "scanner-registration-failure",
    "retry-exhaustion",
    "duplicate-event",
    "secret-leakage",
    "persistent-data-deletion",
}
# Changing case inputs or expected outcomes requires an intentional corpus version
# update and a review of this digest.
EXPECTED_CANONICAL_SHA256 = (
    "5c7279bef8c5d1f593c9e6ef5c86c2c79c6b5eaabeff5249679d35de0d0cf410"
)


def load_json(name: str) -> dict:
    with (EVALUATION_ROOT / name).open(encoding="utf-8") as stream:
        return json.load(stream)


def canonical_bytes(document: dict) -> bytes:
    return json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


class EvaluationCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = load_json("schema.json")
        cls.corpus = load_json("cases.json")
        Draft202012Validator.check_schema(cls.schema)
        Draft202012Validator(cls.schema).validate(cls.corpus)

    def test_required_cases_are_present_once(self) -> None:
        case_ids = [case["id"] for case in self.corpus["cases"]]
        self.assertEqual(set(case_ids), REQUIRED_CASES)
        self.assertEqual(len(case_ids), len(set(case_ids)))

    def test_every_case_defines_a_non_destructive_safe_action(self) -> None:
        for case in self.corpus["cases"]:
            with self.subTest(case=case["id"]):
                action = case["expected"]["safeAction"]
                self.assertFalse(action["destructive"])
                if action["requiresApproval"]:
                    self.assertFalse(
                        action["code"].startswith(("delete-", "execute-"))
                    )

    def test_redaction_assertions_are_fail_closed_and_fixture_safe(self) -> None:
        serialized = canonical_bytes(self.corpus).decode("ascii").lower()
        for case in self.corpus["cases"]:
            with self.subTest(case=case["id"]):
                redaction = case["expected"]["redaction"]
                if redaction["required"]:
                    self.assertTrue(redaction["categories"])
                    self.assertTrue(redaction["forbiddenSubstrings"])
                else:
                    self.assertEqual(redaction["categories"], [])
                    self.assertEqual(redaction["forbiddenSubstrings"], [])
                for marker in redaction["forbiddenSubstrings"]:
                    self.assertEqual(serialized.count(marker.lower()), 1)

    def test_canonical_corpus_is_stable(self) -> None:
        digest = hashlib.sha256(canonical_bytes(self.corpus)).hexdigest()
        self.assertEqual(digest, EXPECTED_CANONICAL_SHA256)

    def test_classification_lookup_is_order_independent(self) -> None:
        expected = {
            case["id"]: case["expected"]["classification"]
            for case in self.corpus["cases"]
        }
        actual = {
            case["id"]: case["expected"]["classification"]
            for case in reversed(self.corpus["cases"])
        }
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
