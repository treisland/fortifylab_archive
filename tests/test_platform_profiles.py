"""Versioned platform profile contract and fail-closed regression tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from manager.api import ManagerAPI, PROFILE_PATH
from manager.component_registry import ComponentRegistry, RegistryError
from manager.platform_profiles import PlatformProfile, PlatformProfileError


ROOT = Path(__file__).resolve().parents[1]


def request(app, path=PROFILE_PATH):
    response = {}

    def start_response(status, headers):
        response["status"] = status
        response["headers"] = dict(headers)

    body = b"".join(app({"REQUEST_METHOD": "GET", "PATH_INFO": path}, start_response))
    response["json"] = json.loads(body)
    return response


class PlatformProfileTests(unittest.TestCase):
    def test_baseline_schema_scope_evidence_and_registry_pins(self):
        profile = PlatformProfile.load("fortify-24.4-eval.1")
        schema = json.loads(
            (ROOT / "profiles/schemas/platform-profile.schema.json").read_text()
        )
        Draft202012Validator(schema).validate(profile.document)
        self.assertEqual(profile.maturity, "experimental")
        self.assertFalse(profile.document["scope"]["aspm"])
        self.assertEqual(profile.document["cleanInstall"]["status"], "not-run")
        self.assertEqual(profile.document["upgrade"]["allowedSources"], [])
        self.assertEqual(
            ComponentRegistry.load().profile.document, profile.document
        )

    def test_unknown_profile_fails_closed_without_support_claim(self):
        with self.assertRaisesRegex(
            PlatformProfileError, "unavailable or malformed"
        ):
            PlatformProfile.load("unknown-profile")
        response = request(
            ManagerAPI(
                registry_loader=lambda: (_ for _ in ()).throw(
                    RegistryError("unsafe local detail")
                )
            )
        )
        self.assertEqual(response["status"], "503 Service Unavailable")
        self.assertEqual(
            response["json"],
            {"code": "REGISTRY_UNAVAILABLE", "message": "platform profile is unavailable"},
        )

    def test_static_evidence_cannot_claim_validated_maturity(self):
        source = json.loads(
            (ROOT / "profiles/fortify-24.4-eval.1.json").read_text()
        )
        source["maturity"] = "validated"
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            (directory / "schemas").mkdir()
            (directory / "evidence").mkdir()
            for name in ("platform-profile.schema.json", "release-evidence.schema.json"):
                (directory / "schemas" / name).write_text(
                    (ROOT / "profiles/schemas" / name).read_text(), encoding="utf-8"
                )
            (directory / "evidence/fortify-24.4-eval.1.json").write_text(
                (ROOT / "profiles/evidence/fortify-24.4-eval.1.json").read_text(),
                encoding="utf-8",
            )
            (directory / "fortify-24.4-eval.1.json").write_text(
                json.dumps(source), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                PlatformProfileError, "licensed clean-install evidence"
            ):
                PlatformProfile.load("fortify-24.4-eval.1", directory)

    def test_registry_pin_drift_fails_closed(self):
        document = json.loads(
            (ROOT / "registry/components.json").read_text(encoding="utf-8")
        )
        document["components"][0]["version"]["chart"] = "unknown"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", encoding="utf-8"
        ) as stream:
            json.dump(document, stream)
            stream.flush()
            with self.assertRaisesRegex(
                RegistryError, "does not match platform profile"
            ):
                ComponentRegistry.load(Path(stream.name))

    def test_profile_api_returns_selected_contract(self):
        response = request(ManagerAPI())
        self.assertEqual(response["status"], "200 OK")
        self.assertEqual(response["json"]["id"], "fortify-24.4-eval.1")
        self.assertEqual(response["json"]["maturity"], "experimental")
        self.assertNotIn("vendorSupported", response["json"])
