"""Effective Manager capability API and fail-closed browser contracts."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from manager.capabilities import CapabilityProvider
from manager.dashboard import CAPABILITIES_PATH, DashboardApp, password_verifier
from tests.test_dashboard import request


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)


def states(document):
    return {item["id"]: item for item in document["capabilities"]}


class CapabilityProviderTests(unittest.TestCase):
    def provider(self, **options):
        return CapabilityProvider(clock=lambda: NOW, **options)

    def test_enabled_contract_is_schema_valid_and_mutation_is_explicit(self):
        document = self.provider(
            observation_state=lambda: "available",
            functional_health_configured=True,
            functional_health_state=lambda: True,
            lifecycle_enabled=True,
            lifecycle_configured=True,
            lifecycle_credential_state=lambda: True,
            lifecycle_authorization_state=lambda: True,
            lifecycle_adapter_state=lambda: True,
            approvals_configured=True,
            approvals_state=lambda: True,
            recovery_configured=True,
            recovery_state=lambda: True,
            upgrades_configured=True,
            upgrades_state=lambda: True,
            secrets_configured=True,
            secrets_state=lambda: True,
            notifications_configured=True,
            notifications_state=lambda: True,
        ).document()
        schema = json.loads(
            (ROOT / "registry/schemas/manager-capabilities.schema.json").read_text()
        )
        Draft202012Validator(schema).validate(document)
        self.assertEqual(document["contractVersion"], "1.0")
        self.assertEqual(
            set(states(document)),
            {
                "observation", "functional-health", "lifecycle-execution",
                "approvals", "backup-restore", "upgrades",
                "secret-workflows", "notifications",
            },
        )
        self.assertTrue(states(document)["lifecycle-execution"]["canMutate"])
        self.assertEqual(
            states(document)["lifecycle-execution"]["prerequisites"],
            ["OBSERVATION_AVAILABLE", "LIFECYCLE_SERVICE_COMPOSED"],
        )

    def test_functional_health_requires_successful_live_handshake(self):
        unavailable = states(self.provider(
            observation_state=lambda: "available",
            functional_health_configured=True,
            functional_health_state=lambda: False,
        ).document())["functional-health"]
        self.assertEqual(unavailable["state"], "temporarily-unavailable")
        self.assertEqual(unavailable["code"], "FUNCTIONAL_PROBE_HANDSHAKE_FAILED")
        recovered = states(self.provider(
            observation_state=lambda: "available",
            functional_health_configured=True,
            functional_health_state=lambda: True,
        ).document())["functional-health"]
        self.assertEqual(recovered["state"], "available")

    def test_disabled_and_intentionally_unconfigured_states_explain_failure(self):
        document = self.provider().document()
        capability = states(document)
        self.assertEqual(capability["observation"]["state"], "not-configured")
        self.assertEqual(capability["lifecycle-execution"]["state"], "disabled")
        self.assertEqual(capability["lifecycle-execution"]["code"], "OPERATIONS_DISABLED")
        self.assertFalse(capability["lifecycle-execution"]["canMutate"])
        self.assertEqual(capability["backup-restore"]["state"], "not-configured")
        self.assertEqual(capability["upgrades"]["state"], "not-configured")

    def test_partial_observation_failure_temporarily_disables_mutation(self):
        document = self.provider(
            observation_state=lambda: "unavailable",
            lifecycle_enabled=True,
            lifecycle_configured=True,
            lifecycle_credential_state=lambda: True,
            lifecycle_authorization_state=lambda: True,
            lifecycle_adapter_state=lambda: True,
            approvals_configured=True,
        ).document()
        capability = states(document)
        self.assertEqual(
            capability["lifecycle-execution"]["state"],
            "temporarily-unavailable",
        )
        self.assertEqual(
            capability["lifecycle-execution"]["code"], "OBSERVER_DISCONNECTED"
        )
        self.assertTrue(capability["observation"]["canInspect"])
        self.assertFalse(capability["lifecycle-execution"]["canMutate"])

    def test_unauthorized_is_sanitized_and_fails_closed(self):
        document = self.provider(
            observation_state=lambda: "available",
            lifecycle_enabled=True,
            lifecycle_configured=True,
            lifecycle_credential_state=lambda: True,
            lifecycle_authorization_state=lambda: True,
            lifecycle_adapter_state=lambda: True,
            authorized=lambda _identity, capability: capability != "lifecycle-execution",
        ).document(object())
        lifecycle = states(document)["lifecycle-execution"]
        self.assertEqual(lifecycle["state"], "unauthorized")
        self.assertEqual(lifecycle["code"], "CAPABILITY_UNAUTHORIZED")
        self.assertNotIn("identity", json.dumps(document).lower())

    def test_recovery_is_visible_on_next_bounded_document(self):
        observation = ["unavailable"]
        provider = self.provider(
            observation_state=lambda: observation[0],
            lifecycle_enabled=True,
            lifecycle_configured=True,
            lifecycle_credential_state=lambda: True,
            lifecycle_authorization_state=lambda: True,
            lifecycle_adapter_state=lambda: True,
        )
        self.assertFalse(
            states(provider.document())["lifecycle-execution"]["canMutate"]
        )
        observation[0] = "available"
        recovered = provider.document()
        self.assertTrue(states(recovered)["lifecycle-execution"]["canMutate"])
        self.assertEqual(recovered["refreshAfterSeconds"], 30)

    def test_composed_runtime_services_fail_closed_and_recover(self):
        credential = [False]
        adapter = [True]
        provider = self.provider(
            observation_state=lambda: "available",
            lifecycle_enabled=True,
            lifecycle_configured=True,
            lifecycle_credential_state=lambda: credential[0],
            lifecycle_authorization_state=lambda: True,
            lifecycle_adapter_state=lambda: adapter[0],
        )
        first = states(provider.document())["lifecycle-execution"]
        self.assertEqual(first["code"], "LIFECYCLE_CREDENTIAL_UNAVAILABLE")
        credential[0] = True
        adapter[0] = False
        self.assertEqual(
            states(provider.document())["lifecycle-execution"]["state"], "degraded"
        )
        adapter[0] = True
        self.assertTrue(states(provider.document())["lifecycle-execution"]["canMutate"])

    def test_unexpected_runtime_evidence_failure_is_sanitized_and_fails_closed(self):
        def unavailable():
            raise Exception("sensitive runtime detail")

        document = self.provider(
            observation_state=lambda: "available",
            lifecycle_enabled=True,
            lifecycle_configured=True,
            lifecycle_credential_state=lambda: True,
            lifecycle_authorization_state=lambda: True,
            lifecycle_adapter_state=lambda: True,
            approvals_configured=True,
            approvals_state=unavailable,
        ).document()
        approval = states(document)["approvals"]
        self.assertEqual(approval["state"], "temporarily-unavailable")
        self.assertEqual(approval["code"], "APPROVAL_STORE_UNAVAILABLE")
        self.assertNotIn("sensitive", str(document))


class CapabilityAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verifier = password_verifier("long password", iterations=1)

    def test_authenticated_api_supports_get_head_and_rejects_mutation(self):
        app = DashboardApp(
            accounts={"operator": self.verifier},
            capability_provider=CapabilityProvider(clock=lambda: NOW),
        )
        login = request(
            app, "/api/v1alpha1/session", "POST",
            {"username": "operator", "password": "long password"},
        )
        cookie = login["headers"]["Set-Cookie"].split(";", 1)[0]
        get = request(app, CAPABILITIES_PATH, cookie=cookie)
        self.assertEqual(get["status"], "200 OK")
        self.assertEqual(
            json.loads(get["body"])["kind"], "ManagerCapabilities"
        )
        self.assertEqual(
            request(app, CAPABILITIES_PATH, "HEAD", cookie=cookie)["body"], b""
        )
        self.assertEqual(
            request(app, CAPABILITIES_PATH, "POST", cookie=cookie)["status"],
            "405 Method Not Allowed",
        )

    def test_browser_uses_one_authoritative_state_and_fails_closed(self):
        script = (
            ROOT / "manager/web/assets/dashboard.js"
        ).read_text(encoding="utf-8")
        html = (ROOT / "manager/web/index.html").read_text(encoding="utf-8")
        self.assertIn('path: "/api/v1alpha1/capabilities"', script)
        self.assertNotIn("setOperationsAvailable(items.length", script)
        self.assertIn("supportedCapabilityContractVersion", script)
        self.assertIn("CAPABILITY_CONTRACT_UNSUPPORTED_OR_STALE", script)
        self.assertIn("expires.valueOf() > Date.now()", script)
        self.assertIn("capabilityExpiresAt <= Date.now()", script)
        self.assertIn('["execute-operation", "confirm-operation", "cancel-operation", "retry-operation"]', script)
        self.assertIn("failClosedCapabilities(\"CAPABILITY_CONTRACT_PENDING\")", script)
        self.assertIn("lifecycleCapability", script)
        self.assertIn('id="operations-capability-badge"', html)
        self.assertIn('aria-describedby="operations-panel-state"', html)


if __name__ == "__main__":
    unittest.main()
