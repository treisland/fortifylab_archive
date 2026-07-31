"""Tests for provider-neutral manager communications and Telegram mapping."""

from __future__ import annotations

import json
import unittest
import urllib.error

from manager.communications import (
    CommandKind,
    HTTPManagerClient,
    ManagerRateLimited,
    ManagerUnauthorized,
    ManagerUnavailable,
    ReadCommand,
    ReadModelService,
    decode_callback,
    encode_callback,
    parse_command,
)
from manager.telegram_observer import PrivateTelegramObserver


class FakeManager:
    def __init__(self, documents=None, error=None):
        self.documents = documents or {}
        self.error = error
        self.calls = []

    def read(self, resource, *, page=1, page_size=10):
        self.calls.append((resource, page, page_size))
        if self.error:
            raise self.error
        return self.documents.get(
            resource,
            {
                "freshness": {"state": "fresh"},
                "observedAt": "2026-07-30T12:00:00Z",
                "items": [],
            },
        )


class FakeTelegram:
    def __init__(self):
        self.messages = []
        self.answers = []

    def send(self, text, markup=None):
        self.messages.append((text, markup))

    def answer_callback(self, callback_id, text):
        self.answers.append((callback_id, text))


def private_update(text="/lab", user=7, chat=11):
    return {
        "message": {
            "text": text,
            "from": {"id": user},
            "chat": {"id": chat, "type": "private"},
        }
    }


class CommunicationContractTests(unittest.TestCase):
    def test_commands_and_callbacks_are_typed_and_bounded(self):
        self.assertEqual(parse_command("/lab").kind, CommandKind.SUMMARY)
        command = parse_command("/health scancentral-sast page=2")
        self.assertEqual(command, ReadCommand(CommandKind.HEALTH, 2, "scancentral-sast"))
        self.assertEqual(decode_callback(encode_callback(command)), command)
        for unsafe in ("/history ../../etc/passwd", "/health 'x y'", "/unknown"):
            with self.assertRaises(ValueError):
                parse_command(unsafe)

    def test_mysql_root_cause_precedes_blocked_ssc_and_sast(self):
        manager = FakeManager(
            {
                "health": {
                    "freshness": {"state": "fresh"},
                    "observedAt": "2026-07-30T12:00:00Z",
                    "items": [
                        {
                            "id": "scancentral-sast",
                            "displayName": "ScanCentral SAST",
                            "status": "blocked",
                            "rootCause": {
                                "componentId": "mysql",
                                "summary": "MySQL query failed",
                            },
                        },
                        {
                            "id": "ssc",
                            "displayName": "SSC",
                            "status": "blocked",
                            "rootCause": {
                                "componentId": "mysql",
                                "summary": "MySQL query failed",
                            },
                        },
                        {
                            "id": "mysql",
                            "displayName": "MySQL",
                            "status": "unhealthy",
                            "evidence": {
                                "summary": "Authenticated query failed",
                                "observedAt": "2026-07-30T11:59:58Z",
                            },
                            "remediation": {
                                "safe": True,
                                "summary": "Inspect database health in the Web UI",
                            },
                        },
                    ],
                }
            }
        )
        message = ReadModelService(manager, "https://manager.example").execute(
            ReadCommand(CommandKind.HEALTH)
        )
        self.assertLess(
            message.text.index("MySQL: unhealthy"), message.text.index("SSC: blocked")
        )
        self.assertLess(
            message.text.index("MySQL: unhealthy"),
            message.text.index("ScanCentral SAST: blocked"),
        )
        self.assertIn("Freshness: fresh", message.text)
        self.assertIn("Safe action:", message.text)

    def test_postgresql_and_lim_roots_precede_blocked_dast(self):
        manager = FakeManager(
            {
                "health": {
                    "freshness": {"state": "stale"},
                    "observedAt": "2026-07-30T11:00:00Z",
                    "items": [
                        {
                            "id": "scancentral-dast-core",
                            "displayName": "ScanCentral DAST",
                            "status": "blocked",
                            "rootCause": {
                                "componentId": "postgresql",
                                "summary": "PostgreSQL unavailable; LIM configuration invalid",
                            },
                        },
                        {"id": "lim", "displayName": "LIM", "status": "misconfigured"},
                        {
                            "id": "postgresql",
                            "displayName": "PostgreSQL",
                            "status": "unreachable",
                        },
                    ],
                }
            }
        )
        text = ReadModelService(manager, "https://manager.example").execute(
            ReadCommand(CommandKind.HEALTH)
        ).text
        self.assertIn("Freshness: stale", text)
        self.assertLess(
            text.index("LIM: misconfigured"), text.index("ScanCentral DAST: blocked")
        )
        self.assertLess(
            text.index("PostgreSQL: unreachable"),
            text.index("ScanCentral DAST: blocked"),
        )

    def test_documents_are_paginated_bounded_and_sanitized(self):
        documents = {
            "history": {
                "freshness": {"state": "fresh"},
                "observedAt": "now",
                "items": [
                    {
                        "occurredAt": "now",
                        "summary": (
                            f"token=abc /etc/fortify/private.conf item {index} "
                            + "x" * 500
                        ),
                    }
                    for index in range(30)
                ],
                "pagination": {"hasPrevious": True, "hasNext": True},
            }
        }
        message = ReadModelService(FakeManager(documents), "https://manager.example").execute(
            ReadCommand(CommandKind.HISTORY, page=2)
        )
        self.assertLessEqual(len(message.text), 3500)
        self.assertNotIn("abc", message.text)
        self.assertNotIn("/etc/", message.text)
        self.assertEqual([action.label for action in message.actions], ["← Previous", "Next →"])

    def test_unavailable_unauthorized_and_rate_limited_states_are_safe(self):
        cases = (
            (ManagerUnavailable(), "unavailable"),
            (ManagerUnauthorized(), "authorization failed"),
            (ManagerRateLimited(17), "17 seconds"),
        )
        for error, expected in cases:
            with self.subTest(error=type(error).__name__):
                message = ReadModelService(
                    FakeManager(error=error), "https://manager.example"
                ).execute(ReadCommand(CommandKind.SUMMARY))
                self.assertIn(expected, message.text)

    def test_recovery_event_mapping_is_provider_neutral(self):
        service = ReadModelService(FakeManager(), "https://manager.example")
        message = service.recovery(
            {
                "type": "health.recovered",
                "subject": {"id": "mysql", "displayName": "MySQL"},
                "summary": "Database checks pass again",
                "occurredAt": "2026-07-30T12:05:00Z",
            }
        )
        self.assertIsNotNone(message)
        self.assertIn("MySQL recovered", message.text)
        self.assertEqual(message.replace_key, "health:mysql")
        self.assertNotIn("telegram", json.dumps(message.__dict__).lower())


class TelegramAdapterTests(unittest.TestCase):
    def setUp(self):
        self.manager = FakeManager()
        self.telegram = FakeTelegram()
        self.adapter = PrivateTelegramObserver(
            ReadModelService(self.manager, "https://manager.example"),
            self.telegram,
            allowed_user="7",
            allowed_chat="11",
        )

    def test_private_authorized_command_uses_manager_and_returns_buttons(self):
        self.assertTrue(self.adapter.handle(private_update()))
        self.assertEqual(self.manager.calls, [("summary", 1, 10)])
        markup = json.loads(self.telegram.messages[0][1])
        self.assertEqual(len(markup["inline_keyboard"][0]), 4)

    def test_unauthorized_group_and_wrong_identity_are_ignored(self):
        self.assertFalse(self.adapter.handle(private_update(user=99)))
        group = private_update()
        group["message"]["chat"]["type"] = "group"
        self.assertFalse(self.adapter.handle(group))
        self.assertEqual(self.manager.calls, [])
        self.assertEqual(self.telegram.messages, [])

    def test_callback_maps_to_typed_read_command(self):
        update = {
            "callback_query": {
                "id": "cb-1",
                "data": encode_callback(ReadCommand(CommandKind.INCIDENTS, 2)),
                "from": {"id": 7},
                "message": {
                    "message_id": 4,
                    "chat": {"id": 11, "type": "private"},
                },
            }
        }
        self.assertTrue(self.adapter.handle(update))
        self.assertEqual(self.manager.calls, [("incidents", 2, 10)])
        self.assertEqual(self.telegram.answers, [("cb-1", "Updated")])

    def test_secret_content_is_neither_accepted_nor_echoed(self):
        marker = "unique-sensitive-telegram-marker"
        self.assertTrue(self.adapter.handle(private_update(marker)))
        self.assertEqual(self.manager.calls, [])
        self.assertEqual(self.telegram.messages, [])

        self.assertTrue(self.adapter.handle(private_update(f"/replace token={marker}")))
        self.assertEqual(self.manager.calls, [])
        self.assertEqual(self.telegram.messages[-1][0], "Unknown read-only command. Use /help.")
        self.assertNotIn(marker, json.dumps(self.telegram.messages))


class HTTPManagerClientTests(unittest.TestCase):
    def test_client_only_calls_versioned_manager_get_endpoint(self):
        captured = {}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *unused):
                return False

            def read(self, unused_limit):
                return b'{"items":[]}'

        def opener(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return Response()

        client = HTTPManagerClient(
            "http://127.0.0.1:8080", "session-value", opener=opener
        )
        self.assertEqual(client.read("health", page=2), {"items": []})
        request = captured["request"]
        self.assertEqual(request.get_method(), "GET")
        self.assertIn("/api/v1alpha1/health?page=2&pageSize=10", request.full_url)
        self.assertEqual(request.headers["Authorization"], "Bearer session-value")

    def test_http_error_mapping_does_not_include_response_details(self):
        def unauthorized(*unused, **kwargs):
            raise urllib.error.HTTPError(
                "http://manager", 401, "/root/protected token=abc", {}, None
            )

        client = HTTPManagerClient("http://manager", "session", opener=unauthorized)
        with self.assertRaisesRegex(ManagerUnauthorized, "authorization failed"):
            client.read("summary")


if __name__ == "__main__":
    unittest.main()
