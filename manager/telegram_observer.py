"""Thin private Telegram adapter for provider-neutral manager read commands."""

from __future__ import annotations

import json
from typing import Any, Protocol

from manager.communications import (
    Action,
    Message,
    ReadModelService,
    decode_callback,
    encode_callback,
    parse_command,
)
from manager.authorization import ActorIdentity
from manager.remote_actions import OpaqueAction, RemoteActionError, RemoteActionService
from datetime import datetime, timezone


class TelegramPort(Protocol):
    def send(self, text: str, markup: str | None = None) -> None: ...
    def answer_callback(self, callback_id: str, text: str) -> None: ...


class PrivateTelegramObserver:
    """Authorize one private identity and translate transport envelopes only."""

    def __init__(
        self,
        service: ReadModelService,
        telegram: TelegramPort,
        *,
        allowed_user: str,
        allowed_chat: str,
        actions: RemoteActionService | None = None,
        clock: Any = None,
    ) -> None:
        self._service = service
        self._telegram = telegram
        self._allowed_user = allowed_user
        self._allowed_chat = allowed_chat
        self._actions = actions
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def handle(self, update: dict[str, Any]) -> bool:
        callback = update.get("callback_query")
        if isinstance(callback, dict):
            message = callback.get("message")
            sender = callback.get("from")
            if not self._authorized(message, sender):
                return False
            callback_id = str(callback.get("id", ""))
            try:
                data = str(callback.get("data", ""))
                if data.startswith("act:") and self._actions is not None:
                    self._send(
                        self._actions.execute(data[4:], self._identity())
                    )
                else:
                    command = decode_callback(data)
                    self._send(self._service.execute(command))
                self._telegram.answer_callback(callback_id, "Updated")
            except (ValueError, TypeError, RemoteActionError):
                self._telegram.answer_callback(callback_id, "Action is invalid or expired")
            return True

        message = update.get("message")
        sender = message.get("from") if isinstance(message, dict) else None
        if not self._authorized(message, sender):
            return False
        text = str(message.get("text", ""))
        if not text.startswith("/"):
            return True
        try:
            response = self._service.execute(parse_command(text))
        except ValueError:
            response = Message("Unknown read-only command. Use /help.")
        self._send(response)
        return True

    def _authorized(self, message: Any, sender: Any) -> bool:
        if not isinstance(message, dict) or not isinstance(sender, dict):
            return False
        chat = message.get("chat")
        return (
            isinstance(chat, dict)
            and chat.get("type") == "private"
            and str(chat.get("id")) == self._allowed_chat
            and str(sender.get("id")) == self._allowed_user
        )

    def _send(self, message: Message) -> None:
        self._telegram.send(message.text, self._markup(message.actions))

    def _identity(self) -> ActorIdentity:
        return ActorIdentity(
            actor=f"telegram:{self._allowed_user}",
            source="telegram",
            session_id=f"private-chat:{self._allowed_chat}",
            authenticated_at=self._clock(),
        )

    @staticmethod
    def _markup(actions: tuple[Action, ...]) -> str | None:
        if not actions:
            return None
        return json.dumps(
            {
                "inline_keyboard": [
                    [
                        {
                            "text": action.label,
                            "callback_data": (
                                f"act:{action.command.token}"
                                if isinstance(action.command, OpaqueAction)
                                else encode_callback(action.command)
                            ),
                        }
                        for action in actions
                    ]
                ]
            },
            separators=(",", ":"),
        )
