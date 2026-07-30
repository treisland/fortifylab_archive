"""Provider-neutral, bounded read-only communications for manager observability."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol


API_PREFIX = "/api/v1alpha1"
MAX_ITEMS = 10
MAX_MESSAGE = 3500
SAFE_COMPONENT = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
SAFE_WEB_PATHS = {
    "summary": "/",
    "health": "/health",
    "preflight": "/preflight",
    "incidents": "/incidents",
    "history": "/history",
}


class ManagerClientError(RuntimeError):
    """A sanitized manager client failure suitable for state mapping."""


class ManagerUnavailable(ManagerClientError):
    pass


class ManagerUnauthorized(ManagerClientError):
    pass


class ManagerRateLimited(ManagerClientError):
    def __init__(self, retry_after: int | None = None) -> None:
        super().__init__("manager request was rate limited")
        self.retry_after = retry_after


class ManagerResponseInvalid(ManagerClientError):
    pass


class CommandKind(str, Enum):
    SUMMARY = "summary"
    HEALTH = "health"
    PREFLIGHT = "preflight"
    INCIDENTS = "incidents"
    HISTORY = "history"
    HELP = "help"


@dataclass(frozen=True)
class ReadCommand:
    """Provider-independent allowlisted command."""

    kind: CommandKind
    page: int = 1
    component: str | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.page <= 1000:
            raise ValueError("page is outside the supported range")
        if self.component is not None and not SAFE_COMPONENT.fullmatch(self.component):
            raise ValueError("component ID is invalid")


@dataclass(frozen=True)
class Action:
    label: str
    command: ReadCommand


@dataclass(frozen=True)
class Message:
    """A transport-neutral rendered response."""

    text: str
    actions: tuple[Action, ...] = ()
    replace_key: str | None = None

    def __post_init__(self) -> None:
        if not self.text or len(self.text) > MAX_MESSAGE:
            raise ValueError("message is empty or exceeds its bound")
        if len(self.actions) > 6:
            raise ValueError("too many message actions")


class ManagerPort(Protocol):
    def read(
        self, resource: str, *, page: int = 1, page_size: int = MAX_ITEMS
    ) -> Mapping[str, Any]: ...


class HTTPManagerClient:
    """Read JSON from the manager API; never query Kubernetes directly."""

    def __init__(
        self,
        base_url: str,
        session_token: str,
        *,
        timeout_seconds: float = 5.0,
        opener: Any = urllib.request.urlopen,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("manager base URL must be HTTP(S)")
        if not session_token:
            raise ValueError("manager session token is required")
        self._base_url = base_url.rstrip("/")
        self._session_token = session_token
        self._timeout = max(0.1, min(float(timeout_seconds), 30.0))
        self._opener = opener

    def read(
        self, resource: str, *, page: int = 1, page_size: int = MAX_ITEMS
    ) -> Mapping[str, Any]:
        if resource not in SAFE_WEB_PATHS:
            raise ValueError("unsupported manager resource")
        query = urllib.parse.urlencode(
            {"page": max(1, min(page, 1000)), "pageSize": max(1, min(page_size, MAX_ITEMS))}
        )
        request = urllib.request.Request(
            f"{self._base_url}{API_PREFIX}/{resource}?{query}",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._session_token}",
            },
            method="GET",
        )
        try:
            with self._opener(request, timeout=self._timeout) as response:
                payload = response.read(256 * 1024 + 1)
        except urllib.error.HTTPError as error:
            code = error.code
            value = error.headers.get("Retry-After", "")
            error.close()
            if code in {401, 403}:
                raise ManagerUnauthorized("manager authorization failed") from None
            if code == 429:
                retry_after = int(value) if value.isdigit() else None
                raise ManagerRateLimited(retry_after) from None
            raise ManagerUnavailable("manager is unavailable") from None
        except (OSError, TimeoutError, urllib.error.URLError):
            raise ManagerUnavailable("manager is unavailable") from None
        if len(payload) > 256 * 1024:
            raise ManagerResponseInvalid("manager response is too large")
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ManagerResponseInvalid("manager returned an invalid response") from None
        if not isinstance(document, dict):
            raise ManagerResponseInvalid("manager returned an invalid response")
        return document


def parse_command(text: str) -> ReadCommand:
    """Parse a deliberately small command language without shell semantics."""

    parts = text.strip().split()
    if not parts:
        raise ValueError("empty command")
    name = parts[0].split("@", 1)[0].lstrip("/").lower()
    aliases = {"lab": CommandKind.SUMMARY, "start": CommandKind.SUMMARY}
    if name in aliases:
        kind = aliases[name]
    else:
        try:
            kind = CommandKind(name)
        except ValueError:
            raise ValueError("unknown command") from None
    component: str | None = None
    page = 1
    for value in parts[1:]:
        if value.startswith("page=") and value[5:].isdigit():
            page = int(value[5:])
        elif kind is CommandKind.HEALTH and component is None:
            component = value.lower()
        else:
            raise ValueError("unsupported command argument")
    return ReadCommand(kind=kind, page=page, component=component)


def encode_callback(command: ReadCommand) -> str:
    """Encode only typed fields; Telegram's 64-byte callback limit is preserved."""

    component = command.component or "-"
    value = f"read:{command.kind.value}:{command.page}:{component}"
    if len(value.encode()) > 64:
        raise ValueError("callback is too large")
    return value


def decode_callback(value: str) -> ReadCommand:
    parts = value.split(":")
    if len(parts) != 4 or parts[0] != "read" or not parts[2].isdigit():
        raise ValueError("invalid callback")
    return ReadCommand(
        kind=CommandKind(parts[1]),
        page=int(parts[2]),
        component=None if parts[3] == "-" else parts[3],
    )


def _safe_text(value: Any, limit: int = 240) -> str:
    text = str(value if value is not None else "unknown")
    text = text.replace("\r", " ").replace("\n", " ")
    text = re.sub(
        r"(?i)\b(password|token|secret|authorization|credential)\b\s*[:=]\s*\S+",
        r"\1=[redacted]",
        text,
    )
    text = re.sub(r"(?<!\w)(?:/home|/etc|/var|/run|/root|~)/\S+", "[protected-path]", text)
    return text[:limit]


def _items(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    values = document.get("items", [])
    if not isinstance(values, list):
        raise ManagerResponseInvalid("manager returned invalid items")
    return [item for item in values[:MAX_ITEMS] if isinstance(item, dict)]


def _freshness(document: Mapping[str, Any]) -> str:
    state = (
        _safe_text(document.get("freshness", {}).get("state", "unknown"), 32)
        if isinstance(document.get("freshness"), dict)
        else "unknown"
    )
    observed = _safe_text(document.get("observedAt", "unknown"), 40)
    return f"Freshness: {state} (observed {observed})"


def _pagination(kind: CommandKind, document: Mapping[str, Any], page: int) -> tuple[Action, ...]:
    pagination = document.get("pagination")
    if not isinstance(pagination, dict):
        return ()
    actions = []
    if bool(pagination.get("hasPrevious")) and page > 1:
        actions.append(Action("← Previous", ReadCommand(kind, page=page - 1)))
    if bool(pagination.get("hasNext")):
        actions.append(Action("Next →", ReadCommand(kind, page=page + 1)))
    return tuple(actions)


class ReadModelService:
    """Map manager read models to bounded provider-neutral messages."""

    def __init__(self, manager: ManagerPort, web_base_url: str) -> None:
        parsed = urllib.parse.urlsplit(web_base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Web UI base URL must be HTTP(S)")
        self._manager = manager
        self._web_base = web_base_url.rstrip("/")

    def execute(self, command: ReadCommand) -> Message:
        if command.kind is CommandKind.HELP:
            return self._help()
        try:
            document = self._manager.read(command.kind.value, page=command.page)
            renderer = {
                CommandKind.SUMMARY: self._summary,
                CommandKind.HEALTH: self._health,
                CommandKind.PREFLIGHT: self._preflight,
                CommandKind.INCIDENTS: self._incidents,
                CommandKind.HISTORY: self._history,
            }[command.kind]
            return renderer(document, command)
        except ManagerUnauthorized:
            return Message(
                "Manager authorization failed. Reconnect the protected manager session locally."
            )
        except ManagerRateLimited as error:
            suffix = (
                f" Try again in {error.retry_after} seconds."
                if error.retry_after is not None
                else " Try again later."
            )
            return Message("Manager rate limit reached." + suffix)
        except (ManagerUnavailable, ManagerResponseInvalid):
            return Message(
                "Manager is unavailable. Telegram did not query MicroK8s directly; try again later."
            )

    def recovery(self, event: Mapping[str, Any]) -> Message | None:
        """Map a manager recovery event without provider-specific fields."""

        if event.get("type") not in {"health.recovered", "incident.resolved"}:
            return None
        subject = event.get("subject")
        name = (
            subject.get("displayName", subject.get("id", "Lab"))
            if isinstance(subject, dict)
            else "Lab"
        )
        occurred = _safe_text(event.get("occurredAt", "unknown"), 40)
        return Message(
            f"✅ {_safe_text(name, 80)} recovered\n"
            f"{_safe_text(event.get('summary', 'Health returned to normal.'))}\n"
            f"Observed: {occurred}\n{self._link('health')}",
            replace_key=(
                f"health:{_safe_text(subject.get('id', 'lab'), 64)}"
                if isinstance(subject, dict)
                else "health:lab"
            ),
        )

    def _link(self, resource: str) -> str:
        return f"Open Web UI: {self._web_base}{SAFE_WEB_PATHS[resource]}"

    def _summary(self, document: Mapping[str, Any], command: ReadCommand) -> Message:
        lines = ["Fortify Lab summary", _freshness(document)]
        for item in _items(document):
            lines.append(
                f"{_safe_text(item.get('displayName', item.get('id', 'Component')), 80)}: "
                f"{_safe_text(item.get('status', 'unknown'), 32)}"
            )
        lines.append(self._link("summary"))
        actions = (
            Action("Health", ReadCommand(CommandKind.HEALTH)),
            Action("Preflight", ReadCommand(CommandKind.PREFLIGHT)),
            Action("Incidents", ReadCommand(CommandKind.INCIDENTS)),
            Action("History", ReadCommand(CommandKind.HISTORY)),
        )
        return Message("\n".join(lines)[:MAX_MESSAGE], actions, "lab:summary")

    def _health(self, document: Mapping[str, Any], command: ReadCommand) -> Message:
        items = _items(document)
        if command.component:
            items = [item for item in items if item.get("id") == command.component]
        roots = [item for item in items if item.get("status") != "blocked"]
        blocked = [item for item in items if item.get("status") == "blocked"]
        lines = ["Dependency-aware health", _freshness(document)]
        for item in roots + blocked:
            status = _safe_text(item.get("status", "unknown"), 32)
            name = _safe_text(item.get("displayName", item.get("id", "Component")), 80)
            root = item.get("rootCause")
            suffix = ""
            if isinstance(root, dict):
                suffix = f" — cause: {_safe_text(root.get('summary', root.get('componentId', 'unknown')))}"
            lines.append(f"{name}: {status}{suffix}")
            evidence = item.get("evidence")
            if isinstance(evidence, dict):
                lines.append(
                    f"  Evidence: {_safe_text(evidence.get('summary', 'unavailable'))}; "
                    f"checked {_safe_text(evidence.get('observedAt', 'unknown'), 40)}"
                )
            remediation = item.get("remediation")
            if isinstance(remediation, dict) and remediation.get("safe") is True:
                lines.append(f"  Safe action: {_safe_text(remediation.get('summary', 'See Web UI'))}")
        lines.append(self._link("health"))
        actions = _pagination(CommandKind.HEALTH, document, command.page)
        return Message("\n".join(lines)[:MAX_MESSAGE], actions, "lab:health")

    def _preflight(self, document: Mapping[str, Any], command: ReadCommand) -> Message:
        lines = ["Latest deployment preflight", _freshness(document)]
        if not _items(document):
            lines.append("No preflight result is available.")
        for item in _items(document):
            lines.append(
                f"{_safe_text(item.get('name', item.get('id', 'Check')), 100)}: "
                f"{_safe_text(item.get('status', 'unknown'), 32)} — "
                f"{_safe_text(item.get('summary', 'No detail available.'))}"
            )
            remediation = item.get("remediation")
            if isinstance(remediation, dict) and remediation.get("safe") is True:
                lines.append(f"  Safe action: {_safe_text(remediation.get('summary', 'See Web UI'))}")
        lines.append(self._link("preflight"))
        return Message(
            "\n".join(lines)[:MAX_MESSAGE],
            _pagination(CommandKind.PREFLIGHT, document, command.page),
            "lab:preflight",
        )

    def _incidents(self, document: Mapping[str, Any], command: ReadCommand) -> Message:
        lines = ["Manager incidents", _freshness(document)]
        if not _items(document):
            lines.append("No incidents on this page.")
        for item in _items(document):
            root = item.get("rootCause")
            root_summary = root.get("summary", "unknown") if isinstance(root, dict) else "unknown"
            lines.append(
                f"{_safe_text(item.get('severity', 'unknown'), 16)} "
                f"{_safe_text(item.get('status', 'unknown'), 16)}: "
                f"{_safe_text(item.get('summary', 'Incident'))}\n"
                f"  Root cause: {_safe_text(root_summary)}"
            )
        lines.append(self._link("incidents"))
        return Message(
            "\n".join(lines)[:MAX_MESSAGE],
            _pagination(CommandKind.INCIDENTS, document, command.page),
            "lab:incidents",
        )

    def _history(self, document: Mapping[str, Any], command: ReadCommand) -> Message:
        lines = ["Recent manager history", _freshness(document)]
        if not _items(document):
            lines.append("No history on this page.")
        for item in _items(document):
            lines.append(
                f"{_safe_text(item.get('occurredAt', item.get('updatedAt', 'unknown')), 40)} — "
                f"{_safe_text(item.get('summary', item.get('type', 'Event')))}"
            )
        lines.append(self._link("history"))
        return Message(
            "\n".join(lines)[:MAX_MESSAGE],
            _pagination(CommandKind.HISTORY, document, command.page),
            "lab:history",
        )

    @staticmethod
    def _help() -> Message:
        return Message(
            "Read-only Fortify Lab commands\n"
            "/lab — inventory and aggregate state\n"
            "/health [component] — dependency-aware health\n"
            "/preflight — latest deployment preflight\n"
            "/incidents [page=N] — current incidents\n"
            "/history [page=N] — recent manager history\n"
            "/help — this command list"
        )
