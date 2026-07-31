"""Protected, versioned migration for the external Manager TOML configuration."""

from __future__ import annotations

import argparse
import datetime
import grp
import os
import pwd
import re
import stat
import sys
import tempfile
import tomllib
from pathlib import Path

CURRENT_SCHEMA_VERSION = 1
SUPPORTED_OLD_VERSIONS = (0,)
VERSION_KEY = "schema_version"
SECTION_RE = re.compile(r"^\s*\[([A-Za-z0-9_.-]+)\]\s*(?:#.*)?$")
KEY_RE = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=")


class MigrationError(RuntimeError):
    """A sanitized configuration migration failure."""


def _read_document(path: Path) -> tuple[str, dict]:
    try:
        if path.is_symlink() or not path.is_file():
            raise MigrationError("manager configuration is not a protected regular file")
        text = path.read_text(encoding="utf-8")
        document = tomllib.loads(text)
    except MigrationError:
        raise
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise MigrationError("manager configuration is missing or malformed") from error
    return text, document


def schema_version(document: dict) -> int:
    version = document.get(VERSION_KEY, 0)
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise MigrationError("manager configuration schema version is invalid")
    if version > CURRENT_SCHEMA_VERSION:
        raise MigrationError("manager configuration uses a newer unsupported schema")
    if version not in (*SUPPORTED_OLD_VERSIONS, CURRENT_SCHEMA_VERSION):
        raise MigrationError("manager configuration schema version is unsupported")
    return version


def _section(document: dict, name: str) -> dict:
    value = document.get(name, {})
    if not isinstance(value, dict):
        raise MigrationError(f"manager configuration section [{name}] is invalid")
    return value


def validate_document(document: dict) -> int:
    version = schema_version(document)
    server = _section(document, "server")
    storage = _section(document, "storage")
    authentication = _section(document, "authentication")
    cluster = _section(document, "cluster")
    lifecycle = _section(document, "lifecycle")
    _section(document, "recovery")
    if not server or not storage or not authentication:
        raise MigrationError(
            "manager configuration requires server, storage, and authentication sections"
        )
    if "host" in server and not isinstance(server["host"], str):
        raise MigrationError("manager configuration server.host is invalid")
    port = server.get("port")
    if port is not None and (
        isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
    ):
        raise MigrationError("manager configuration server.port is invalid")
    if "database" in storage and not isinstance(storage["database"], str):
        raise MigrationError("manager configuration storage.database is invalid")
    if "accounts" in authentication and not isinstance(
        authentication["accounts"], str
    ):
        raise MigrationError("manager configuration authentication.accounts is invalid")
    for key in ("server", "namespace", "token_file", "ca_file", "health_probe_socket"):
        if key in cluster and not isinstance(cluster[key], str):
            raise MigrationError(f"manager configuration cluster.{key} is invalid")
    timeout = cluster.get("timeout_seconds")
    if timeout is not None and (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 1 <= timeout <= 60
    ):
        raise MigrationError("manager configuration cluster.timeout_seconds is invalid")
    if "enabled" in lifecycle and not isinstance(lifecycle["enabled"], bool):
        raise MigrationError("manager configuration lifecycle.enabled is invalid")
    return version


def _protected_file(path: Path, uid: int, gid: int) -> bool:
    try:
        metadata = path.stat()
    except OSError:
        return False
    return (
        not path.is_symlink()
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_size > 0
        and metadata.st_uid == uid
        and metadata.st_gid == gid
        and stat.S_IMODE(metadata.st_mode) == 0o600
    )


def observer_ready(access_root: Path, uid: int, gid: int) -> bool:
    try:
        metadata = access_root.stat()
    except OSError:
        return False
    return (
        not access_root.is_symlink()
        and stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == uid
        and metadata.st_gid == gid
        and stat.S_IMODE(metadata.st_mode) == 0o700
        and _protected_file(access_root / "token", uid, gid)
        and _protected_file(access_root / "ca.crt", uid, gid)
    )


def _section_keys(lines: list[str]) -> tuple[dict[str, set[str]], dict[str, int]]:
    keys: dict[str, set[str]] = {}
    endings: dict[str, int] = {}
    current = ""
    for index, line in enumerate(lines):
        match = SECTION_RE.match(line)
        if match:
            if current:
                endings[current] = index
            current = match.group(1)
            keys.setdefault(current, set())
            continue
        match = KEY_RE.match(line)
        if match:
            keys.setdefault(current, set()).add(match.group(1))
    if current:
        endings[current] = len(lines)
    return keys, endings


def _merge_defaults(text: str, additions: dict[str, tuple[str, ...]]) -> str:
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    keys, endings = _section_keys(lines)
    pending: list[tuple[int, list[str]]] = []
    appended: list[str] = []
    for section, values in additions.items():
        missing = [
            value
            for value in values
            if value.split("=", 1)[0].strip() not in keys.get(section, set())
        ]
        if not missing:
            continue
        rendered = [f"{value}\n" for value in missing]
        if section in endings:
            pending.append((endings[section], rendered))
        else:
            if lines or appended:
                appended.append("\n")
            appended.extend([f"[{section}]\n", *rendered])
    for index, rendered in sorted(pending, reverse=True):
        lines[index:index] = rendered
    lines.extend(appended)
    return "".join(lines)


def candidate_text(
    text: str,
    document: dict,
    access_root: Path,
    observer_uid: int,
    observer_gid: int,
) -> str:
    version = schema_version(document)
    additions: dict[str, tuple[str, ...]] = {"lifecycle": ("enabled = false",)}
    if observer_ready(access_root, observer_uid, observer_gid):
        additions["cluster"] = (
            'server = "https://127.0.0.1:16443"',
            'namespace = "fortify"',
            f'token_file = "{access_root / "token"}"',
            f'ca_file = "{access_root / "ca.crt"}"',
            "timeout_seconds = 5",
        )
    candidate = _merge_defaults(text, additions)
    if version == 0:
        candidate = f"{VERSION_KEY} = {CURRENT_SCHEMA_VERSION}\n\n{candidate}"
    return candidate


def _atomic_write(path: Path, content: str, uid: int, gid: int, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, uid, gid)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def inspect(path: Path, access_root: Path, observer_uid: int, observer_gid: int) -> str:
    _, document = _read_document(path)
    version = validate_document(document)
    return (
        f"configuration-schema: {version}/{CURRENT_SCHEMA_VERSION}\n"
        f"observer-files: {'protected' if observer_ready(access_root, observer_uid, observer_gid) else 'unavailable'}\n"
        f"observer-configuration: {'present' if document.get('cluster') else 'absent'}\n"
        f"lifecycle: {'enabled' if document.get('lifecycle', {}).get('enabled', False) else 'disabled'}\n"
    )


def migrate(
    path: Path,
    backup_root: Path,
    access_root: Path,
    config_uid: int,
    config_gid: int,
    observer_uid: int,
    observer_gid: int,
) -> Path | None:
    text, document = _read_document(path)
    validate_document(document)
    candidate = candidate_text(text, document, access_root, observer_uid, observer_gid)
    try:
        candidate_document = tomllib.loads(candidate)
    except tomllib.TOMLDecodeError as error:
        raise MigrationError("generated manager configuration candidate is invalid") from error
    validate_document(candidate_document)
    if candidate == text:
        return None
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(backup_root, config_uid, config_gid)
    os.chmod(backup_root, 0o700)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    backup = backup_root / f"manager.toml.schema-{schema_version(document)}.{stamp}.bak"
    _atomic_write(backup, text, config_uid, config_gid, 0o600)
    _atomic_write(path, candidate, config_uid, config_gid, 0o640)
    return backup


def rollback(
    path: Path,
    backup: Path,
    backup_root: Path,
    config_uid: int,
    config_gid: int,
) -> None:
    try:
        resolved_root = backup_root.resolve(strict=True)
        resolved = backup.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as error:
        raise MigrationError("configuration backup is outside the protected backup root") from error
    metadata = resolved.stat()
    if (
        backup.is_symlink()
        or not resolved.is_file()
        or metadata.st_uid != config_uid
        or metadata.st_gid != config_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise MigrationError("configuration backup ownership or permissions are invalid")
    text, document = _read_document(resolved)
    validate_document(document)
    _atomic_write(path, text, config_uid, config_gid, 0o640)


def _identity(user: str, group: str) -> tuple[int, int]:
    try:
        return pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid
    except KeyError as error:
        raise MigrationError("required Manager account or group is unavailable") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Protected Manager configuration migration")
    parser.add_argument("command", choices=("inspect", "migrate", "diagnose", "rollback"))
    parser.add_argument("backup", nargs="?")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--backup-root", type=Path, required=True)
    parser.add_argument("--access-root", type=Path, required=True)
    parser.add_argument("--config-user", default="root")
    parser.add_argument("--config-group", default="fortify-manager")
    parser.add_argument("--observer-user", default="fortify-manager")
    parser.add_argument("--observer-group", default="fortify-manager")
    arguments = parser.parse_args(argv)
    try:
        config_uid, config_gid = _identity(arguments.config_user, arguments.config_group)
        observer_uid, observer_gid = _identity(
            arguments.observer_user, arguments.observer_group
        )
        if arguments.command in ("inspect", "diagnose"):
            if arguments.backup:
                raise MigrationError("this configuration command does not accept a backup")
            print(
                inspect(arguments.config, arguments.access_root, observer_uid, observer_gid),
                end="",
            )
        elif arguments.command == "migrate":
            if arguments.backup:
                raise MigrationError("migrate does not accept a backup")
            backup = migrate(
                arguments.config,
                arguments.backup_root,
                arguments.access_root,
                config_uid,
                config_gid,
                observer_uid,
                observer_gid,
            )
            print(
                "Manager configuration is already current."
                if backup is None
                else f"Manager configuration migrated; protected backup: {backup.name}"
            )
        else:
            if not arguments.backup:
                raise MigrationError("rollback requires a protected backup path")
            rollback(
                arguments.config,
                Path(arguments.backup),
                arguments.backup_root,
                config_uid,
                config_gid,
            )
            print("Manager configuration rollback completed.")
    except MigrationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
