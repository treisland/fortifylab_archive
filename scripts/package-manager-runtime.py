#!/usr/bin/env python3
"""Stage and validate the complete, policy-mode Manager runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

INVENTORY = Path("packaging/runtime-files.json")


class PackagingError(ValueError):
    """The declared runtime closure cannot be staged safely."""


def _contained(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _load_manifest(source: Path) -> dict:
    path = source / "packaging" / "manager-runtime.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PackagingError("runtime packaging manifest is unavailable or malformed") from error
    if set(document) != {"version", "directories", "files", "launchers", "modes"}:
        raise PackagingError("runtime packaging manifest fields are invalid")
    if document["version"] != 1:
        raise PackagingError("runtime packaging manifest version is unsupported")
    if (
        not isinstance(document["directories"], list)
        or not isinstance(document["files"], list)
        or not document["directories"]
        or not document["files"]
        or any(not isinstance(item, str) or not item for item in document["directories"] + document["files"])
        or not isinstance(document["launchers"], dict)
        or not document["launchers"]
        or any(
            not isinstance(path, str)
            or not path
            or not isinstance(module, str)
            or not module.startswith("manager.")
            for path, module in document["launchers"].items()
        )
        or document["modes"]
        != {"directory": "0755", "file": "0644", "executable": "0755"}
    ):
        raise PackagingError("runtime packaging manifest policy is invalid")
    return document


def _relative_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or path == Path("."):
        raise PackagingError("runtime packaging manifest contains an unsafe path")
    return path


def _copy_file(source_root: Path, target_root: Path, relative: Path, mode: int) -> None:
    source = source_root / relative
    target = target_root / relative
    if source.is_symlink() or not source.is_file() or not _contained(source_root, source):
        raise PackagingError(f"required runtime file is unavailable: {relative}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    os.chmod(target, mode)


def stage(source: Path, target: Path) -> None:
    source = source.resolve()
    manifest = _load_manifest(source)
    if target.exists():
        raise PackagingError("staged candidate already exists")
    target.mkdir(parents=True, mode=0o755)
    try:
        for value in manifest["directories"]:
            relative = _relative_path(value)
            directory = source / relative
            if directory.is_symlink() or not directory.is_dir() or not _contained(source, directory):
                raise PackagingError(f"required runtime directory is unavailable: {relative}")
            for item in sorted(directory.rglob("*")):
                item_relative = item.relative_to(source)
                if item.is_symlink() or not _contained(source, item):
                    raise PackagingError(f"runtime input is not a confined regular file: {item_relative}")
                if item.is_dir():
                    (target / item_relative).mkdir(parents=True, exist_ok=True)
                    continue
                if not item.is_file():
                    raise PackagingError(f"runtime input has an unsupported file type: {item_relative}")
                mode = 0o755 if item_relative.parts[0] == "apps" and item.suffix == ".sh" else 0o644
                _copy_file(source, target, item_relative, mode)
        for value in manifest["files"]:
            _copy_file(source, target, _relative_path(value), 0o644)
        for value, module in manifest["launchers"].items():
            relative = _relative_path(value)
            launcher = target / relative
            launcher.parent.mkdir(parents=True, exist_ok=True)
            launcher.write_text(
                "#!/bin/sh\n"
                'runtime_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"\n'
                'cd "$runtime_root"\n'
                f'exec /usr/bin/python3 -m {module} "$@"\n',
                encoding="utf-8",
            )
            os.chmod(launcher, 0o755)
        for directory in (path for path in target.rglob("*") if path.is_dir()):
            os.chmod(directory, 0o755)
        os.chmod(target, 0o755)
        files = sorted(
            str(path.relative_to(target))
            for path in target.rglob("*")
            if path.is_file()
        )
        (target / INVENTORY).write_text(
            json.dumps({"version": 1, "files": files + [str(INVENTORY)]}, indent=2)
            + "\n",
            encoding="utf-8",
        )
        os.chmod(target / INVENTORY, 0o644)
        validate(target)
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise


def validate(root: Path) -> None:
    root = root.resolve()
    if not root.is_dir() or stat.S_IMODE(root.stat().st_mode) != 0o755:
        raise PackagingError("staged runtime root mode is invalid")
    manifest = _load_manifest(root)
    try:
        inventory = json.loads((root / INVENTORY).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PackagingError("staged runtime inventory is unavailable or malformed") from error
    if (
        not isinstance(inventory, dict)
        or set(inventory) != {"version", "files"}
        or inventory["version"] != 1
        or not isinstance(inventory["files"], list)
        or any(not isinstance(item, str) for item in inventory["files"])
    ):
        raise PackagingError("staged runtime inventory is invalid")
    actual_files = sorted(
        str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()
    )
    if actual_files != sorted(inventory["files"]):
        raise PackagingError("staged runtime files differ from the packaging inventory")
    for value in manifest["directories"]:
        path = root / _relative_path(value)
        if path.is_symlink() or not path.is_dir() or not _contained(root, path):
            raise PackagingError(f"staged runtime directory is invalid: {value}")
    for value in manifest["files"]:
        path = root / _relative_path(value)
        if path.is_symlink() or not path.is_file() or not _contained(root, path):
            raise PackagingError(f"staged runtime file is invalid: {value}")
    launchers = {_relative_path(value) for value in manifest["launchers"]}
    for relative in launchers:
        path = root / relative
        if path.is_symlink() or not path.is_file() or not _contained(root, path):
            raise PackagingError(f"staged runtime launcher is invalid: {relative}")
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if path.is_symlink() or not _contained(root, path):
            raise PackagingError(f"staged runtime path escapes its root: {relative}")
        expected = 0o755 if path.is_dir() else 0o644
        if path.is_file() and (
            (relative.parts[0] == "apps" and path.suffix == ".sh")
            or relative in launchers
        ):
            expected = 0o755
        if not (path.is_dir() or path.is_file()):
            raise PackagingError(f"staged runtime path has an unsupported type: {relative}")
        actual = stat.S_IMODE(path.stat().st_mode)
        if actual != expected:
            raise PackagingError(f"staged runtime mode is invalid: {relative}")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from manager.component_registry import ComponentRegistry; ComponentRegistry.load()",
        ],
        cwd=root,
        env={
            **os.environ,
            "PYTHONPATH": str(root),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise PackagingError("staged runtime registry validation failed")


def content_digest(root: Path) -> str:
    """Return a deterministic digest of the validated runtime and its modes."""
    validate(root)
    root = root.resolve()
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: str(item.relative_to(root))):
        relative = str(path.relative_to(root)).encode("utf-8")
        kind = b"directory" if path.is_dir() else b"file"
        mode = f"{stat.S_IMODE(path.stat().st_mode):04o}".encode("ascii")
        digest.update(kind + b"\0" + relative + b"\0" + mode + b"\0")
        if path.is_file():
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            digest.update(b"\0")
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("stage", "validate", "digest"))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--target", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        if arguments.command == "stage":
            if arguments.source is None:
                parser.error("stage requires --source")
            stage(arguments.source, arguments.target)
        elif arguments.command == "validate":
            validate(arguments.target)
        else:
            print(content_digest(arguments.target))
    except (OSError, PackagingError) as error:
        print(f"Manager runtime packaging failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
