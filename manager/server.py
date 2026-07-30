"""Supported host launcher for the Fortify Lab Manager 0.2 service."""

from __future__ import annotations

import argparse
import json
import logging
import os
import stat
import sys
import tomllib
from pathlib import Path
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIServer, make_server

from manager.api import ManagerAPI
from manager.dashboard import DashboardApp
from manager.history import StoreHistoryReader
from manager.record_store import LoopRecordStore


LOG = logging.getLogger("fortify-manager")
DEFAULT_CONFIG = Path("/etc/fortify-lab-manager/manager.toml")


class ConfigurationError(RuntimeError):
    """A sanitized, actionable launcher configuration failure."""


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


def load_config(path: Path) -> dict:
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigurationError("manager configuration is missing or invalid") from error
    server = document.get("server", {})
    storage = document.get("storage", {})
    authentication = document.get("authentication", {})
    config = {
        "host": server.get("host", "0.0.0.0"),
        "port": server.get("port", 8080),
        "state_database": storage.get(
            "database", "/var/lib/fortify-lab-manager/history.sqlite3"
        ),
        "accounts": authentication.get(
            "accounts", "/var/lib/fortify-lab-manager/accounts.json"
        ),
    }
    if config["host"] != "0.0.0.0":
        raise ConfigurationError("server.host must be 0.0.0.0 for MicroK8s ingress")
    if not isinstance(config["port"], int) or not 1 <= config["port"] <= 65535:
        raise ConfigurationError("server.port must be an integer from 1 through 65535")
    return config


def load_accounts(path: Path) -> dict[str, str]:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise ConfigurationError("account verifier file permissions must be 0600")
        document = json.loads(path.read_text(encoding="utf-8"))
    except ConfigurationError:
        raise
    except (OSError, json.JSONDecodeError) as error:
        raise ConfigurationError("account verifier file is missing or invalid") from error
    if (
        not isinstance(document, dict)
        or not document
        or not all(
            isinstance(name, str)
            and name
            and isinstance(verifier, str)
            and verifier.startswith("pbkdf2-sha256$")
            for name, verifier in document.items()
        )
    ):
        raise ConfigurationError("account verifier file contains no valid accounts")
    return document


def build_app(config: dict) -> tuple[DashboardApp, LoopRecordStore]:
    accounts = load_accounts(Path(config["accounts"]))
    store = LoopRecordStore(Path(config["state_database"]))
    api = ManagerAPI(history_reader=StoreHistoryReader(store))
    return DashboardApp(accounts=accounts, api=api, secure_cookies=True), store


def check(config_path: Path) -> None:
    config = load_config(config_path)
    accounts = load_accounts(Path(config["accounts"]))
    state_parent = Path(config["state_database"]).parent
    if not state_parent.is_dir() or not os.access(state_parent, os.W_OK):
        raise ConfigurationError("manager state directory is missing or not writable")
    LOG.info(
        "configuration valid: listener=%s:%d accounts=%d state=available",
        config["host"],
        config["port"],
        len(accounts),
    )


def serve(config_path: Path) -> None:
    config = load_config(config_path)
    app, store = build_app(config)
    httpd = make_server(
        config["host"],
        config["port"],
        app,
        server_class=ThreadingWSGIServer,
    )
    try:
        LOG.info("manager listening on %s:%d", config["host"], config["port"])
        httpd.serve_forever()
    finally:
        store.close()
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fortify Lab Manager host service")
    parser.add_argument("command", choices=("serve", "check"))
    parser.add_argument(
        "--config", type=Path, default=DEFAULT_CONFIG, help=argparse.SUPPRESS
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        if args.command == "check":
            check(args.config)
        else:
            serve(args.config)
    except (ConfigurationError, OSError, RuntimeError):
        LOG.error(
            "manager could not start; run 'sudo fortify-manager diagnose' "
            "for sanitized checks"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
