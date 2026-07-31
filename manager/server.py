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
from manager.availability import AvailabilityMonitor
from manager.capabilities import CapabilityProvider
from manager.dashboard import DashboardApp
from manager.history import StoreHistoryReader
from manager.component_registry import ComponentRegistry
from manager.component_inventory import ComponentInventory
from manager.kubernetes_observer import KubernetesObserver
from manager.functional_health import UnixFunctionalHealthProbe
from manager.health import CheckSpec
from manager.record_store import LoopRecordStore
from manager.authorization import ApprovalStore, AuthorizationService
from manager.microk8s_lifecycle import (
    MicroK8sLifecycleAdapter,
    RegistryHealthVerifier,
)
from manager.operation_engine import OperationEngine, OperationStore
from manager.preflight import PreflightEngine
from manager.web_operations import WebOperationAPI
from manager.backup_restore import (
    Destination, RecoveryService, RecoveryStore, UnixRecoveryAdapter,
)


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
        "cluster": document.get("cluster", {}),
        "lifecycle_enabled": document.get("lifecycle", {}).get("enabled", False),
        "recovery": document.get("recovery", {}),
    }
    if config["host"] != "0.0.0.0":
        raise ConfigurationError("server.host must be 0.0.0.0 for MicroK8s ingress")
    if not isinstance(config["port"], int) or not 1 <= config["port"] <= 65535:
        raise ConfigurationError("server.port must be an integer from 1 through 65535")
    if not isinstance(config["lifecycle_enabled"], bool):
        raise ConfigurationError("lifecycle.enabled must be a boolean")
    recovery = config["recovery"]
    if recovery and not isinstance(recovery.get("enabled", False), bool):
        raise ConfigurationError("recovery.enabled must be a boolean")
    if recovery.get("enabled", False) and not config["lifecycle_enabled"]:
        raise ConfigurationError(
            "recovery.enabled requires lifecycle.enabled"
        )
    timeout = recovery.get("timeout_seconds", 3600)
    if not isinstance(timeout, (int, float)) or not 1 <= timeout <= 7200:
        raise ConfigurationError(
            "recovery.timeout_seconds must be from 1 through 7200"
        )
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
    registry = ComponentRegistry.load()
    cluster = config.get("cluster", {})
    observer = None
    operation_api = None
    operation_store = None
    functional_health_configured = False
    functional_probe = None
    recovery_service = None
    if cluster:
        try:
            functional_probe = (
                UnixFunctionalHealthProbe(Path(cluster["health_probe_socket"]))
                if cluster.get("health_probe_socket")
                else None
            )
            functional_health_configured = functional_probe is not None
            observer = KubernetesObserver(
                cluster["server"],
                Path(cluster["token_file"]),
                Path(cluster["ca_file"]),
                registry,
                namespace=cluster.get("namespace", "fortify"),
                timeout_seconds=cluster.get("timeout_seconds", 5),
                functional_probe=functional_probe,
            )
        except (KeyError, OSError, TypeError, ValueError):
            LOG.warning(
                "protected cluster observation is unavailable; desired inventory "
                "will remain visible"
            )
    if config["lifecycle_enabled"]:
        if observer is None:
            raise ConfigurationError(
                "lifecycle operations require protected cluster observation"
            )
        database = Path(config["state_database"])
        operation_store = OperationStore(database.with_suffix(".operations.sqlite3"))
        approval_store = ApprovalStore(database.with_suffix(".approvals.sqlite3"))
        authorization = AuthorizationService(approval_store)

        def component_states(component_ids: tuple[str, ...]) -> dict[str, str]:
            states: dict[str, str] = {}
            for component_id in component_ids:
                check = next(
                    item
                    for item in registry.monitoring_checks(component_id)
                    if item["type"] == "workload-ready"
                )
                result = observer.probe(
                    CheckSpec(
                        check["id"], component_id, "workload", check["type"],
                        check["target"], min(float(check["timeoutSeconds"]), 10),
                        bool(check["required"]),
                    )
                )
                states[component_id] = (
                    "running" if result.state == "healthy" else result.state
                )
            return states

        engine = OperationEngine(
            registry,
            operation_store,
            MicroK8sLifecycleAdapter(registry),
            RegistryHealthVerifier(registry, observer),
            authorization=authorization,
            state_provider=component_states,
            preflight_provider=lambda: PreflightEngine(
                registry, observer
            ).document(),
            footprint_provider=getattr(observer, "installation_footprint", None),
        )
        recovery_service = _build_recovery(config, registry, database, store)
        operation_api = WebOperationAPI(
            engine, operation_store, authorization, component_states,
            recovery=recovery_service,
        )
        store._lifecycle_stores = (operation_store, approval_store)
    api = ManagerAPI(
        registry_loader=lambda: registry,
        observer=observer,
        health_probe=observer,
        preflight_probe=observer,
        history_reader=StoreHistoryReader(store, operation_store),
        availability_monitor=AvailabilityMonitor(registry, observer),
    )
    observation_state = (
        lambda: ComponentInventory(registry, observer).document()
        .get("observation", {}).get("state", "unavailable")
    ) if observer is not None else None
    return DashboardApp(
        accounts=accounts,
        api=api,
        operation_api=operation_api,
        capability_provider=CapabilityProvider(
            observation_state=observation_state,
            functional_health_configured=functional_health_configured,
            functional_health_state=(
                functional_probe.handshake if functional_probe is not None else None
            ),
            lifecycle_enabled=config["lifecycle_enabled"],
            lifecycle_configured=operation_api is not None,
            approvals_configured=operation_api is not None,
            recovery_configured=recovery_service is not None,
        ),
        secure_cookies=True,
    ), store


def _build_recovery(config, registry, database, parent_store):
    settings = config.get("recovery", {})
    if not settings.get("enabled", False):
        return None
    try:
        destination = Destination(
            settings["destination_id"],
            settings["destination_class"],
            settings["retention_days"],
        )
        socket_path = Path(settings["helper_socket"])
    except (KeyError, TypeError, ValueError) as error:
        raise ConfigurationError("recovery configuration is invalid") from error
    recovery_store = RecoveryStore(database.with_suffix(".recovery.sqlite3"))
    parent_store._recovery_stores = (recovery_store,)
    return RecoveryService(
        recovery_store,
        UnixRecoveryAdapter(
            socket_path, timeout_seconds=settings.get("timeout_seconds", 3600)
        ),
        profile_id=registry.profile.id,
        destination=destination,
    )


def check(config_path: Path, *, cluster: bool = False) -> None:
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
    if cluster:
        registry = ComponentRegistry.load()
        settings = config.get("cluster", {})
        observer = KubernetesObserver(
            settings["server"],
            Path(settings["token_file"]),
            Path(settings["ca_file"]),
            registry,
            namespace=settings.get("namespace", "fortify"),
            timeout_seconds=settings.get("timeout_seconds", 5),
            functional_probe=(
                UnixFunctionalHealthProbe(Path(settings["health_probe_socket"]))
                if settings.get("health_probe_socket")
                else None
            ),
        )
        resources = tuple(
            resource
            for _, resource in ComponentInventory(registry)._desired_resources()
        )
        evidence = observer.diagnose_access(resources)
        LOG.info(
            "registry and protected cluster access valid: namespace=%s node=%s "
            "kubernetes=%s latency_ms=%d",
            evidence.namespace,
            evidence.node,
            evidence.kubernetes_version,
            evidence.latency_ms,
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
        for lifecycle_store in (
            *getattr(store, "_lifecycle_stores", ()),
            *getattr(store, "_recovery_stores", ()),
        ):
            lifecycle_store.close()
        store.close()
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fortify Lab Manager host service")
    parser.add_argument("command", choices=("serve", "check", "diagnose-cluster"))
    parser.add_argument(
        "--config", type=Path, default=DEFAULT_CONFIG, help=argparse.SUPPRESS
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        if args.command in {"check", "diagnose-cluster"}:
            check(args.config, cluster=args.command == "diagnose-cluster")
        else:
            serve(args.config)
    except (ConfigurationError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        LOG.error(
            "manager could not start; run 'sudo fortify-manager diagnose' "
            "for sanitized checks"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
