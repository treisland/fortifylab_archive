"""Versioning, protection, atomicity, and rollback tests for manager.toml."""

from __future__ import annotations

import os
import stat
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from manager.config_migration import (
    CURRENT_SCHEMA_VERSION,
    MigrationError,
    inspect,
    migrate,
    rollback,
    validate_document,
)
from manager.server import ConfigurationError, load_config


LEGACY = """# operator comment
[server]
host = "0.0.0.0"
port = 9443

[storage]
database = "/custom/history.sqlite3"

[authentication]
accounts = "/custom/accounts.json"

[operator]
label = "keep-me"
"""


class ConfigMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = self.root / "manager.toml"
        self.backups = self.root / "backups"
        self.access = self.root / "cluster-access"
        self.uid = os.getuid()
        self.gid = os.getgid()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_config(self, text: str = LEGACY) -> None:
        self.config.write_text(text, encoding="utf-8")
        self.config.chmod(0o640)

    def protect_observer(self, mode: int = 0o600) -> None:
        self.access.mkdir(mode=0o700)
        for name, content in (("token", "test-only-opaque"), ("ca.crt", "test-ca")):
            path = self.access / name
            path.write_text(content, encoding="utf-8")
            path.chmod(mode)

    def test_preflight_external_inputs_require_absolute_paths(self) -> None:
        document = tomllib.loads(LEGACY + '\n[preflight]\nlicense_file = "relative.license"\n')
        with self.assertRaisesRegex(MigrationError, "absolute path"):
            validate_document(document)
        document["preflight"]["license_file"] = "/protected/fortify.license"
        self.assertEqual(validate_document(document), 0)

    def run_migration(self):
        return migrate(
            self.config,
            self.backups,
            self.access,
            self.uid,
            self.gid,
            self.uid,
            self.gid,
        )

    def test_legacy_migration_preserves_custom_values_and_is_idempotent(self) -> None:
        self.write_config()
        self.protect_observer()
        backup = self.run_migration()
        migrated = self.config.read_text(encoding="utf-8")
        document = tomllib.loads(migrated)
        self.assertIsNotNone(backup)
        self.assertEqual(document["schema_version"], CURRENT_SCHEMA_VERSION)
        self.assertEqual(document["server"]["port"], 9443)
        self.assertEqual(document["storage"]["database"], "/custom/history.sqlite3")
        self.assertEqual(document["authentication"]["accounts"], "/custom/accounts.json")
        self.assertEqual(document["operator"]["label"], "keep-me")
        self.assertEqual(document["cluster"]["token_file"], str(self.access / "token"))
        self.assertFalse(document["lifecycle"]["enabled"])
        self.assertIn("# operator comment", migrated)
        self.assertIsNone(self.run_migration())
        self.assertEqual(self.config.read_text(encoding="utf-8"), migrated)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)

    def test_current_schema_adds_missing_safe_sections(self) -> None:
        self.write_config(f"schema_version = 1\n\n{LEGACY}")
        self.protect_observer()
        self.assertIsNotNone(self.run_migration())
        document = tomllib.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(document["schema_version"], 1)
        self.assertIn("cluster", document)
        self.assertEqual(document["lifecycle"], {"enabled": False})

    def test_observer_configuration_waits_for_protected_files(self) -> None:
        self.write_config()
        self.protect_observer(mode=0o640)
        self.run_migration()
        document = tomllib.loads(self.config.read_text(encoding="utf-8"))
        self.assertNotIn("cluster", document)
        self.assertFalse(document["lifecycle"]["enabled"])
        report = inspect(self.config, self.access, self.uid, self.gid)
        self.assertIn("observer-files: unavailable", report)
        self.assertNotIn("test-only-opaque", report)
        self.assertNotIn("test-ca", report)

    def test_existing_cluster_and_lifecycle_values_are_not_overwritten(self) -> None:
        custom = (
            LEGACY
            + '\n[cluster]\nserver = "https://10.0.0.2:16443"\n'
            + 'namespace = "custom"\ntimeout_seconds = 9\n'
            + "\n[lifecycle]\nenabled = true\n"
        )
        self.write_config(custom)
        self.protect_observer()
        self.run_migration()
        document = tomllib.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(document["cluster"]["server"], "https://10.0.0.2:16443")
        self.assertEqual(document["cluster"]["namespace"], "custom")
        self.assertEqual(document["cluster"]["timeout_seconds"], 9)
        self.assertTrue(document["lifecycle"]["enabled"])
        self.assertEqual(document["cluster"]["token_file"], str(self.access / "token"))

    def test_table_like_lines_in_multiline_values_are_not_treated_as_sections(self) -> None:
        custom = (
            LEGACY
            + '\nnote = """operator text\\n[lifecycle]\\nstill operator text\\n"""\n'
        )
        self.write_config(custom)
        self.run_migration()
        document = tomllib.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(
            document["operator"]["note"],
            "operator text\n[lifecycle]\nstill operator text\n",
        )
        self.assertEqual(document["lifecycle"], {"enabled": False})

    def test_malformed_ambiguous_and_future_schemas_fail_closed(self) -> None:
        cases = (
            "[server\n",
            f"schema_version = 1\nschema_version = 1\n{LEGACY}",
            f"schema_version = 999\n{LEGACY}",
            f'schema_version = "1"\n{LEGACY}',
        )
        for text in cases:
            with self.subTest(text=text[:24]):
                self.write_config(text)
                original = self.config.read_bytes()
                with self.assertRaises(MigrationError):
                    self.run_migration()
                self.assertEqual(self.config.read_bytes(), original)
        self.write_config(f"schema_version = 999\n{LEGACY}")
        with self.assertRaises(ConfigurationError):
            load_config(self.config)

    def test_runtime_invalid_candidates_fail_closed(self) -> None:
        cases = (
            LEGACY.replace('host = "0.0.0.0"', 'host = "127.0.0.1"'),
            LEGACY + "\n[recovery]\nenabled = true\n",
            LEGACY + "\n[recovery]\ntimeout_seconds = 7201\n",
            LEGACY + '\n[network]\ndomain = "fortifydemo.com"\n',
            LEGACY + '\n[network]\ndomain = "fortifydemo.com"\n'
            'private_backend_address = "184.33.159.224"\n'
            'public_address = "184.33.159.224"\n',
            LEGACY + '\n[network]\ndomain = "fortifydemo.com"\n'
            'private_backend_address = "172.31.30.41"\n'
            'public_address = "2001:4860:4860::8888"\n',
            LEGACY + '\n[network]\ndomain = "fortifydemo.com"\n'
            'private_backend_address = "172.31.30.41"\n'
            'public_address = "192.0.2.10"\n',
        )
        for text in cases:
            with self.subTest(text=text[-48:]):
                self.write_config(text)
                original = self.config.read_bytes()
                with self.assertRaises(MigrationError):
                    self.run_migration()
                self.assertEqual(self.config.read_bytes(), original)

    def test_dual_address_network_model_is_optional_and_loaded(self) -> None:
        self.write_config(
            LEGACY
            + '\n[network]\ndomain = "fortifydemo.com"\n'
            + 'private_backend_address = "172.31.30.41"\n'
            + 'public_address = "184.33.159.224"\n'
        )
        self.run_migration()
        config = load_config(self.config)
        self.assertEqual(config["network"]["private_backend_address"], "172.31.30.41")
        self.assertEqual(config["network"]["public_address"], "184.33.159.224")

    def test_legacy_private_only_address_model_remains_valid(self) -> None:
        self.write_config(
            LEGACY
            + '\n[network]\ndomain = "fortifydemo.com"\n'
            + 'private_backend_address = "172.31.30.41"\n'
            + 'public_address = "172.31.30.41"\n'
        )
        self.run_migration()
        self.assertEqual(
            load_config(self.config)["network"]["public_address"], "172.31.30.41"
        )

    def test_failed_atomic_replacement_leaves_original_active(self) -> None:
        self.write_config()
        original = self.config.read_bytes()
        real_replace = os.replace

        def fail_config_replace(source, target):
            if Path(target) == self.config:
                raise OSError("simulated replacement failure")
            return real_replace(source, target)

        with patch("manager.config_migration.os.replace", side_effect=fail_config_replace):
            with self.assertRaises(OSError):
                self.run_migration()
        self.assertEqual(self.config.read_bytes(), original)

    def test_rollback_validates_backup_protection_and_restores_atomically(self) -> None:
        self.write_config()
        self.protect_observer()
        backup = self.run_migration()
        assert backup is not None
        rollback(self.config, backup, self.backups, self.uid, self.gid)
        self.assertEqual(self.config.read_text(encoding="utf-8"), LEGACY)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o640)
        backup.chmod(0o644)
        with self.assertRaises(MigrationError):
            rollback(self.config, backup, self.backups, self.uid, self.gid)
        outside = self.root / "outside.toml"
        outside.write_text(LEGACY, encoding="utf-8")
        outside.chmod(0o600)
        with self.assertRaises(MigrationError):
            rollback(self.config, outside, self.backups, self.uid, self.gid)


if __name__ == "__main__":
    unittest.main()
