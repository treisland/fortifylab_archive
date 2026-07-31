# Component-aware backup and restore

Fortify Lab Manager coordinates a complete, profile-bound recovery point for
the supported single-node MicroK8s lab. ASPM is not included. The recovery
point covers manager history and authorization state, required configuration
metadata, the MySQL database used by SSC, SSC application state, the protected
SSC `secret.key`, and the PostgreSQL database used by ScanCentral DAST.

The browser-facing Manager never reads database credentials, Kubernetes
Secret values, artifact contents, or destination paths. A separately
protected local recovery helper owns those capabilities. Its Unix socket must
not be accessible to other users. It accepts only the versioned fixed actions
and scopes documented here; it must not accept shell commands, paths, Secret
names, or environment variables from an HTTP request.

## Configure recovery

Create an operator-managed destination in the helper, then configure only its
opaque metadata in `manager.toml`:

```toml
[recovery]
enabled = true
helper_socket = "/run/fortify-lab-manager/recovery-helper.sock"
destination_id = "primary"
destination_class = "local-protected"
retention_days = 30
timeout_seconds = 3600
```

`lifecycle.enabled` must also be true. `destination_id` selects a helper
configuration; it is not a path. The helper must write each backup to a new
staging artifact, calculate a SHA-256 checksum for every scope, and publish it
atomically only after all scopes finish. File modes, encryption, capacity,
off-host copies, retention deletion, and destination credentials remain
helper/operator responsibilities.

## Back up

Review impact before starting:

```bash
fortify-manager-cli --url https://lab.example.test --username operator backup-plan
fortify-manager-cli --url https://lab.example.test --username operator backup --wait 3600
```

The plan reports scope, per-scope consistency method, estimated application
impact, destination class/ID, and retention days. MySQL/SSC and
PostgreSQL/DAST use application-quiesced logical backups. The manager database
uses an online SQLite snapshot. Required metadata and SSC `secret.key` are
captured as protected entries. Values and paths are never returned.

A cancelled, helper-failed, timed-out, or manager-interrupted backup stays
incomplete and cannot be restored. A new backup operation is required; no
operation overwrites an older artifact. Retention continues independently of
component uninstall and persistent-data deletion.

## Restore

Warning: restore replaces covered persistent state and makes the covered
applications unavailable. First inspect the artifact/profile gate:

```bash
fortify-manager-cli --url https://lab.example.test --username operator \
  restore-plan backup-0123456789abcdef0123456789abcdef
```

Restore fails closed unless the artifact is complete and its exact platform
profile equals the selected runtime profile. The Web UI must submit the exact
phrase `RESTORE VERIFIED PLATFORM BACKUP`. The local CLI provides the
equivalent strong confirmation only when `--confirm-restore` is present:

```bash
fortify-manager-cli --url https://lab.example.test --username operator \
  restore backup-0123456789abcdef0123456789abcdef --confirm-restore --wait 3600
```

Scopes restore in reverse dependency-safe order. A failed or interrupted
restore is never reported as rolled back and must not be blindly retried.
Keep applications unavailable, diagnose the helper/destination, inspect the
sanitized operation record, and start a new confirmed restore from the same
complete artifact.

After data is applied, success requires manager readiness, MySQL query, SSC
readiness, PostgreSQL query, DAST readiness, and an SSC `secret.key` identity
match. Evidence records only check ID, state, and bounded result code. A
failed verification makes the restore fail.

## Retention and deletion boundary

Uninstall does not remove backup artifacts. Component `delete-data` and
manager `delete-state` do not remove backup artifacts. Expiring or deleting
retained backups is a separate destination-administration action and is not
exposed by this recovery API.

Repository tests provide static and simulated evidence only. Before using
recovery as an upgrade gate, record a licensed lab exercise against the exact
profile, including interruption and successful application-level recovery.
