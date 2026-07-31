# Effective Manager capabilities

`GET /api/v1alpha1/capabilities` is the authenticated, sanitized source of
truth for Web controls. It describes what the running Manager can currently
inspect and mutate; component connectivity alone never implies lifecycle
support. The contract is MicroK8s-first and excludes ASPM.

The current document uses `contractVersion: "1.0"` and expires 45 seconds
after `generatedAt`. The browser refreshes all read models every 30 seconds,
without requiring a new login. An absent, malformed, expired, unknown, or
newer contract disables every mutation control. Previously loaded inventory,
health, history, and operation progress remain available for inspection.

## Capability states

| State | Meaning |
| --- | --- |
| `available` | Effective Manager composition and current prerequisites support the capability. `canMutate` remains authoritative for controls. |
| `disabled` | The operator explicitly disabled the capability in Manager configuration. |
| `not-configured` | Required Manager services or protected adapters were not composed. |
| `unauthorized` | The authenticated identity may inspect the state but cannot use the capability. |
| `degraded` | Partial inspection is useful, but the complete capability is not available. |
| `temporarily-unavailable` | A configured transient prerequisite, such as protected observation, is unavailable. |

The fixed capability IDs are `observation`, `functional-health`,
`lifecycle-execution`, `approvals`, `backup-restore`, `upgrades`,
`secret-workflows`, and `notifications`. Each entry has a stable sanitized
`code`, safe prerequisite codes, a matching remediation code and documentation
link, and separate `canInspect` and `canMutate` booleans. No credentials,
Secret names, paths, adapter targets, raw exceptions, or authorization details
are exposed.

`OPERATIONS_DISABLED` explains explicit `lifecycle.enabled = false`.
`OPERATIONS_UNAVAILABLE` explains incomplete lifecycle composition before a
plan is submitted. `OBSERVER_DISCONNECTED` reports a configured but transiently
unavailable observation prerequisite. The header badge, plan form, execution
and confirmation buttons, cancellation, and retry controls all consume the
same `lifecycle-execution` entry. A retained operation can still be inspected
when those mutation controls are disabled.

The supported operator transition is
`sudo ./scripts/fortify-manager activate-lifecycle`. It publishes `available`
only after protected package, observer, health-probe, credential, positive
permission, negative permission, restart, and service-state checks pass.
`deactivate-lifecycle` revokes mutation without deleting operation history or
lab data. Neither command exposes credential material through this API.

Backup/restore, upgrade, write-only secret, and notification services report
`not-configured` until their independently protected runtime services are
composed. This is intentional while those features remain unavailable; the
browser does not infer support from registry metadata or connectivity.

## Recovery and troubleshooting

Use **Refresh** after correcting Manager configuration or restoring the
allow-listed observer. Auto-refresh performs the same read within 30 seconds
while the page is visible. Recovery changes the same authenticated session's
capability document; signing out and back in is not required.

If the Web client reports `CAPABILITY_CONTRACT_UNSUPPORTED_OR_STALE`, refresh
once. If the state persists, update the Web client and Manager together or
restore Manager clock accuracy. Do not broaden Kubernetes RBAC, add Secret
read permission, or expose helper sockets to make a capability appear
available.

The JSON Schema is
[`manager-capabilities.schema.json`](../registry/schemas/manager-capabilities.schema.json).
Deterministic API and browser coverage is in
[`test_capabilities.py`](../tests/test_capabilities.py). These checks do not
contact a live MicroK8s cluster.
