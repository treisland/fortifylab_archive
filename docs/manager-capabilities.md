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
The Web UI presents these technical states as the operator-facing labels
`available`, `disabled-by-policy`, `setup-required`, `unauthorized`,
`temporarily-unavailable`, and `unsupported`. `disabled-by-policy` and
`unsupported` are informational states, setup and transient failures are
warnings, and authorization failures are errors. These labels must not be
interpreted as workload health.

The fixed capability IDs are `observation`, `functional-health`,
`lifecycle-execution`, `approvals`, `backup-restore`, `upgrades`,
`secret-workflows`, and `notifications`. Each entry has a stable sanitized
`code`, safe prerequisite codes, a matching remediation code and documentation
link and summary, and separate `canInspect` and `canMutate` booleans. Entries
also identify their `observation` or `mutation` category, responsible boundary,
and evidence timestamp. The dashboard renders those two categories separately:
disabled lifecycle mutation never changes observed workload or functional
health evidence. No credentials,
Secret names, paths, adapter targets, raw exceptions, or authorization details
are exposed.

`OPERATIONS_DISABLED` explains explicit `lifecycle.enabled = false`.
`OPERATIONS_UNAVAILABLE` explains incomplete lifecycle composition before a
plan is submitted. `OBSERVER_DISCONNECTED` reports a configured but transiently
unavailable observation prerequisite. The header badge, plan form, execution
and confirmation buttons, cancellation, and retry controls all consume the
same `lifecycle-execution` entry. A retained operation can still be inspected
when those mutation controls are disabled.

Composition is necessary but never sufficient. Every document freshly checks
the protected observer, functional-probe handshake, lifecycle credential
metadata, complete packaged adapter closure, approval database, recovery helper
socket, upgrade service, secret service, and notification provider when those
services are configured. A missing lifecycle credential reports
`LIFECYCLE_CREDENTIAL_UNAVAILABLE`; a missing declared adapter reports
`LIFECYCLE_ADAPTER_UNAVAILABLE`. A configured dependent service that cannot
answer its bounded runtime check is `temporarily-unavailable`, not `available`.
Raw paths, socket names, credentials, and exceptions are never returned.

The supported operator transition is
`sudo ./scripts/fortify-manager activate-lifecycle`. It publishes `available`
only after protected package, observer, health-probe, credential, positive
permission, negative permission, restart, and service-state checks pass.
`deactivate-lifecycle` revokes mutation without deleting operation history or
lab data. Neither command exposes credential material through this API.

Approvals, backup/restore, upgrade, write-only secret, and notification
services retain the compatible API state `not-configured` but are presented as
`unsupported` until their independently protected runtime services are
composed and successfully checked. This is intentional while those features
remain unavailable; the
browser does not infer support from registry metadata or connectivity.

If the MicroK8s arguments request RBAC but the running API-server process
predates that change, lifecycle reports `RBAC_RESTART_REQUIRED` with
`desired=RBAC`, `effective=previous-authorization`, and
`action=restart-required`. Mutation remains disabled. Follow the documented
MicroK8s restart workflow, verify the observer and lifecycle least-privilege
allow/deny probes, and refresh. The Manager never treats an arguments-file
change alone as proof that RBAC is active. The privileged
`install-cluster-access` workflow performs that comparison and atomically
publishes a three-field sanitized activation document as `root:fortify-manager`
mode `0640`; the unprivileged Web Manager never reads MicroK8s arguments or
process metadata. Symlinked, oversized, malformed, incorrectly owned, or
incorrectly permissioned evidence is ambiguous and never enables mutation.
Explicit lifecycle-disabled and lifecycle-not-composed policy states take
precedence over this infrastructure transition. Rolling back the arguments must be
an explicit operator decision; disabling lifecycle is the safe application
rollback and does not stop or uninstall deployed workloads.

The lifecycle credential check reads file metadata and access state only; it
does not read or return credential content. A bounded authorization probe must
both allow a namespace-scoped lifecycle permission and deny Secret reads;
failure reports `LIFECYCLE_CREDENTIAL_UNAUTHORIZED`. Adapter closure checks verify the
fixed registry-declared files under the installed `apps` tree without running
them. Authorization is evaluated for the authenticated identity before an
available mutation state is emitted.

## Recovery and troubleshooting

Use **Refresh** after correcting Manager configuration or restoring the
allow-listed observer. Auto-refresh performs the same read within 30 seconds
while the page is visible. Recovery changes the same authenticated session's
capability document; signing out and back in is not required.

For `functional-health`, composition means a successful versioned handshake
with the protected socket. Merely configuring
`cluster.health_probe_socket` yields
`FUNCTIONAL_PROBE_HANDSHAKE_FAILED` and `temporarily-unavailable` until the
service is live and the socket policy is valid.

Use this decision order for a mutation failure:

1. `disabled`: activate lifecycle through the protected operator workflow.
2. `not-configured`: complete the named protected Manager setup.
3. `unauthorized`: reauthenticate; do not widen Kubernetes RBAC.
4. `temporarily-unavailable`: restore the named credential, socket, store, or
   observer and refresh. The next request rechecks it automatically.
5. `degraded`: repair the packaged lifecycle adapter closure before planning.
6. `available`: consult the selected action's preflight readiness; lifecycle
   capability alone does not make every action ready.
7. `unsupported` presentation: install and verify the named independently
   protected service; do not advertise it from registry metadata alone.

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
