# Profile-aware upgrades

Fortify Lab Manager upgrades only between exact versioned platform profiles
whose target profile declares the current profile as an allowed source. A
declared transition is executable only when its release evidence is
`licensed-live`, its upgrade check passed, and it records timeout, expected
downtime, backup requirement, migrations, rollback limitation, and recovery
guidance. Static rendering does not make a transition executable.

The repository's `fortify-24.4-eval.1` profile is experimental and has no
allowed source transitions. It cannot currently be used as an executable
upgrade target. This describes the fail-closed manager contract; it does not
claim that a live upgrade was performed.

## Plan gates

`POST /api/v1alpha1/profile-upgrades/plans` accepts only a
`targetProfileId`. Planning is read-only and collects fresh evidence for:

- the selected source profile and every observed component chart/image version;
- the validated target profile and its exact versions;
- available CPU, memory, and storage against target requirements;
- aggregate current health and every component's dependency-ready state;
- a complete, verified backup bound to the source profile when required;
- changed components, full dependency impact, expected downtime, and timeout;
- database and application migrations, their rollback class, and recovery.

An unknown profile, untested path, version drift, unhealthy layer, missing
dependency evidence, insufficient capacity, or missing backup blocks planning
before an adapter is invoked. The returned SHA-256 digest covers all evidence,
and plans expire after ten minutes by default.

## Confirmation and execution

Submit the exact plan through the authenticated Web UI or local CLI. Copy the
complete `confirmation` value emitted by the plan:

```bash
fortify-manager-cli --url https://lab.example.test --username operator \
  upgrade-plan TARGET_PROFILE_ID

fortify-manager-cli --url https://lab.example.test --username operator \
  upgrade-profile PLAN_ID --confirmation \
  'UPGRADE SOURCE_PROFILE TO TARGET_PROFILE sha256:PLAN_DIGEST'
```

Authentication must be no more than five minutes old. Telegram can observe
sanitized state but cannot confirm or submit a profile upgrade. Immediately
before queueing, the manager reloads the target and recollects source versions,
capacity, health, dependencies, and backup evidence. A digest change rejects
the stale plan; create and review a new one.

Execution is durable, bounded by the transition timeout, and ordered from
dependencies to consumers. Every dependency layer is verified even when its
version did not change. Success means every layer, including final application
consumers, passed health verification. Cancellation is cooperative and never
claims that already-applied migrations were reversed.

## Migration and recovery boundaries

Every ordered step is classified as `reversible`, `compensating-action`,
`restore-required`, or `irreversible`; the strictest item becomes the operation
boundary. A chart/configuration-only failure may use its declared reverse
adapter. Any uncertain database or application migration blocks automatic
rollback and requires restoration and verification of the source-profile
backup named in the operation record. A failed, interrupted, cancelled, or
timed-out migration is not automatically retried or reported as rolled back.
See [Rollback and recovery boundaries](rollback-recovery.md).

Records and errors contain sanitized identifiers and guidance only. They do
not contain credentials, secret values, paths, command output, or database
errors.
