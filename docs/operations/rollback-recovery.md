# Rollback and recovery boundaries

Review the recovery class in the Web UI, CLI/API plan, or private Telegram
summary before execution. The Manager uses exactly four classes:

- `reversible` — a configuration or chart revision has an explicit reverse
  adapter and must pass post-rollback health checks;
- `compensating-action` — no exact reversal is available, but a documented,
  typed follow-up can restore service;
- `restore-required` — a database or application migration may have applied;
  do not use Helm rollback as evidence of recovery;
- `irreversible` — neither rollback nor compensation can restore prior state.

Cancellation, timeout, adapter failure, failed health verification, and a
Manager restart do not erase completed-step evidence. Status retains the
current and completed components, sanitized evidence, recovery boundary,
backup identifier, verification state, and next action. A retry creates a new
record and does not rewrite the failed operation.

## Safe automatic rollback

Only `reversible` chart or configuration steps are eligible. The adapter must
apply the declared reverse mutation and record `rollback-verified`. If the
reverse adapter is absent or fails, status becomes
`compensating-action-required`. Never report success from a Helm revision
number alone.

If an adapter fails while applying a migration, assume it may have partially
applied. Automatic rollback is blocked. Recovery is `restore-required`;
restore the complete, verified backup bound to the source profile and verify
every component layer before creating a fresh plan. A missing or unverified
backup is a hard stop.

## Drill procedure

The static definitions in
[`evaluations/rollback-recovery-v0.4/drills.json`](../../evaluations/rollback-recovery-v0.4/drills.json)
cover failed SSC, ScanCentral DAST, database, ingress, and certificate changes.
Repository tests validate classification and evidence without contacting a
cluster.

For a release candidate, run each drill only against a disposable MicroK8s lab
with synthetic data and protected test credentials. Capture the plan,
operation, evidence, health result, and backup/restore verification. The
fixture records `liveClusterExecuted: false`; static validation is not live
recovery evidence.

Certificate replacement remains a controlled secret workflow. The Manager
does not retain private keys to manufacture rollback. Supply the prior
authoritative material through that workflow or perform the declared
compensating action.
