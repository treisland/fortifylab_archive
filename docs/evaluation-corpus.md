# Loop evaluation corpus

The regression corpus in `evaluations/v1alpha1/cases.json` versions
representative inputs and expected outcomes for Fortify Lab Manager control
loops. It is a static, technology-neutral evaluation boundary: tests do not
access MicroK8s, external configuration, or secret material. ASPM is excluded.

Each case contains:

- stable signals that describe the observation without raw logs;
- one expected classification;
- a safe next action, including whether it is automatic or approval-gated;
- redaction categories and synthetic substrings that must not survive in
  evaluated output.

The initial `1.0.0` corpus covers a healthy baseline, database availability
and authentication failures, application readiness, slow initialization,
path and symlink rejection, TLS verification, LIM pool configuration, scanner
registration, retry exhaustion, duplicate observations, secret leakage, and
persistent-data deletion.

## Determinism and versioning

Cases have unique identifiers and contain no clock, network, cluster, or
random inputs. JSON object keys are canonicalized before hashing.
`tests/test_evaluation_corpus.py` pins the canonical SHA-256 digest, validates
the JSON Schema, checks coverage and safe-action constraints, and verifies
that every required redaction assertion is present.

Any change to a signal or expected result must deliberately update both
`corpusVersion` and the pinned digest. Use semantic versioning:

- patch for wording or additive assertions that do not change an expected
  classification or action;
- minor for backward-compatible new cases or fields;
- major for incompatible schema or expectation changes.

Run the local evaluation checks with:

```bash
python3 -m unittest tests.test_evaluation_corpus
```

The corpus describes expected behavior; it does not execute lifecycle
operations. In particular, the persistent-data case expects a blocked,
approval-gated action. Uninstall and persistent-data deletion remain separate.

## 0.2 observable-manager release gate

The general corpus is supplemented by the versioned
`evaluations/observable-manager-v0.2` suite. It proves the deterministic
portion of the complete 0.2 vertical slice: clean manager access, healthy and
dependency-blocked labs, infrastructure degradation, license preflight,
restart recovery, cluster disconnection, runner phases and long quiet work,
stall recovery, adaptive heartbeat cadence, Telegram delivery policy and
recovery, approval/stop security, and cross-surface redaction.

Every scenario explicitly states its expected health, heartbeat, event, API,
UI, Telegram, diagnostic, remediation, and workflow-authorization outcome.
The fixture clock is injected; the suite never sleeps to reach a cadence
boundary. `observations.json` contains only digests of normalized synthetic
outcomes, and `recorded-result.json` pins both input digests. Repository
validation recomputes that result and fails if a scenario is missing, changed,
failed, or accompanied by an unexpected observation.

Evaluation artifacts are intentionally unable to carry multiline or unbounded
text and reject fields for secrets, protected paths, raw prompts, source
excerpts, environment dumps, raw logs, and provider credentials. Diagnostics
are bounded categories with safe documentation links. In particular, a
Telegram delivery failure leaves workflow authorization unchanged.

Run this gate directly with:

```bash
python3 -m unittest tests.test_observable_manager_evaluation
```

This recorded result is deterministic fixture evidence, not live evidence. It
does **not** prove the EC2 Security Group, public DNS, browser trust, a live
MicroK8s installation, real Fortify licenses or images, component performance,
or Telegram provider delivery. The live browser/MicroK8s checklist remains in
the [manager operator guide](operations/manager.md#verification-evidence) and
must be recorded separately by an authorized operator. ASPM, production
hardening, multi-node Kubernetes, and component mutation remain outside 0.2.

## 0.3 controlled-operations milestone gate

The versioned `evaluations/controlled-operations-v0.3` suite gates completion
of milestone 0.3. Its thirteen deterministic scenarios cover dependency
ordering, MySQL blocking SSC, cancellation, timeout, retry, manager restart,
concurrent conflict, stale approval, Telegram outage, unauthorized callbacks,
write-only secret updates, the uninstall/data-deletion boundary, and failed
post-operation health verification.

Each scenario has structured expected plans, event categories, approval state,
terminal state, health outcome, API, Web UI, CLI, Telegram behavior, recovery,
and rollback limitations. The write-only secret scenario additionally requires
redaction across all seven named surfaces: API, UI, CLI, Telegram, logs,
history, and diagnostics. Fixtures contain bounded synthetic classifications
only; raw command output, protected locations, credentials, secret values, and
provider payloads are prohibited.

`recorded-result.json` is the machine-readable milestone gate. It pins the
canonical suite and observation digests, requires all thirteen scenarios to
pass, rejects unexpected observations, and records live evidence as `not-run`.
Run it with:

```bash
python3 -m unittest tests.test_controlled_operations_evaluation
```

This result proves deterministic contract behavior only. It does not prove
real MicroK8s mutation, Fortify image or license behavior, browser rendering,
component timing, or Telegram delivery. Authorized live evidence must be
recorded separately and must never be copied into these fixtures. Rollback is
also intentionally limited: cancellation, timeout, manager restart, and failed
health verification can follow partial mutation, and neither Helm rollback nor
manager recovery is represented as reversing database or schema changes.

## 0.4 verified-platform-lifecycle milestone gate

`evaluations/verified-platform-lifecycle-v0.4` is the final 0.4 milestone
gate. Its twelve deterministic scenarios cover connected inventory, partial
Kubernetes API failure, layered health, clean installation, dependency
ordering, cancellation, retry, backup/restore, profile upgrade, the database
rollback boundary, Manager service restart, and secret safety. Each scenario
records a reproducible local command, expected outcome, browser-facing actual
state, primary root cause, blocked consumers, remediation, and a residual
limitation.

Run the deterministic gate with:

```bash
python3 -m unittest tests.test_verified_lifecycle_evaluation
```

That command does not contact MicroK8s. The checked-in deterministic
observations pass, while the overall milestone intentionally fails because
`live-evidence.json` is `not-run`. Missing, changed, or unexpected fixture
observations also fail. A live record passes only when it is for
`fortify-24.4-eval.1`, marks that profile verified, names single-node
MicroK8s, includes every required lifecycle and browser check, and is
evaluated between its `recordedAt` and `expiresAt` instants.

### Authorized live evidence

Live evaluation is a separate operator activity on a disposable, licensed
lab. It is not part of repository validation. Starting from
`live-evidence.schema.json`, record only bounded classifications and these
reproducible command labels:

- repository gate: `./scripts/validate-repository.sh`;
- connected inventory and browser acceptance:
  `python3 -m unittest tests.test_component_inventory_api tests.test_dashboard`;
- layered health: `python3 -m unittest tests.test_functional_health`;
- clean install and ordering:
  `python3 -m unittest tests.test_manager_installation tests.test_operation_engine`;
- cancellation and retry:
  `python3 -m unittest tests.test_operation_engine`;
- backup and restore: `python3 -m unittest tests.test_backup_restore`;
- upgrade and recovery boundary:
  `python3 -m unittest tests.test_profile_upgrade tests.test_rollback_recovery`;
- restart: `python3 -m unittest tests.test_manager_installation`;
- secret safety:
  `python3 -m unittest tests.test_secret_workflow tests.test_license_file_contract`.

The local commands establish contract behavior; the operator must separately
exercise the equivalent Manager operations and browser views against the
exact live profile. Browser acceptance requires the displayed cluster state
to match sanitized observations, the earliest primary cause to be identified,
all dependency-blocked consumers to be named, and remediation to link to a
safe typed action or operator procedure.

Do not store screenshots, raw logs, credentials, license material, Secret
values, private keys, protected locations, internal hostnames, or environment
dumps. Store only `passed` classifications, bounded command labels, UTC
validity instants, and residual limitations. The suite cannot establish
multi-node behavior, production hardening, vendor workload performance, or
ASPM support.
