# Changelog

## Unreleased

- Add a release-blocking 0.4 operational-console browser evaluation contract
  with deterministic desktop and narrow journeys, exact-profile sanitized live
  evidence, Telegram/audit correlation, and an explicit unavailable default.
- Add first-class Deploy, Start, and Suspend Lab plans with component-centered
  graph expansion, dependency-ordered health gates, reverse-order safe
  suspension, durable progress/retry/restart recovery, shared approval state,
  explicit impact and duration evidence, and a preservation-only data boundary.
- Add registry-curated Manager, SSC, SAST, LIM, and DAST Core quick links with
  bounded Manager-host DNS/TLS/HTTP availability, latency, evidence time,
  jittered backoff, compact recovery history, strict redirect/SSRF boundaries,
  and explicit separation from application and client-network health.
- Add a responsive, filterable component explorer with keyboard/pointer
  selection, safe deep links, dependency highlighting, and an accessible
  right-side inspector for desired and observed component context.
- Add a versioned, expiring effective Manager capability API covering
  observation, functional health, lifecycle, approvals, recovery, upgrades,
  secret workflows, and notifications; make all Web mutation controls and
  the header badge fail closed from the same sanitized state while preserving
  inspection and bounded no-login recovery.
- Render all six dashboard evidence panels progressively with cancellable
  eight-second reads, non-overlapping refresh generations, retained evidence,
  honest per-panel observation/refresh times, derived counts, and bounded
  concurrent aggregate health and preflight evaluation.
- Add a versioned 0.4 verified-platform-lifecycle evaluation suite covering
  inventory, partial API failure, layered health, lifecycle and recovery,
  browser acceptance, and secret safety, with a fail-closed fresh,
  exact-profile live MicroK8s evidence contract.
- Classify lifecycle and profile-upgrade recovery as reversible,
  compensating-action, restore-required, or irreversible; expose the boundary
  before execution; retain failure evidence; safely reverse eligible chart
  changes; and add static SSC, DAST, database, ingress, and certificate drills.
- Add profile-aware, evidence-digest-bound upgrade plans with tested-transition,
  capacity, health, dependency, backup, downtime, timeout, migration,
  strong-confirmation, Telegram-exclusion, ordered verification, interruption,
  and rollback-boundary gates.
- Add durable, profile-bound component-aware backup and restore planning,
  strong restore confirmation, protected helper isolation, sanitized recovery
  evidence, and application-level verification.

All notable changes will be documented in this file.

The project uses [Semantic Versioning](https://semver.org/) for Fortify Lab
Manager releases. Manager versions are independent of Fortify component
platform profiles.

## [Unreleased]

- Make dashboard read models independently actionable during partial and
  disconnected failures, with retained stale evidence, observer/node/version
  and evidence-age context, root-cause and blocked-consumer summaries,
  sanitized error codes, session-aware bounded refresh, and accessible
  panel-local recovery guidance.
- Compose the authenticated Manager with a protected, least-privilege
  MicroK8s observer so desired inventory remains visible during failures and
  live component, health, preflight, node, namespace, version, freshness, and
  latency evidence is available without Secrets, logs, or mutation access.

### Added

- Deterministic local 0.4 release-candidate preparation with bounded
  tracked-file packaging, sensitive-input rejection, checksums, SPDX SBOM,
  profile/lifecycle evidence, vulnerability and signature status,
  documentation references, and objective fail-closed go/no-go gates.
- Verified clean-install orchestration for the complete selected profile with
  fresh fail-closed preflight, workload/PVC collision detection, dependency
  ordering, durable resume evidence, functional completion gates, and shared
  Web/API/CLI/history/Telegram-visible progress.
- A bounded local MicroK8s lifecycle adapter that revalidates exact
  registry-declared actions, fixes namespace/root/environment, cooperatively
  cancels and times out child actions, discards action output, verifies only
  registry-declared functional health, and ships a separate namespace Role
  with no Kubernetes Secret read access.
- A schema-validated, versioned platform profile contract shared by registry,
  preflight, Web UI, CLI, and release evidence, with an experimental Fortify
  24.4 baseline, exact pins and capacity, fail-closed compatibility, and
  documented deprecation and forward migration.
- Layered functional health for databases, SSC, ScanCentral SAST/DAST, LIM,
  DNS, ingress, TLS, and storage, with a protected credential-isolating probe
  boundary, earliest-root blocking, bounded sanitized evidence, and recovery
  coverage.
- A versioned, machine-checked 0.3 controlled-operations milestone gate
  covering lifecycle ordering and recovery, approvals, Telegram failures,
  write-only secrets, destructive boundaries, completion health, interface
  parity, and seven-surface secret redaction while separating fixture and live
  evidence.
- Local CLI and authenticated HTTP API parity for typed lifecycle plans,
  authorization, session-bound approvals, durable progress, cancellation,
  retries, and completion health, with versioned secret-safe JSON, stable
  automation exit statuses, recovery examples, and cross-interface contracts.
- Policy-bounded private Telegram lifecycle approvals and incident recovery
  actions with immutable plan digests, opaque single-use callbacks,
  authoritative state revalidation, Web UI escalation, and deep links.
- Authenticated Web lifecycle plan, approval, progress, cancellation, retry,
  reconnect, completion-health, and sanitized-failure contracts while keeping
  the live MicroK8s adapter boundary fail closed.
- An authorized, transport-neutral write-only secret replacement workflow for
  protected external paths, bounded uploads, existing Kubernetes Secret
  references, and generated values, with metadata-only history, explicit
  impact plans, targeted restart/health verification, rollback boundaries,
  interrupted-update recovery, and SSC `secret.key` safeguards.
- Shared local authorization and risk-based, state-bound, expiring,
  revocable, single-use lifecycle approvals across Web, CLI, and
  communications identities, with stronger high-risk confirmation and
  fail-closed audit behavior.
- A typed, dependency-aware lifecycle operation engine with durable progress,
  bounded retry and timeout, cancellation, conflict rejection, post-operation
  health verification, and restart recovery.
- Controlled Telegram-approved milestone rollover using an ordered external
  allowlist, closed-milestone revalidation, durable audit state, and immediate
  dispatch of the next eligible issue, with compact contextual action rows.
- A versioned, machine-checked 0.2 observable-manager evaluation gate covering
  manager, health, workflow, Telegram, recovery, cadence, authorization, and
  cross-surface redaction scenarios with deterministic and live evidence kept
  explicitly separate.
- Detailed private Telegram workflow cards, adaptive real heartbeat
  notifications, restart-safe deduplication, stall/recovery alerts, durable
  details, watch controls, and policy-gated two-step audited runner Stop.
- Atomic, sanitized bounded-runner heartbeat documents with explicit phases,
  activity-age health, restart fencing, bounded terminal retention, and
  operator/JSON-schema contracts.
- A deterministic 0.2 manager host installation and upgrade path with
  protected external configuration/state, systemd ownership, authentication
  bootstrap, `lab.$DOMAIN` MicroK8s ingress using the existing wildcard TLS
  Secret, sanitized diagnostics, and separate uninstall/state deletion.
- A secure, same-origin read-only Web dashboard with authenticated sessions,
  whole-lab summary, dependency/version map, health root cause and evidence,
  remediation, preflight, sanitized recent history, accessible state badges,
  and explicit loading, empty, failure, and disconnected-cluster views.
- A repeatable, fail-closed deployment preflight report covering capacity,
  MicroK8s/addons, storage, ingress, DNS/TLS, licenses, registries/images,
  configuration, and compatibility with actionable, secret-safe blockers.
- Bounded, secret-safe, dependency-aware environment health for MicroK8s
  infrastructure and managed Fortify components, including explicit degraded,
  unhealthy, unknown, blocked, and stale states.
- Repository governance and contribution guidance.
- Baseline repository validation and lifecycle regression checks.
- Foundational Fortify Lab Manager architecture decisions and their index.
- Private Telegram and GitHub SDLC supervisor with durable approvals,
  merge-state monitoring, and automatic next-issue queueing.
- An authoritative, schema-validated component registry shared by lifecycle
  and monitoring contracts for MySQL, PostgreSQL, SSC, LIM, ScanCentral SAST,
  and ScanCentral DAST.
- Versioned, technology-neutral contracts for operation progress, health,
  events, incidents, expiring plan approvals, and sanitized traces.
- Restart-safe local history for versioned operations, progress transitions,
  events, incidents, approvals, and traces with transactional migrations,
  pre-persistence redaction, bounded retention, and malformed-row quarantine.
- A versioned, deterministic loop evaluation corpus with representative
  success and failure classifications, safe actions, and redaction assertions.
- The accepted minimum 0.2 manager runtime boundary for its read-only API,
  local persistence, authentication, Web UI, and namespace-scoped Kubernetes
  access.
- A schema-versioned, read-only manager component inventory API with desired
  resources, sanitized cluster observations, and explicit unavailable state.
- Telegram inline PR approval controls backed by opaque expiring single-use
  callbacks and one editable milestone, issue, runner, and PR workflow card.
- Protected Telegram notification preferences with quiet hours, failure-only
  delivery, durable digests, deduplication, sanitized failure recovery, and
  allowlisted idempotent retry requests.
- Provider-neutral, bounded manager observability commands with private
  Telegram buttons for lab summary, dependency-aware health, preflight,
  incidents, history, recovery notifications, and Web UI deep links.

### Fixed

- Manager route configuration now preserves the prior external configuration
  when MicroK8s rejects an update, diagnostics detect live route drift and a
  missing wildcard TLS Secret, and failed upgrades attempt to restore the
  previously active service.
- ScanCentral SAST lifecycle operations now use the chart's actual sensor
  StatefulSet consistently.
- ScanCentral DAST Core stop now scales down each StatefulSet created by the
  chart.
- Fresh-clone version pins are documented as an intentional, unverified
  evaluation bundle rather than a supported platform profile.
- SSC `secret.key` is preserved when generated secret artifacts are rebuilt,
  and its recovery and deliberate-rotation boundary is documented.
- Repository licensing and lab support boundaries are explicit and
  link-validated.
