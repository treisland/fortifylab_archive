# Changelog

All notable changes will be documented in this file.

The project uses [Semantic Versioning](https://semver.org/) for Fortify Lab
Manager releases. Manager versions are independent of Fortify component
platform profiles.

## [Unreleased]

### Added

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
