# Changelog

All notable changes will be documented in this file.

The project uses [Semantic Versioning](https://semver.org/) for Fortify Lab
Manager releases. Manager versions are independent of Fortify component
platform profiles.

## [Unreleased]

### Added

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
