# ADR 0004: Make a component registry authoritative

- Status: Accepted
- Date: 2026-07-30

## Context

Fortify components have different dependencies, versions, deployment
artifacts, operations, health evidence, configuration, secrets, and
persistence. Duplicating that knowledge across scripts, APIs, and interfaces
causes unsafe ordering and inconsistent availability of actions.

## Decision

Introduce a versioned component registry as the authoritative,
machine-readable catalog of manager-supported components and capabilities.
Each entry has a stable identifier and declares, as applicable:

- display metadata and supported platform-profile constraints;
- dependencies and ordering;
- lifecycle operations and whether they are destructive or disruptive;
- configuration and secret references without secret values;
- persistence, health checks, and verification requirements;
- implementation adapters and exposed communication or UI capabilities.

Consumers derive available operations and dependency graphs from the
registry. Runtime health and operation history remain separate state; the
registry describes capability, not current condition. Registry schemas and
initial entries are implementation tasks kept in GitHub issues.

## Considered alternatives

### Discover all capabilities from the cluster

Discovery reflects deployed resources but cannot reliably express intended
versions, missing dependencies, destructive semantics, or application-level
health.

### Keep metadata in component scripts

This is convenient locally, but forces every consumer to parse or duplicate
shell behavior and prevents schema validation.

### Hard-code component knowledge in each interface

This avoids a registry at first, but creates drift between the API, Web UI,
automation, and documentation.

## Consequences

- Dependency-aware operations and consistent interfaces share one catalog.
- Registry validation can catch cycles, missing references, and unsupported
  combinations before cluster mutation.
- Schema evolution and compatibility rules become ongoing maintenance.
- A stale registry can hide or misrepresent capabilities, so entries must
  change with component behavior.
- Registry membership means manager support, not vendor support or runtime
  health.

## Security and operational implications

The registry contains secret names, classifications, and references only,
never values. Destructive operations are explicitly marked and cannot be
inferred from display text. Adapters still enforce authorization,
idempotency, bounded execution, and post-operation health verification.

## Compatibility and migration

Existing scripts can be registered incrementally through adapters. Registry
schema changes require versioning and validation. Unknown components remain
unmanaged rather than being given inferred actions.

## Related decisions

- [ADR 0002](0002-technology-neutral-control-loops.md)
- [ADR 0003](0003-microk8s-first-scope.md)
- [ADR 0005](0005-write-only-secrets.md)
