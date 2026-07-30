# ADR 0008: Keep SSC as the application-security system of record

- Status: Accepted
- Date: 2026-07-30

## Context

Fortify Lab Manager coordinates installation, configuration, lifecycle,
health, and evaluation of Fortify components. It may display derived status
or initiate bounded operations, but duplicating application-security
projects, versions, findings, audit decisions, and reporting ownership would
create conflicting records and expand the manager's security boundary.

## Decision

SSC remains the authoritative application-security system of record for
application and application-version identity, uploaded analysis results,
issues/findings, audit state, and SSC reporting.

Fortify Lab Manager owns lab infrastructure intent, component registry and
profiles, manager operation and approval history, health observations, and
sanitized references needed to coordinate components. It may cache bounded
derived SSC metadata for display or health verification, with source and
freshness recorded, but it does not become an alternate findings database or
write application-security state except through explicit, audited SSC
operations.

ASPM is not a substitute system of record and remains out of scope.
Integration details and any permitted SSC mutations remain implementation
work in GitHub issues.

## Considered alternatives

### Replicate SSC findings into the manager

This could enable a unified UI, but introduces synchronization, retention,
authorization, audit, schema, and conflict-resolution obligations.

### Make the manager authoritative for all lab state

One database appears simpler conceptually, but contradicts SSC product
ownership and makes manager recovery responsible for security-analysis data.

### Use ASPM as the system of record

This expands scope into a separate product and does not fit the SSC-centered
evaluation foundation.

## Consequences

- Findings, audit decisions, and reporting retain one authoritative owner.
- Manager backup and recovery do not claim to protect SSC application data.
- Some views require live SSC access or clearly marked stale derived data.
- Cross-component workflows must retain SSC identifiers and respect SSC
  authorization.
- The manager cannot offer offline editing of SSC-owned security state.

## Security and operational implications

SSC credentials follow write-only secret handling and least privilege.
Derived data is minimized, sanitized, access-controlled, and assigned a
retention policy. Health checks distinguish connectivity or authentication
failure from component absence and never expose finding content or
credentials in diagnostics.

## Compatibility and migration

Existing SSC data remains in place and requires no import into the manager.
Any prototype that persists SSC-owned mutable state must migrate to
references or be explicitly retired before compatibility is claimed.

## Related decisions

- [ADR 0003](0003-microk8s-first-scope.md)
- [ADR 0004](0004-component-registry.md)
- [ADR 0005](0005-write-only-secrets.md)
