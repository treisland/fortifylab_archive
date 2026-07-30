# ADR 0005: Treat submitted secret values as write-only

- Status: Accepted
- Date: 2026-07-30

## Context

Lab setup requires licenses, credentials, service tokens, certificate
material, and SSC `secret.key`. Interfaces need to report whether required
material is configured without turning the manager, its APIs, logs, state, or
support output into a secret-retrieval system.

## Decision

Secret values are write-only after submission through any manager interface.
Create, replace, reference, and delete workflows may accept a value or an
external secret reference, but read APIs and interfaces return only sanitized
metadata such as configured state, source type, consumer references, and
non-sensitive timestamps or fingerprints.

Values are delivered only to their declared protected store and consumers.
They are excluded from operation plans, durable workflow state, events, logs,
errors, diagnostics, backups unless explicitly designed as encrypted secret
backups, and communications. Rotation is an explicit operation with impact
analysis and consumer restart or health verification. SSC `secret.key`,
trust roots, and shared tokens are never rotated incidentally.

Detailed secret workflows and storage adapters remain implementation work in
GitHub issues.

## Considered alternatives

### Allow privileged secret reveal

Reveal can help recovery, but greatly expands authorization, audit, browser,
logging, and support-data exposure paths. Source systems should handle
recovery instead.

### Store reversible values in the manager database

Central storage simplifies retrieval but makes the manager database a
high-value vault without establishing the required key management.

### Accept only existing Kubernetes Secrets

This minimizes manager handling, but makes initial lab setup unnecessarily
difficult and does not cover protected external files.

## Consequences

- A read-path compromise cannot use normal manager APIs to retrieve submitted
  values.
- Interfaces can show readiness without exposing content.
- Lost values cannot be recovered from the manager and must be replaced or
  restored from their authoritative protected source.
- Troubleshooting must rely on metadata and consumer health, not value echo.
- Storage providers need a common metadata and redaction contract.

## Security and operational implications

Secret inputs are redacted at the earliest boundary and never passed through
command-line arguments when a safer file or API mechanism exists. Temporary
material has restrictive permissions and bounded lifetime. Audit events
record the actor, secret identifier, action, and result, never the value.
Deletion of a reference is distinct from destructive deletion of persistent
data.

## Compatibility and migration

Existing repository-local secret scripts are not retroactively made managed
interfaces. Adoption requires inventorying existing stores, preserving SSC
`secret.key`, and migrating references without logging or returning values.
Legacy reveal behavior, if discovered, must be removed through an explicit
migration.

## Related decisions

- [ADR 0002](0002-technology-neutral-control-loops.md)
- [ADR 0004](0004-component-registry.md)
- [ADR 0006](0006-provider-neutral-communications.md)
