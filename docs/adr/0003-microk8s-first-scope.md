# ADR 0003: Target MicroK8s first and exclude ASPM

- Status: Accepted
- Date: 2026-07-30

## Context

Fortify Lab Manager serves evaluation, training, and demonstration labs. The
project needs one deterministic initial platform instead of claiming broad
Kubernetes compatibility without validation. It also needs a clear product
boundary: Fortify Software Security Center (SSC), ScanCentral SAST,
ScanCentral DAST, LIM, and their infrastructure are in scope, while Fortify
Application Security Posture Management (ASPM) is a separate product domain.

## Decision

The first supported deployment target is a local, single-node MicroK8s lab.
Defaults, validation, documentation, and platform profiles optimize for that
target. Kubernetes-facing contracts should avoid unnecessary MicroK8s
coupling so additional conformant clusters can be evaluated later, but no
support is implied before validation is recorded.

ASPM deployment, configuration, data ownership, integrations, and workflows
are explicitly outside Fortify Lab Manager scope. Generic interfaces must not
silently broaden that boundary.

## Considered alternatives

### Support multiple Kubernetes distributions immediately

This broadens reach, but multiplies ingress, storage, DNS, permissions, and
upgrade combinations before the lifecycle model is stable.

### Build for generic Kubernetes with no reference distribution

This appears portable but leaves defaults and acceptance evidence ambiguous,
making failures difficult to reproduce.

### Include ASPM in the initial component portfolio

This could present a wider Fortify suite, but adds distinct integration and
ownership concerns that distract from a reliable SSC-centered lab.

## Consequences

- Installation and validation can use a reproducible platform baseline.
- MicroK8s-specific addons and operational assumptions must be identified
  rather than presented as universal Kubernetes behavior.
- Other clusters are unsupported until their profiles and lifecycle paths
  have evidence.
- ASPM requests are declined or routed outside this project.
- Future cluster support may require adapters, profile changes, and new
  operational guidance.

## Security and operational implications

MicroK8s remains a lab boundary, not a production security claim. Cluster
privileges are least-privilege where practical, and the manager must not
expose arbitrary Kubernetes access. Additional targets require separate RBAC,
storage, ingress/TLS, backup, upgrade, and secret-handling assessment.

## Compatibility and migration

Current MicroK8s scripts remain the initial compatibility baseline. A future
target must document differences and migration limitations before it is
called supported. Excluding ASPM requires no migration because ASPM behavior
is not part of the product contract.

## Related decisions

- [ADR 0004](0004-component-registry.md)
- [ADR 0008](0008-ssc-system-of-record.md)
