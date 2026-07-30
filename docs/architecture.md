# Architecture decisions

Architecture Decision Records (ADRs) capture durable Fortify Lab Manager
constraints. Accepted records are authoritative until another ADR explicitly
supersedes them. Product behavior and implementation status remain defined by
the code, tests, and GitHub issues; an ADR is not evidence that planned
behavior has been implemented.

The accepted component-registry decision is implemented by the
[component registry reference](component-registry.md), its machine-readable
definitions, and validation contracts.

## Accepted decisions

| ADR | Decision |
| --- | --- |
| [0001](adr/0001-sdlc-supervisor.md) | Use a host-level SDLC supervisor |
| [0002](adr/0002-technology-neutral-control-loops.md) | Define technology-neutral control-loop contracts |
| [0003](adr/0003-microk8s-first-scope.md) | Target MicroK8s first and exclude ASPM |
| [0004](adr/0004-component-registry.md) | Make a component registry authoritative |
| [0005](adr/0005-write-only-secrets.md) | Treat submitted secret values as write-only |
| [0006](adr/0006-provider-neutral-communications.md) | Use provider-neutral communications with private Telegram first |
| [0007](adr/0007-deduplicated-github-observations.md) | File deduplicated GitHub observations automatically |
| [0008](adr/0008-ssc-system-of-record.md) | Keep SSC as the application-security system of record |

## Process

Create one ADR for each consequential, durable decision. Each record states
its status, context, decision, alternatives, consequences, security and
operational implications, compatibility impact, and related decisions.
Follow-up implementation work belongs in GitHub issues rather than ADR
checklists.
