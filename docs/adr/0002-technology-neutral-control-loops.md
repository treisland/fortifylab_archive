# ADR 0002: Define technology-neutral control-loop contracts

- Status: Accepted
- Date: 2026-07-30

## Context

Fortify Lab Manager needs repeatable loops for observing state, planning a
bounded change, obtaining approval when required, executing it, verifying the
result, and recording evidence. Those loops span component lifecycle,
health, development, and improvement workflows. Encoding the architecture in
one agent framework, user interface, or transport would make core safety and
recovery behavior depend on an implementation choice.

## Decision

Define loop behavior through technology-neutral contracts. A loop has typed
inputs and outcomes and explicit states for observation, planning, approval,
execution, verification, completion, failure, cancellation, and recovery as
applicable.

Adapters may implement these contracts with a Web UI, CLI, scheduler,
communications provider, Kubernetes client, or agent runtime. Adapters do not
change authorization, dependency, idempotency, timeout, health-verification,
audit, or secret-handling requirements. Plans and approvals bind to an exact
operation and relevant state version so changed inputs require reevaluation.

Concrete schemas, state machines, and adapters are implementation work and
remain in GitHub issues.

## Considered alternatives

### Bind loops to an agent framework

An agent framework could accelerate orchestration, but would make a current
library's execution model part of the product contract and complicate
non-agent operations.

### Encode loops independently in each interface

This reduces initial abstraction work, but approval and recovery semantics
would drift between the Web UI, automation, and communications channels.

### Use shell scripts as the contract

Scripts suit some deployment steps but do not provide typed state,
authorization boundaries, durable progress, or provider-neutral outcomes.

## Consequences

- Core safety and lifecycle semantics can be tested independently of a UI,
  provider, or orchestration library.
- New adapters must map to the same contract rather than invent workflow
  behavior.
- Contract and adapter versioning add design and compatibility work.
- Some current scripts will need wrappers or refactoring before they can
  participate in managed loops.
- Technology neutrality does not promise support for every runtime.

## Security and operational implications

Authorization is evaluated at the operation boundary, not delegated to a
transport adapter. Audit records contain sanitized identifiers, state
transitions, and outcomes. Long operations require bounded waits,
cancellation semantics, retries appropriate to idempotency, and
application-level verification.

## Compatibility and migration

Existing scripts remain usable during incremental adoption. Bringing one
under management requires an adapter that preserves its current inputs or an
explicit migration; an ADR alone does not change runtime behavior.

## Related decisions

- [ADR 0001](0001-sdlc-supervisor.md)
- [ADR 0004](0004-component-registry.md)
- [ADR 0006](0006-provider-neutral-communications.md)
