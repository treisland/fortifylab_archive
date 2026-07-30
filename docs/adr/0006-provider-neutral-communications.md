# ADR 0006: Use provider-neutral communications with private Telegram first

- Status: Accepted
- Date: 2026-07-30

## Context

Maintainers need status, observation, and bounded approval interactions away
from the lab terminal. Telegram is the first available private channel, but
workflow meaning and authorization must not be coupled to Telegram message
formats or identity primitives.

## Decision

Define provider-neutral communication events, commands, responses, identity
bindings, delivery outcomes, and approval references. Provider adapters map
those contracts to external services.

The first adapter is a Telegram bot restricted to one explicitly allowlisted
user in one private chat. It exposes only typed, allowlisted commands and
never arbitrary shell, filesystem, Kubernetes, secret, or GitHub access.
Delivery is retryable and idempotent where possible. A communications outage
does not bypass approval or change authoritative workflow state.

Sensitive platform operations require the stronger local or Web UI approval
policy defined by their operation; availability in a communications adapter
does not grant authority. Additional providers require their own threat
model and adapter implementation in GitHub issues.

## Considered alternatives

### Make Telegram the workflow API

This is fast for the initial channel, but couples commands, identities, and
delivery semantics to one provider.

### Use email as the first provider

Email is ubiquitous but has weaker interactive command ergonomics and
different threading, latency, and identity risks.

### Defer remote communications

This minimizes exposure but prevents bounded oversight while maintainers are
away from the terminal.

## Consequences

- Core workflows can support future providers without changing their safety
  semantics.
- Private Telegram supplies an intentionally narrow first experience.
- Provider adapters must handle formatting limits, retries, duplicates, and
  identity mapping.
- Provider neutrality adds contracts that a Telegram-only implementation
  would not need.
- No provider is an authoritative store for workflow or secret state.

## Security and operational implications

Provider credentials and linked identity values remain in protected external
files or secret stores and are never returned. Incoming commands fail closed
on identity, chat type, authorization, expiry, or state mismatch. Outgoing
messages are sanitized. Rate limits and outages delay notification but do not
authorize actions or lose durable workflow state.

## Compatibility and migration

The existing supervisor's private Telegram behavior is the initial adapter
baseline. Its command semantics can move behind provider-neutral contracts
without changing the allowlisted user experience. Adding a provider is
additive and does not automatically link identities or approvals across
providers.

## Related decisions

- [ADR 0001](0001-sdlc-supervisor.md)
- [ADR 0002](0002-technology-neutral-control-loops.md)
- [ADR 0005](0005-write-only-secrets.md)
- [ADR 0007](0007-deduplicated-github-observations.md)
