# ADR 0001: Use a host-level SDLC supervisor

- Status: Accepted
- Date: 2026-07-30

## Context

Fortify Lab Manager development uses execution, verification, event, and
improvement loops. Work should be able to wait for CI, review, and merge while
the maintainer is away from the EC2 terminal. Telegram is already linked to
one private user, and GitHub is the source of truth for issues and pull
requests.

The solution must not turn Telegram into an arbitrary administrative shell or
allow unattended access to live Fortify workloads, secrets, databases, PVCs,
RBAC, or releases.

## Decision

Run a technology-neutral SDLC supervisor as systemd user services on the EC2
host.

The supervisor:

- stores workflow state, events, and approvals in a local SQLite database;
- polls GitHub periodically through the authenticated `gh` CLI;
- accepts a small command allowlist from one linked private Telegram identity;
- binds merge approvals to a repository, pull request, exact head SHA, and
  expiration time;
- merges only unchanged, mergeable pull requests whose checks have completed
  successfully;
- queues the next open issue in an explicitly configured milestone after a
  merge;
- invokes only an optional, absolute, externally configured runner command.

Telegram approval may authorize a qualifying PR merge. Sensitive platform
operations continue to require a stronger local or Web UI approval workflow.

## Alternatives

### GitHub Actions only

Actions can react to repository events but do not provide the desired private
Telegram command channel or host-local durable control over the coding loop.

### Telegram commands executing shell text

This is flexible but creates an unacceptable remote-command surface and is
rejected.

### LangGraph or another agent framework

The initial state machine does not require an agent framework. Keeping
contracts technology-neutral avoids coupling the product to one runtime.

### GitHub webhooks

Webhooks reduce polling latency but require an externally reachable endpoint.
Polling is simpler for the initial single-host lab; the adapter can be
replaced later.

## Consequences

- Workflow state survives terminal disconnects and service restarts.
- GitHub and Telegram outages delay progress but do not corrupt state.
- Polling introduces bounded latency and API use.
- SQLite and systemd are initial single-host constraints.
- Automatic coding requires a separately configured, bounded runner; the
  supervisor never accepts a runner command from Telegram.
- Maintainers must protect the external configuration and state directories.

## Security and operations

- Telegram bot tokens and linked IDs remain outside Git.
- Approval records contain identifiers and plan digests, never secrets.
- Approval replay, expiry, identity mismatch, and PR-head changes fail closed.
- Every state-changing command and GitHub transition is audited.
- Live Fortify cluster mutations remain outside this supervisor's authority.
