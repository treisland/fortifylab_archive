# Local mutation authorization and approvals

All lifecycle mutation entry points use
[`AuthorizationService`](../../manager/authorization.py). Web UI, CLI, and
communications adapters authenticate an envelope and pass an `ActorIdentity`;
they do not decide risk, mint approvals, or execute an operation themselves.
The operation engine enforces the same service before calling an adapter.

## Administrator identity and session boundary

The initial administrator is a locally bootstrapped manager account. Its
stable actor ID is `local:<account-name>`. An identity also binds its source
(`web`, `local-cli`, or `telegram`), an opaque bounded session ID, and the most
recent authentication time.

Web identities come from the existing server-side session. A manager restart
invalidates them. A local CLI identity exists only for an authenticated,
interactive invocation and must not come from a caller-supplied `--actor`
value. Telegram maps the one allowlisted private user/chat pair to a local
account in protected configuration; this authenticates the envelope but does
not turn Telegram into a local or Web session. Adapters never persist
passwords, cookies, provider tokens, or confirmation input.

## Risk policy

| Risk | Operations | Requirement |
| --- | --- | --- |
| Routine | `install`, `configure`, `start` | Authenticated local identity |
| Disruptive | `stop`, `restart` | Matching approved single-use plan |
| High | `upgrade`, `uninstall`, `delete-data` | Matching plan plus fresh Web reauthentication or exact interactive local CLI confirmation |

The high-risk phrase is `AUTHORIZE HIGH-RISK OPERATION`. A Web adapter must
verify the account password again immediately before submitting it. A CLI
reads it from a terminal, never an option or environment variable. Telegram
cannot approve high-risk work. Unknown operations have no risk policy and
fail closed.

## Immutable plan and current-state binding

Before approval, the manager resolves the operation into its complete affected
target set and reads authoritative current state. The SHA-256 plan digest
binds the typed operation, ordered targets, and each target's state. The
approval separately binds actor, source, session, expiry, and its single-use
ID.

State is read again immediately before execution. A plan or state change,
different actor/session/source, expiry, or revocation denies execution. A
state-provider outage fails closed and leaves an approved record unconsumed,
allowing a retry after recovery without authorizing from stale state.

## Replay, concurrency, revocation, and audit

Approval state is stored in manager-owned SQLite. Conditional atomic
transitions ensure exactly one concurrent decision and one consumption can
win. Consumed approvals cannot authorize a retry. The bound actor may revoke a
pending or approved record.

Requests, decisions, revocations, consumption, and denials are appended to
audit history with timestamp, approval ID, actor, action, outcome, and bounded
reason. Audit and approval rows contain no secrets, credentials, provider
payloads, commands, raw cluster evidence, or exception text.

Every adapter displays the resolved operation, targets, risk, and expiry
before confirmation and preserves the authenticated identity unchanged.
Provider availability and Telegram capabilities never downgrade policy.

Tests use isolated SQLite files, synthetic state providers, and an in-memory
operation adapter. They do not contact Telegram or MicroK8s.
