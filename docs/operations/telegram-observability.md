# Private Telegram manager observability

The manager communications adapter provides private mobile access
to the Fortify Lab Manager's inventory summary, dependency-aware health,
latest deployment preflight, incidents, and recent history. It consumes only
the versioned manager HTTP API. It does not import a Kubernetes client, run
`kubectl`, read logs or Secrets, or accept shell text. Lifecycle operations
remain limited to the bounded approval and recovery actions below.

This is a MicroK8s-first lab feature. It does not add multi-cluster behavior
or ASPM support.

## Boundary and integration

[`manager/communications.py`](../../manager/communications.py) contains the
provider-neutral command, action, message, recovery-event, and manager-client
contracts. [`manager/telegram_observer.py`](../../manager/telegram_observer.py)
only authenticates Telegram envelopes and translates typed callbacks. A
different communications provider can reuse the same service without
changing manager semantics.

The adapter reads these manager resources:

| Command | Manager request | Web UI link |
| --- | --- | --- |
| `/lab` | `GET /api/v1alpha1/summary` | `/` |
| `/health [component]` | `GET /api/v1alpha1/health` | `/health` |
| `/preflight` | `GET /api/v1alpha1/preflight` | `/preflight` |
| `/incidents [page=N]` | `GET /api/v1alpha1/incidents` | `/incidents` |
| `/history [page=N]` | `GET /api/v1alpha1/history` | `/history` |

Every request has a bounded timeout and page size. Responses are capped at ten
items and 3,500 characters. Manager documents provide the authoritative
freshness, evidence, root-cause, remediation, and pagination fields; Telegram
does not reconstruct them from cluster state.

The HTTP client accepts only the five allowlisted resources and sends a
protected manager bearer credential. Supply that credential from the
runtime's protected external configuration or secret store. Do not put the
credential, Telegram bot token, linked IDs, or manager session material in
this repository, command-line arguments, logs, or messages. The client never
returns the credential or an upstream response body in an error.

## Health presentation

Health records use the states returned by the manager. Root and independently
unhealthy components are listed before records with `status: blocked`, so a
MySQL failure is shown before blocked SSC and ScanCentral SAST, and
PostgreSQL/LIM failures are shown before blocked ScanCentral DAST.

Each response labels freshness and the observation time. Evidence is bounded
to a safe summary and check time. A remediation is displayed only when the
manager explicitly marks it `safe: true`; detailed or sensitive recovery
remains in the authenticated Web UI.

Manager `health.recovered` and `incident.resolved` events map to a
provider-neutral recovery message with a stable replacement key. The
delivery runtime can use that key to replace the corresponding failure
notification rather than creating an unbounded stream.

## Lifecycle approvals and recovery

The provider-neutral remote action service can send an immutable summary of a
manager-generated lifecycle plan to the linked private Telegram identity. The
summary identifies dependency impact, aggregate bounded timeout, rollback
boundary, expiry, Web UI deep link, and a short reference to the full SHA-256
plan digest. The complete immutable snapshot is stored by the manager;
Telegram callback data contains only a random opaque reference.

Remote approval is limited by shared policy to disruptive, non-high-risk
operations. Uninstall, persistent-data deletion, database restore, secret
rotation, and every upgrade require stronger confirmation in the authenticated
Web UI or local CLI. Migration-bearing upgrades are therefore never remotely
approvable.

Callbacks expire with the approval, are bound to the linked actor and private
chat session, and transition transactionally from pending to executing to
consumed. Replays and concurrent decisions fail closed. Immediately before
execution, the operation engine rereads authoritative target state and compares
the full plan digest. Health or state drift invalidates the approval.

Known recovery notifications may offer only actions applicable to current
manager state:

- acknowledge an incident through the manager incident service;

- safely retry a failed, timed-out, or interrupted routine operation;

- cancel non-terminal work at the engine's cooperative cancellation boundary;

- pause automation through its authoritative manager service.

Every result links to the corresponding Web UI detail. Destructive recovery,
arbitrary commands, paths, secret values, and Kubernetes inputs are never
accepted. Retry and cancellation retain their normal durable history and
health verification.

## Failure behavior

- Stale manager data is displayed with `Freshness: stale`; it is not presented
  as current.
- A disconnected or timed-out manager produces a bounded unavailable message.
  The adapter does not fall back to MicroK8s.
- A rejected manager credential asks the operator to reconnect the protected
  session locally and does not expose upstream detail.
- A manager `429` produces a retry-later response and includes `Retry-After`
  only when it is a valid integer.
- Telegram updates from any user or chat other than the single allowlisted
  identity in the allowlisted private chat are ignored.
- Invalid and expired typed callbacks fail closed.
- Telegram delivery failure never creates, approves, consumes, retries, or
  cancels an operation. If the manager is unavailable while processing an
  already approved callback, the opaque action returns to pending until expiry;
  authoritative approval and operation state remain unchanged.

The formatter flattens newlines, redacts secret-like assignments, replaces
common protected absolute paths, limits scalar fields, and ignores items past
the page bound. The manager API must still apply its own schema validation and
disclosure policy; transport sanitization is defense in depth.

## Validation

The unit suite uses an in-memory manager port and Telegram transport. It
verifies provider-neutral event mapping, typed callbacks, identity failure,
pagination, response bounds, redaction, HTTP failure mapping, and the two
representative dependency failures required above. These are static and unit
checks only; they do not contact Telegram or a live MicroK8s cluster. The
remote-action suite additionally covers immutable plans, stale health, expiry,
replay, provider outage, policy rejection, retry, cancel, incident
acknowledgement, automation pause, and unauthorized callbacks.
