# Private Telegram manager observability

The manager communications adapter provides private mobile, read-only access
to the Fortify Lab Manager's inventory summary, dependency-aware health,
latest deployment preflight, incidents, and recent history. It consumes only
the versioned manager HTTP API. It does not import a Kubernetes client, run
`kubectl`, read logs or Secrets, accept shell text, or provide lifecycle
operations.

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

The formatter flattens newlines, redacts secret-like assignments, replaces
common protected absolute paths, limits scalar fields, and ignores items past
the page bound. The manager API must still apply its own schema validation and
disclosure policy; transport sanitization is defense in depth.

## Validation

The unit suite uses an in-memory manager port and Telegram transport. It
verifies provider-neutral event mapping, typed callbacks, identity failure,
pagination, response bounds, redaction, HTTP failure mapping, and the two
representative dependency failures required above. These are static and unit
checks only; they do not contact Telegram or a live MicroK8s cluster.
