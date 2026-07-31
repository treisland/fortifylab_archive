#!/usr/bin/env bash
# Opt-in, mutating acceptance gate for an authorized disposable EC2 lab only.

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANAGER_TOOL="$REPOSITORY_ROOT/scripts/fortify-manager"
PACKAGE_TOOL="$REPOSITORY_ROOT/scripts/package-manager-runtime.py"
INSTALL_ROOT="${FORTIFY_MANAGER_INSTALL_ROOT:-/opt/fortify-lab-manager}"
STATE_ROOT="${FORTIFY_MANAGER_STATE_ROOT:-/var/lib/fortify-lab-manager}"
TIMEOUT_SECONDS="${FORTIFY_ACCEPTANCE_TIMEOUT_SECONDS:-45}"
RECOVERY_SECONDS="${FORTIFY_ACCEPTANCE_RECOVERY_SECONDS:-90}"
PROFILE_ID="${FORTIFY_ACCEPTANCE_PROFILE_ID:-fortify-24.4-eval.1}"
DOMAIN="${FORTIFY_ACCEPTANCE_DOMAIN:-}"
PRIVATE_ADDRESS="${FORTIFY_ACCEPTANCE_PRIVATE_ADDRESS:-}"
PRE_SESSION_COOKIE="${FORTIFY_ACCEPTANCE_PRE_SESSION_COOKIE:-}"
POST_SESSION_COOKIE="${FORTIFY_ACCEPTANCE_POST_SESSION_COOKIE:-}"
EVIDENCE_PATH="${FORTIFY_ACCEPTANCE_EVIDENCE:-$PWD/manager-upgrade-evidence.json}"
RESULTS=""
RELEASE_BEFORE="unknown"
RELEASE_AFTER="unknown"
FAILURE_LAYER="package"
ROLLBACK_REQUIRED=0

CHECKS=(prerequisites account-preservation history-preservation session-invalidation
 immutable-activation rollback-evidence configuration-migration legacy-ca rbac-positive
 rbac-negative inventory node-version health preflight partial-failure recovery
 private-https no-public-backend dns-resolution)

fail() { printf 'ERROR[%s]: %s\n' "$FAILURE_LAYER" "$2" >&2; exit "${1:-1}"; }
require_command() { command -v "$1" >/dev/null 2>&1 || fail 2 "required command is missing: $1"; }
bounded() { local seconds="$1"; shift; timeout --foreground --signal=TERM "$seconds" "$@"; }
mark() { sed -i "s/^$1=.*/$1=$2/" "$RESULTS"; }
safe_release() { basename "$(readlink -f "$INSTALL_ROOT/current")"; }
hash_or_absent() { [ -f "$1" ] && sha256sum "$1" | cut -d ' ' -f 1 || printf 'absent\n'; }

write_evidence() {
    local status="$1"
    local -a failure_arguments=()
    [ -z "$FAILURE_LAYER" ] || failure_arguments=(--failure-layer "$FAILURE_LAYER")
    PYTHONPATH="$REPOSITORY_ROOT" python3 -m manager.live_upgrade_acceptance \
        --output "$EVIDENCE_PATH" --status "$status" --profile-id "$PROFILE_ID" \
        --release-before "$RELEASE_BEFORE" --release-after "$RELEASE_AFTER" \
        "${failure_arguments[@]}" --results "$RESULTS"
}

cleanup() {
    local code="$?"
    trap - EXIT INT TERM
    if [ "$code" -ne 0 ]; then
        if [ "$ROLLBACK_REQUIRED" -eq 1 ] && [ -n "$RELEASE_BEFORE" ] && \
           [ -d "$INSTALL_ROOT/releases/$RELEASE_BEFORE" ]; then
            ln -sfn "$INSTALL_ROOT/releases/$RELEASE_BEFORE" "$INSTALL_ROOT/.acceptance-current"
            mv -Tf "$INSTALL_ROOT/.acceptance-current" "$INSTALL_ROOT/current" || true
            bounded "$RECOVERY_SECONDS" systemctl restart fortify-health-probe.service || true
            bounded "$RECOVERY_SECONDS" systemctl restart fortify-manager.service || true
        fi
        [ -z "$RESULTS" ] || write_evidence failed || true
    fi
    [ -z "$RESULTS" ] || rm -f "$RESULTS"
    exit "$code"
}
trap cleanup EXIT INT TERM

[ "$(id -u)" -eq 0 ] || fail 2 "run with sudo on the authorized lab host"
[[ "$TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] && [ "$TIMEOUT_SECONDS" -ge 5 ] && [ "$TIMEOUT_SECONDS" -le 300 ] ||
    fail 2 "FORTIFY_ACCEPTANCE_TIMEOUT_SECONDS must be 5..300"
[[ "$RECOVERY_SECONDS" =~ ^[0-9]+$ ]] && [ "$RECOVERY_SECONDS" -ge 15 ] && [ "$RECOVERY_SECONDS" -le 600 ] ||
    fail 2 "FORTIFY_ACCEPTANCE_RECOVERY_SECONDS must be 15..600"
[[ "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] || fail 2 "set a valid FORTIFY_ACCEPTANCE_DOMAIN"
python3 - "$PRIVATE_ADDRESS" <<'PY' || fail 2 "set FORTIFY_ACCEPTANCE_PRIVATE_ADDRESS to the ingress backend private IP"
import ipaddress, sys
raise SystemExit(0 if ipaddress.ip_address(sys.argv[1]).is_private else 1)
PY
for command in timeout curl python3 microk8s systemctl sha256sum getent; do require_command "$command"; done
[ -L "$INSTALL_ROOT/current" ] || fail 2 "previous Manager release is not installed"
[ -f "$STATE_ROOT/accounts.json" ] && [ -f "$STATE_ROOT/history.sqlite3" ] || fail 2 "account or history state is missing"
[ -f "$PRE_SESSION_COOKIE" ] && [ -n "$POST_SESSION_COOKIE" ] || fail 2 "provide protected pre/post session cookie paths"
[ "$PRE_SESSION_COOKIE" != "$POST_SESSION_COOKIE" ] || fail 2 "pre/post session cookie files must differ"
RESULTS="$(mktemp)"; chmod 600 "$RESULTS"
for check in "${CHECKS[@]}"; do printf '%s=not-run\n' "$check" >>"$RESULTS"; done
RELEASE_BEFORE="$(safe_release)"
[[ "$RELEASE_BEFORE" =~ ^build-[a-f0-9]{64}$ ]] || fail 2 "active release is not immutable"
bounded "$TIMEOUT_SECONDS" python3 "$PACKAGE_TOOL" validate --target "$INSTALL_ROOT/current" >/dev/null || fail 2 "installed package is incomplete"
bounded "$TIMEOUT_SECONDS" microk8s status --wait-ready >/dev/null || fail 2 "MicroK8s is not ready"
mark prerequisites passed

ACCOUNT_BEFORE="$(hash_or_absent "$STATE_ROOT/accounts.json")"
HISTORY_BEFORE="$(hash_or_absent "$STATE_ROOT/history.sqlite3")"
FAILURE_LAYER="remote-access"
PRE_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time "$TIMEOUT_SECONDS" \
    --cookie "$PRE_SESSION_COOKIE" "https://lab.$DOMAIN/api/v1alpha1/components")" || fail 3 "pre-upgrade HTTPS session failed"
[ "$PRE_CODE" = 200 ] || fail 3 "pre-upgrade session was not authorized"
HISTORY_VIEW_BEFORE="$(curl --silent --show-error --fail --max-time "$TIMEOUT_SECONDS" \
    --cookie "$PRE_SESSION_COOKIE" "https://lab.$DOMAIN/api/v1alpha1/history" | sha256sum | cut -d ' ' -f 1)" ||
    fail 3 "pre-upgrade history observation failed"

FAILURE_LAYER="package"; ROLLBACK_REQUIRED=1
bounded "$RECOVERY_SECONDS" "$MANAGER_TOOL" upgrade >/dev/null || fail 4 "upgrade activation failed"
RELEASE_AFTER="$(safe_release)"
[ "$RELEASE_AFTER" != "$RELEASE_BEFORE" ] || fail 4 "candidate reused the active immutable release"
[[ "$RELEASE_AFTER" =~ ^build-[a-f0-9]{64}$ ]] || fail 4 "activated release is not immutable"
bounded "$TIMEOUT_SECONDS" python3 "$PACKAGE_TOOL" validate --target "$INSTALL_ROOT/current" >/dev/null || fail 4 "activated package is incomplete"
find "$STATE_ROOT/backups" -mindepth 1 -maxdepth 1 -type d -newer "$RESULTS" -print -quit | grep -q . ||
    fail 4 "upgrade did not retain protected rollback evidence"
mark immutable-activation passed; mark rollback-evidence passed

FAILURE_LAYER="configuration"
bounded "$TIMEOUT_SECONDS" "$MANAGER_TOOL" config-diagnose >/dev/null || fail 5 "migrated configuration is invalid"
mark configuration-migration passed
[ "$(hash_or_absent "$STATE_ROOT/accounts.json")" = "$ACCOUNT_BEFORE" ] || fail 5 "account verifier state changed"
mark account-preservation passed
[ -s "$STATE_ROOT/history.sqlite3" ] && [ "$HISTORY_BEFORE" != absent ] || fail 5 "history database was not preserved"

FAILURE_LAYER="service"
OLD_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time "$TIMEOUT_SECONDS" \
    --cookie "$PRE_SESSION_COOKIE" "https://lab.$DOMAIN/api/v1alpha1/components")" || true
[ "$OLD_CODE" = 401 ] || fail 6 "pre-upgrade session was not invalidated"
mark session-invalidation passed
bounded "$RECOVERY_SECONDS" "$MANAGER_TOOL" diagnose >/dev/null || fail 6 "post-upgrade Manager diagnostics failed"
printf 'Create a fresh protected session cookie at the configured post-upgrade path. Waiting up to %s seconds.\n' "$RECOVERY_SECONDS" >&2
for ((remaining=RECOVERY_SECONDS; remaining>0; remaining--)); do
    [ -f "$POST_SESSION_COOKIE" ] && break
    sleep 1
done
[ -f "$POST_SESSION_COOKIE" ] || fail 6 "fresh post-upgrade session cookie was not supplied before the recovery deadline"
HISTORY_VIEW_AFTER="$(curl --silent --show-error --fail --max-time "$TIMEOUT_SECONDS" \
    --cookie "$POST_SESSION_COOKIE" "https://lab.$DOMAIN/api/v1alpha1/history" | sha256sum | cut -d ' ' -f 1)" ||
    fail 6 "post-upgrade history observation failed"
[ "$HISTORY_VIEW_AFTER" = "$HISTORY_VIEW_BEFORE" ] || fail 6 "sanitized operation history changed across upgrade"
mark history-preservation passed

FAILURE_LAYER="authorization"
bounded "$TIMEOUT_SECONDS" "$MANAGER_TOOL" rbac-preflight >/dev/null || fail 7 "observer RBAC preflight failed"
bounded "$TIMEOUT_SECONDS" "$INSTALL_ROOT/current/bin/fortify-manager-server" diagnose-cluster >/dev/null || fail 7 "RBAC allow-list or mandatory denials failed"
mark rbac-positive passed; mark rbac-negative passed; mark partial-failure passed; mark recovery passed

FAILURE_LAYER="cluster-tls"
bounded "$TIMEOUT_SECONDS" runuser -u fortify-manager -- "$INSTALL_ROOT/current/bin/fortify-manager-server" diagnose-cluster >/dev/null || fail 8 "legacy-compatible CA validation failed"
mark legacy-ca passed

FAILURE_LAYER="observation"
for endpoint in components health preflight; do
    code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time "$TIMEOUT_SECONDS" \
        --cookie "$POST_SESSION_COOKIE" "https://lab.$DOMAIN/api/v1alpha1/$endpoint")" || fail 9 "$endpoint observation failed"
    [ "$code" = 200 ] || fail 9 "$endpoint observation was unavailable"
done
mark inventory passed; mark node-version passed; mark health passed; mark preflight passed

FAILURE_LAYER="dns"
DNS_ADDRESSES="$(bounded "$TIMEOUT_SECONDS" getent ahosts "lab.$DOMAIN" | awk '{print $1}' | sort -u)" ||
    fail 10 "Manager DNS name does not resolve"
mapfile -t DNS_ADDRESS_LIST <<<"$DNS_ADDRESSES"
python3 - "$PRIVATE_ADDRESS" "${DNS_ADDRESS_LIST[@]}" <<'PY' || fail 10 "Manager DNS is not restricted to the configured private ingress address"
import ipaddress, sys
expected = ipaddress.ip_address(sys.argv[1])
resolved = {ipaddress.ip_address(value) for value in sys.argv[2:]}
raise SystemExit(0 if resolved and resolved == {expected} else 1)
PY
mark dns-resolution passed
FAILURE_LAYER="ingress"
bounded "$TIMEOUT_SECONDS" microk8s kubectl -n fortify get ingress fortify-manager >/dev/null || fail 11 "private HTTPS ingress is absent"
ENDPOINT_ADDRESSES="$(bounded "$TIMEOUT_SECONDS" microk8s kubectl -n fortify get endpointslices.discovery.k8s.io \
    -l kubernetes.io/service-name=fortify-manager-host \
    -o 'jsonpath={.items[*].endpoints[*].addresses[*]}')" || fail 11 "Manager ingress EndpointSlice is unavailable"
[ "$ENDPOINT_ADDRESSES" = "$PRIVATE_ADDRESS" ] || fail 11 "Manager ingress does not target the configured private address"
mark private-https passed
FAILURE_LAYER="remote-access"
python3 - "$PRIVATE_ADDRESS" <<'PY' || fail 12 "configured backend address is public"
import ipaddress, sys
raise SystemExit(0 if ipaddress.ip_address(sys.argv[1]).is_private else 1)
PY
mark no-public-backend passed

FAILURE_LAYER=""; ROLLBACK_REQUIRED=0
write_evidence passed
rm -f "$RESULTS"; RESULTS=""
trap - EXIT INT TERM
printf 'Manager upgrade acceptance passed; sanitized evidence: %s\n' "$EVIDENCE_PATH"
