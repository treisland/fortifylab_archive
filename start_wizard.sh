#!/bin/bash
# start_wizard.sh — Fortify Lab management wizard
#
# Interactive menu for deploying, configuring, and operating the
# Fortify Helm-based lab. Run as your normal user (not root). The
# wizard sudo's only commands that genuinely need it (apt, snap).
# Cluster ops use plain kubectl/helm — no sudo needed when you're
# in the microk8s group.

set -o pipefail


# ============================================================
# Locate FORTIFY_HOME_K8S, source .env
# ============================================================

if [ -z "${FORTIFY_HOME_K8S:-}" ]; then
    FORTIFY_HOME_K8S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    export FORTIFY_HOME_K8S
fi

ENV_FILE="$FORTIFY_HOME_K8S/.env"
ENV_EXAMPLE="$FORTIFY_HOME_K8S/.env.example"


# ============================================================
# Visual helpers (respect NO_COLOR)
# ============================================================

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD="$(tput bold 2>/dev/null || true)"
    DIM="$(tput dim 2>/dev/null || true)"
    RED="$(tput setaf 1 2>/dev/null || true)"
    GREEN="$(tput setaf 2 2>/dev/null || true)"
    YELLOW="$(tput setaf 3 2>/dev/null || true)"
    BLUE="$(tput setaf 4 2>/dev/null || true)"
    RESET="$(tput sgr0 2>/dev/null || true)"
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; RESET=""
fi

OK_MARK="${GREEN}✓${RESET}"
WARN_MARK="${YELLOW}⚠${RESET}"
FAIL_MARK="${RED}✗${RESET}"
INFO_MARK="${BLUE}ℹ${RESET}"

hr()       { printf '%s\n' "────────────────────────────────────────────────────────────"; }
title()    { clear; printf '\n%s%s%s\n' "$BOLD" "$1" "$RESET"; hr; }
section()  { printf '\n%s%s%s\n' "$BOLD" "$1" "$RESET"; }
press_any(){ printf '\n'; read -rp "Press Enter to continue... " _; }
ask()      { local _v="$1"; shift; read -rp "$* " "$_v"; }
confirm()  { local r; read -rp "$1 [y/N] " r; [[ "$r" =~ ^[Yy]$ ]]; }
error()    { printf '%s %s\n' "$FAIL_MARK" "$*" >&2; }
note()     { printf '%s %s\n' "$INFO_MARK" "$*"; }


# ============================================================
# Cluster CLI detection (microk8s vs upstream)
# ============================================================

if command -v microk8s &>/dev/null; then
    KUBECTL="microk8s kubectl"
    HELM="microk8s helm"
elif command -v kubectl &>/dev/null; then
    KUBECTL="kubectl"
    HELM="helm"
else
    KUBECTL=""
    HELM=""
fi


# ============================================================
# Source .env (creates from .env.example on first run)
# ============================================================

bootstrap_env() {
    if [ ! -f "$ENV_FILE" ]; then
        if [ -f "$ENV_EXAMPLE" ]; then
            cp "$ENV_EXAMPLE" "$ENV_FILE"
            note "Created $ENV_FILE from .env.example."
            note "Edit it (option 11) to set your domain, passwords, and image versions."
            press_any
        else
            error "Neither .env nor .env.example found in $FORTIFY_HOME_K8S."
            exit 1
        fi
    fi
    # shellcheck disable=SC1090
    source "$ENV_FILE"
}


# ============================================================
# App registry — single source of truth for the apps menu
# ============================================================

APP_LABEL=("MySQL" "PostgreSQL" "SSC" "LIM" "ScanCentral SAST" "ScanCentral DAST")
APP_PODS=("mysql"  "postgresql" "ssc-webapp" "lim" "scancentral-sast" "sdast")
APP_URL_VAR=(""    ""           "SSC_URL"    "LIM_URL" "SCSAST_CTRL_URL" "SCDAST_URL")
APP_START=(
    "apps/mysql/start.sh"
    "apps/postgresql/start.sh"
    "apps/ssc/start.sh"
    "apps/lim/start.sh"
    "apps/scsast/start.sh"
    "apps/scdast/core/start.sh apps/scdast/scanner/start.sh"
)
APP_STOP=(
    "apps/mysql/stop.sh"
    "apps/postgresql/stop.sh"
    "apps/ssc/stop.sh"
    "apps/lim/stop.sh"
    "apps/scsast/stop.sh"
    "apps/scdast/core/stop.sh apps/scdast/scanner/stop.sh"
)
APP_DESTROY=(
    "apps/mysql/destroy.sh"
    "apps/postgresql/destroy.sh"
    "apps/ssc/destroy.sh"
    "apps/lim/destroy.sh"
    "apps/scsast/destroy.sh"
    "apps/scdast/core/destroy.sh apps/scdast/scanner/destroy.sh"
)


# ============================================================
# Status checks (cheap; called every menu render)
# ============================================================

cluster_reachable() { [ -n "$KUBECTL" ] && $KUBECTL cluster-info &>/dev/null; }

status_prereqs() {
    local missing=()
    command -v java     &>/dev/null || missing+=("java")
    command -v docker   &>/dev/null || missing+=("docker")
    command -v microk8s &>/dev/null || missing+=("microk8s")
    command -v mkcert   &>/dev/null || missing+=("mkcert")
    if [ ${#missing[@]} -eq 0 ]; then
        printf '%s Prerequisites installed\n' "$OK_MARK"
    else
        printf '%s Prerequisites missing: %s\n' "$FAIL_MARK" "${missing[*]}"
    fi
}

status_license() {
    local f="$FORTIFY_HOME_K8S/secrets/input/fortify.license"
    if [ -s "$f" ]; then
        printf '%s License file present\n' "$OK_MARK"
    else
        printf '%s License missing — option 4 to add\n' "$FAIL_MARK"
    fi
}

status_cluster() {
    if ! cluster_reachable; then
        printf '%s Cluster not reachable\n' "$FAIL_MARK"
        return
    fi
    local total ready
    total=$($KUBECTL -n "$NAMESPACE" get pods --no-headers 2>/dev/null | wc -l)
    if [ "$total" -eq 0 ]; then
        printf '%s Cluster up, no pods deployed yet\n' "$WARN_MARK"
        return
    fi
    ready=$($KUBECTL -n "$NAMESPACE" get pods --no-headers 2>/dev/null \
        | awk '$3=="Running" {n=split($2,a,"/"); if (a[1]==a[2]) c++} END{print c+0}')
    if [ "$ready" -eq "$total" ]; then
        printf '%s Cluster: %d/%d pods ready\n' "$OK_MARK" "$ready" "$total"
    else
        printf '%s Cluster: %d/%d pods ready\n' "$WARN_MARK" "$ready" "$total"
    fi
}

status_user() {
    if [ "$(id -u)" -eq 0 ] || [ -n "${SUDO_USER:-}" ]; then
        printf '%s Running as root/sudo — mkcert and helm should run as your normal user\n' "$WARN_MARK"
    fi
}


# ============================================================
# Per-app helpers
# ============================================================

# Aggregate status for one app (e.g. "3/3 ready" or "0/0 not deployed").
app_status() {
    local prefix="$1" total ready
    local pods
    pods=$($KUBECTL -n "$NAMESPACE" get pods --no-headers 2>/dev/null \
           | awk -v p="$prefix" '$1 ~ "^"p {print}')
    if [ -z "$pods" ]; then
        printf '%snot deployed%s' "$DIM" "$RESET"
        return
    fi
    total=$(echo "$pods" | wc -l)
    ready=$(echo "$pods" | awk '$3=="Running" {n=split($2,a,"/"); if (a[1]==a[2]) c++} END{print c+0}')
    if [ "$ready" -eq "$total" ]; then
        printf '%s%d/%d running%s' "$GREEN" "$ready" "$total" "$RESET"
    else
        printf '%s%d/%d ready%s' "$YELLOW" "$ready" "$total" "$RESET"
    fi
}

# Run a (possibly multi-) script field from APP_START/STOP/DESTROY.
run_app_scripts() {
    local field="$1" script
    for script in $field; do
        if [ ! -f "$FORTIFY_HOME_K8S/$script" ]; then
            error "Missing $script"
            return 1
        fi
        # shellcheck disable=SC1090
        ( source "$FORTIFY_HOME_K8S/$script" ) || return $?
    done
}


# ============================================================
# Apps submenu
# ============================================================

apps_menu() {
    while true; do
        title "Apps"
        printf '\n  %-3s %-20s %s\n' "#" "Name" "Status"
        printf '  %s\n' "─────────────────────────────────────"
        local i
        for i in "${!APP_LABEL[@]}"; do
            printf '  %-3d %-20s %s\n' \
                $((i + 1)) "${APP_LABEL[$i]}" "$(app_status "${APP_PODS[$i]}")"
        done
        echo
        echo "  r. Return to main menu"
        echo "  q. Quit"
        echo
        ask choice "Select an app:"

        case "$choice" in
            [Rr]) return ;;
            [Qq]) clear; exit 0 ;;
            ''|*[!0-9]*) error "Invalid selection"; sleep 1 ;;
            *)
                if [ "$choice" -ge 1 ] && [ "$choice" -le "${#APP_LABEL[@]}" ]; then
                    app_action_menu $((choice - 1))
                else
                    error "Out of range"
                    sleep 1
                fi
                ;;
        esac
    done
}

app_action_menu() {
    local idx="$1"
    while true; do
        title "${APP_LABEL[$idx]}"
        local url=""
        [ -n "${APP_URL_VAR[$idx]}" ] && url="${!APP_URL_VAR[$idx]:-}"

        echo
        printf '  Status: %s\n' "$(app_status "${APP_PODS[$idx]}")"
        [ -n "$url" ] && printf '  URL:    %s\n' "$url"
        echo

        echo "  1. Start / Upgrade"
        echo "  2. Stop"
        echo "  3. Destroy (deletes data)"
        echo "  4. Logs"
        echo "  5. Show URL & credentials"
        case "${APP_LABEL[$idx]}" in
            "ScanCentral SAST"|"ScanCentral DAST")
                echo "  6. Scale workers"
                ;;
        esac
        echo
        echo "  r. Return"
        echo "  q. Quit"
        echo
        ask choice "Select:"

        case "$choice" in
            1)
                run_app_scripts "${APP_START[$idx]}"
                press_any ;;
            2)
                run_app_scripts "${APP_STOP[$idx]}"
                press_any ;;
            3)
                if confirm "DELETE ${APP_LABEL[$idx]} and its data. Continue?"; then
                    run_app_scripts "${APP_DESTROY[$idx]}"
                fi
                press_any ;;
            4) logs_for_prefix "${APP_PODS[$idx]}" ;;
            5) show_app_creds "$idx"; press_any ;;
            6) scale_workers "$idx"; press_any ;;
            [Rr]) return ;;
            [Qq]) clear; exit 0 ;;
            *) error "Invalid"; sleep 1 ;;
        esac
    done
}

scale_workers() {
    local idx="$1" sts replicas
    case "${APP_LABEL[$idx]}" in
        "ScanCentral SAST") sts="scancentral-sast-worker-linux" ;;
        "ScanCentral DAST") sts="sdast-scanner-scancentral-dast-scanner" ;;
        *) error "Scaling not supported for ${APP_LABEL[$idx]}"; return ;;
    esac
    local current
    current=$($KUBECTL -n "$NAMESPACE" get statefulset "$sts" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "?")
    note "Current $sts replicas: $current"
    ask replicas "New replica count (or empty to cancel):"
    [ -z "$replicas" ] && return
    [[ "$replicas" =~ ^[0-9]+$ ]] || { error "Not a number"; return; }
    $KUBECTL -n "$NAMESPACE" scale statefulset "$sts" --replicas="$replicas"
}

show_app_creds() {
    local idx="$1" url=""
    [ -n "${APP_URL_VAR[$idx]}" ] && url="${!APP_URL_VAR[$idx]:-}"
    section "${APP_LABEL[$idx]}"
    [ -n "$url" ] && printf '  URL: %s\n' "$url"
    case "${APP_LABEL[$idx]}" in
        SSC)
            echo "  Login: see SSC startup logs for the initial admin password"
            echo "         (option 4 → SSC, search the log for 'admin')"
            ;;
        LIM)
            local pw
            pw=$($KUBECTL -n "$NAMESPACE" get secret lim-admin-credentials \
                 -o jsonpath='{.data.password}' 2>/dev/null | base64 -d || true)
            echo "  Login: lim_admin / ${pw:-<unknown>}"
            ;;
        "ScanCentral SAST")
            echo "  Controller URL: $url"
            echo "  Generate the controller token from SSC and apply via option 6 (Configure)."
            ;;
        "ScanCentral DAST")
            echo "  API URL: ${SCDAST_API_URL:-<unset>}"
            ;;
    esac
}


# ============================================================
# License menu
# ============================================================

license_menu() {
    while true; do
        title "License files"
        local f="$FORTIFY_HOME_K8S/secrets/input/fortify.license"
        echo
        if [ -s "$f" ]; then
            printf '  %s fortify.license  (%s bytes)\n' "$OK_MARK" "$(stat -c%s "$f")"
        else
            printf '  %s fortify.license  not found\n' "$FAIL_MARK"
        fi
        echo
        echo "  Path: $f"
        echo
        echo "  1. Import a license from a path"
        echo "  2. Where to obtain a license"
        echo
        echo "  r. Return"
        echo
        ask choice "Select:"

        case "$choice" in
            1)
                ask src "Path to fortify.license file:"
                if [ ! -s "$src" ]; then
                    error "File not found or empty: $src"
                else
                    mkdir -p "$(dirname "$f")"
                    cp "$src" "$f" && note "Imported to $f"
                fi
                press_any ;;
            2)
                cat <<EOF

  Customers: download from your OpenText / Fortify customer portal.
  Trial:     request at https://www.opentext.com/products/fortify

  Once you have the file, place it at:
    $f

EOF
                press_any ;;
            [Rr]) return ;;
            *) error "Invalid"; sleep 1 ;;
        esac
    done
}


# ============================================================
# Certs + Secrets generation
# ============================================================

certs_secrets_menu() {
    title "Generate certs + secrets"
    cat <<EOF

  This rebuilds the lab's TLS chain and recreates every k8s Secret
  in the '$NAMESPACE' namespace.

  WARNING: rebuilding rotates SSC's secret.key, which invalidates any
  encrypted credentials already stored in the SSC database. Only run
  this on a fresh deploy or immediately before destroying SSC's data.

EOF
    echo "  1. Run scripts/create-certs.sh"
    echo "  2. Run scripts/create-secrets.sh"
    echo "  3. Run both (in order)"
    echo
    echo "  r. Return"
    echo
    ask choice "Select:"

    case "$choice" in
        1) ( bash "$FORTIFY_HOME_K8S/scripts/create-certs.sh" );        press_any ;;
        2) ( bash "$FORTIFY_HOME_K8S/scripts/create-secrets.sh" );      press_any ;;
        3) ( bash "$FORTIFY_HOME_K8S/scripts/create-certs.sh" \
             && bash "$FORTIFY_HOME_K8S/scripts/create-secrets.sh" );   press_any ;;
        [Rr]) return ;;
        *) error "Invalid"; sleep 1 ;;
    esac
}


# ============================================================
# Configure: DNS, SSC token, LIM license, rulepack cert refresh
# ============================================================

configure_menu() {
    while true; do
        title "Configure"
        cat <<EOF

  1. DNS — print /etc/hosts entries + apply CoreDNS hosts override
  2. Apply SSC ControllerToken to ScanCentral SAST
  3. LIM — DAST license & default pool (manual instructions)
  4. Refresh update.fortify.com cert in truststore

  r. Return
EOF
        echo
        ask choice "Select:"

        case "$choice" in
            1) configure_dns;        press_any ;;
            2) configure_ssc_token;  press_any ;;
            3) configure_lim;        press_any ;;
            4) refresh_rules_cert;   press_any ;;
            [Rr]) return ;;
            *) error "Invalid"; sleep 1 ;;
        esac
    done
}

configure_dns() {
    local ip
    ip=$(hostname -I | awk '{print $1}')
    cat <<EOF

  ── Client side ─────────────────────────────────────────
  Add to your client's /etc/hosts (or Pi-hole DNS):

    $ip   ssc.$DOMAIN sast.$DOMAIN dast.$DOMAIN lim.$DOMAIN

  ── In-cluster side ─────────────────────────────────────
  Pods inside the cluster need to resolve $DOMAIN themselves
  (e.g. SCDAST scanner calls https://dast.$DOMAIN). We patch
  CoreDNS's hosts plugin so they resolve to this node's IP.

EOF
    if confirm "Apply CoreDNS hosts override now?"; then
        local cm
        cm=$($KUBECTL -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}' 2>/dev/null)
        if [ -z "$cm" ]; then
            error "Could not read coredns ConfigMap"
            return
        fi
        if echo "$cm" | grep -q "$DOMAIN"; then
            note "CoreDNS already has an entry for $DOMAIN — skipping."
            return
        fi
        # Insert a hosts block before the closing brace of the .:53 server block.
        local patched
        patched=$(echo "$cm" | awk -v ip="$ip" -v dom="$DOMAIN" '
            /^}/ && !done { print "    hosts {"; print "        " ip " ssc." dom " sast." dom " dast." dom " lim." dom; print "        fallthrough"; print "    }"; done=1 } { print }')
        $KUBECTL -n kube-system create configmap coredns \
            --from-literal=Corefile="$patched" --dry-run=client -o yaml \
          | $KUBECTL -n kube-system apply -f - >/dev/null
        $KUBECTL -n kube-system rollout restart deployment/coredns >/dev/null
        note "CoreDNS patched and restarted."
    fi
}

configure_ssc_token() {
    cat <<EOF

  In SSC: Administration → ScanCentral SAST → Tokens →
          Create token of type 'ScanCentralCtrlToken'.
          Copy the value below.

EOF
    ask token "Paste ControllerToken (or empty to cancel):"
    [ -z "$token" ] && return
    if ! $HELM -n "$NAMESPACE" status scancentral-sast &>/dev/null; then
        error "ScanCentral SAST is not deployed yet."
        return
    fi
    $HELM -n "$NAMESPACE" upgrade scancentral-sast \
        oci://registry-1.docker.io/fortifydocker/helm-scancentral-sast \
        --version "$FORTIFY_SCSAST_CHART_VERSION" \
        --reuse-values \
        --set controller.sscScanCentralCtrlToken="$token"
}

configure_lim() {
    cat <<EOF

  LIM needs a DAST license file uploaded and a Default scanner pool
  configured before SCDAST can run scans. Both steps are done in
  LIM's web UI:

    1. Open ${LIM_URL:-https://lim.$DOMAIN}
    2. Sign in with the lim_admin credentials (option 5 in any app
       view will print them).
    3. Upload your DAST license file.
    4. Create a pool named 'Default' (matches \$LIM_POOL_NAME in .env).
    5. Generate seats / activate as documented by Fortify.

  After that, redeploy SCDAST (Apps → ScanCentral DAST → Start/Upgrade)
  so the scanner can authenticate to LIM.

EOF
}

refresh_rules_cert() {
    cat <<EOF

  Re-imports the current update.fortify.com leaf and root CA into the
  truststore. Run this when SSC reports a PKIX/handshake error fetching
  rulepacks (typically every 13 months when the leaf rotates).

EOF
    confirm "Refresh now?" || return

    local update_chain root_ca
    update_chain=$(mktemp)
    root_ca=$(mktemp)

    openssl s_client -servername "$FORTIFY_RULES_DOMAIN" \
        -connect "$FORTIFY_RULES_DOMAIN":443 -showcerts </dev/null 2>/dev/null \
      | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' > "$update_chain"

    awk -v last="$(grep -c '^-----BEGIN CERTIFICATE-----' "$update_chain")" '
        /-----BEGIN CERTIFICATE-----/{c++}
        c==last' "$update_chain" > "$root_ca"

    keytool -delete -alias update-fortify-root-ca -keystore "$TRUSTSTORE" \
        -storepass "$DEFAULT_PASS" 2>/dev/null || true
    keytool -import -alias update-fortify-root-ca -file "$root_ca" \
        -keystore "$TRUSTSTORE" -storepass "$DEFAULT_PASS" -noprompt

    rm -f "$update_chain" "$root_ca"

    # Push back into the live secret + restart SSC.
    $KUBECTL -n "$NAMESPACE" patch secret fortify-secrets \
        --type=merge -p "{\"data\":{\"truststore\":\"$(base64 -w0 < "$TRUSTSTORE")\"}}"
    $KUBECTL -n "$NAMESPACE" delete pod ssc-webapp-0 --ignore-not-found
    note "Truststore refreshed; SSC restarting."
}


# ============================================================
# Operations: status, logs, urls, versions
# ============================================================

cluster_status() {
    title "Cluster status"
    if ! cluster_reachable; then
        error "Cluster not reachable"
        press_any; return
    fi
    section "Pods (namespace: $NAMESPACE)"
    $KUBECTL -n "$NAMESPACE" get pods 2>/dev/null
    section "Pods not Ready"
    local issues
    issues=$($KUBECTL -n "$NAMESPACE" get pods --no-headers 2>/dev/null \
        | awk '$3 != "Running" || ($2 ~ /^[0-9]+\/[0-9]+$/ && split($2,a,"/") && a[1] != a[2])')
    if [ -z "$issues" ]; then
        echo "  (none)"
    else
        echo "$issues"
    fi
    press_any
}

logs_menu() {
    title "Pod logs"
    local pods=()
    if ! cluster_reachable; then
        error "Cluster not reachable"
        press_any; return
    fi
    mapfile -t pods < <($KUBECTL -n "$NAMESPACE" get pods -o name 2>/dev/null | sed 's|^pod/||')
    if [ ${#pods[@]} -eq 0 ]; then
        note "No pods in '$NAMESPACE'"
        press_any; return
    fi
    ask filter "Filter (substring, blank=all):"
    local matched=() i
    for i in "${!pods[@]}"; do
        if [ -z "$filter" ] || [[ "${pods[$i]}" == *"$filter"* ]]; then
            matched+=("${pods[$i]}")
        fi
    done
    if [ ${#matched[@]} -eq 0 ]; then
        note "No pods matched '$filter'"
        press_any; return
    fi
    echo
    for i in "${!matched[@]}"; do
        printf '  %2d. %s\n' $((i + 1)) "${matched[$i]}"
    done
    echo
    ask sel "Pod number:"
    [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#matched[@]} ] || {
        error "Invalid"; press_any; return
    }
    local pod="${matched[$((sel-1))]}"
    if confirm "Follow logs (Ctrl+C to exit)?"; then
        $KUBECTL -n "$NAMESPACE" logs --follow "$pod" || true
    else
        $KUBECTL -n "$NAMESPACE" logs --tail=200 "$pod" || true
        press_any
    fi
}

logs_for_prefix() {
    local prefix="$1" pods=() i
    mapfile -t pods < <($KUBECTL -n "$NAMESPACE" get pods -o name 2>/dev/null \
                       | sed 's|^pod/||' | grep "^$prefix")
    if [ ${#pods[@]} -eq 0 ]; then
        note "No pods matching '$prefix'"
        press_any; return
    fi
    if [ ${#pods[@]} -eq 1 ]; then
        $KUBECTL -n "$NAMESPACE" logs --tail=200 "${pods[0]}" || true
    else
        echo
        for i in "${!pods[@]}"; do
            printf '  %2d. %s\n' $((i + 1)) "${pods[$i]}"
        done
        ask sel "Pod number:"
        [[ "$sel" =~ ^[0-9]+$ ]] || return
        $KUBECTL -n "$NAMESPACE" logs --tail=200 "${pods[$((sel-1))]}" || true
    fi
    press_any
}

urls_creds() {
    title "URLs & credentials"
    cat <<EOF

  SSC          ${SSC_URL:-<unset>}
                login: see initial admin password in SSC startup logs

  LIM          ${LIM_URL:-<unset>}
                login: lim_admin / $($KUBECTL -n "$NAMESPACE" get secret lim-admin-credentials \
                                       -o jsonpath='{.data.password}' 2>/dev/null \
                                       | base64 -d 2>/dev/null || echo "<not deployed>")

  SAST ctrl    ${SCSAST_CTRL_URL:-<unset>}
                shared secret applied via Configure → option 2

  DAST API     ${SCDAST_URL:-<unset>}
                login: SSC user mapped to DAST role

  K8s dashboard https://dashboard.$DOMAIN
                token: kubectl -n kube-system get secret admin-user \\
                              -o jsonpath='{.data.token}' | base64 -d

EOF
    press_any
}

versions_menu() {
    title "Image versions"
    section "Configured (.env)"
    grep -E '^\s*export\s+FORTIFY_.*(CHART_VERSION|IMAGE_TAG)=' "$ENV_FILE" \
        | sed 's/^\s*export\s*/  /'
    section "Running"
    if cluster_reachable; then
        $KUBECTL -n "$NAMESPACE" get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' 2>/dev/null \
            | awk -F'\t' '{ printf "  %-50s %s\n", $1, $2 }'
    else
        note "(cluster unreachable)"
    fi
    press_any
}

edit_env() {
    "${EDITOR:-nano}" "$ENV_FILE"
    # shellcheck disable=SC1090
    source "$ENV_FILE"
}


# ============================================================
# Prerequisites menu
# ============================================================

prereqs_menu() {
    while true; do
        title "Install prerequisites"
        echo
        echo "  1. JDK 17 (apt)"
        echo "  2. Docker (apt) + docker login"
        echo "  3. mkcert (apt)"
        echo "  4. microk8s (snap) + addons (dns, ingress, nfs, dashboard, community)"
        echo "  5. All of the above"
        echo
        echo "  r. Return"
        echo
        ask choice "Select:"

        case "$choice" in
            1) install_jdk;        press_any ;;
            2) install_docker;     press_any ;;
            3) install_mkcert;     press_any ;;
            4) install_microk8s;   press_any ;;
            5) install_jdk; install_docker; install_mkcert; install_microk8s; press_any ;;
            [Rr]) return ;;
            *) error "Invalid"; sleep 1 ;;
        esac
    done
}

install_jdk()      { command -v java   &>/dev/null && note "Already installed."  || sudo apt install -y openjdk-17-jre-headless; }
install_mkcert()   { command -v mkcert &>/dev/null && note "Already installed."  || sudo apt install -y mkcert; }
install_docker()   {
    if command -v docker &>/dev/null; then
        note "Already installed."
    else
        sudo apt install -y docker.io
    fi
    if ! [ -f "$HOME/.docker/config.json" ]; then
        note "Logging into Docker Hub (needed to pull Fortify images)..."
        docker login
    fi
}
install_microk8s() {
    if command -v microk8s &>/dev/null; then
        note "Already installed."
    else
        bash "$FORTIFY_HOME_K8S/scripts/install_microk8s.sh"
    fi
}


# ============================================================
# Deploy from scratch
# ============================================================

deploy_from_scratch() {
    title "Deploy lab from scratch"
    cat <<EOF

  This will run, in order:
    1. Pre-flight checks (license, prereqs, cluster reachable)
    2. scripts/create-certs.sh
    3. scripts/create-secrets.sh
    4. apps/mysql/start.sh + apps/postgresql/start.sh   (wait until ready)
    5. apps/ssc/start.sh + apps/lim/start.sh            (wait until ready)
    6. apps/scsast/start.sh
    7. apps/scdast/core/start.sh + apps/scdast/scanner/start.sh

  The whole flow takes ~15-20 minutes. SSC's first start runs DB
  migrations; LIM does signing-cert setup. Watch logs in another
  terminal if you want progress.

EOF
    confirm "Proceed?" || return

    deploy_step "Pre-flight" preflight_check                                                              || return
    deploy_step "Certs"      bash "$FORTIFY_HOME_K8S/scripts/create-certs.sh"                              || return
    deploy_step "Secrets"    bash "$FORTIFY_HOME_K8S/scripts/create-secrets.sh"                            || return
    deploy_step "MySQL"      run_app_scripts "apps/mysql/start.sh"                                         || return
    deploy_step "PostgreSQL" run_app_scripts "apps/postgresql/start.sh"                                    || return
    wait_pod "mysql"        300
    wait_pod "postgresql"   300
    deploy_step "SSC"        run_app_scripts "apps/ssc/start.sh"                                           || return
    deploy_step "LIM"        run_app_scripts "apps/lim/start.sh"                                           || return
    wait_pod "ssc-webapp"   600
    wait_pod "lim"          300
    deploy_step "SAST"       run_app_scripts "apps/scsast/start.sh"                                       || return
    deploy_step "DAST"       run_app_scripts "apps/scdast/core/start.sh apps/scdast/scanner/start.sh"     || return
    note "Deploy complete. Run option 6 to configure DNS, the SSC token, and LIM."
    press_any
}

preflight_check() {
    [ -s "$FORTIFY_HOME_K8S/secrets/input/fortify.license" ] || { error "Missing fortify.license"; return 1; }
    cluster_reachable || { error "Cluster not reachable"; return 1; }
    return 0
}

deploy_step() {
    local label="$1"; shift
    section "$label"
    if "$@"; then
        note "$label OK"
    else
        error "$label failed — aborting deploy"
        press_any
        return 1
    fi
}

wait_pod() {
    local prefix="$1" timeout="${2:-300}"
    note "Waiting up to ${timeout}s for $prefix pod to be Ready..."
    local pod
    pod=$($KUBECTL -n "$NAMESPACE" get pods --no-headers 2>/dev/null \
          | awk -v p="$prefix" '$1 ~ "^"p {print $1; exit}')
    [ -n "$pod" ] || { error "No pod matching '$prefix' yet"; return 1; }
    $KUBECTL -n "$NAMESPACE" wait --for=condition=Ready --timeout="${timeout}s" "pod/$pod" || true
}


# ============================================================
# Main menu
# ============================================================

main_menu() {
    while true; do
        title "Fortify Lab"
        section "Status"
        printf '  %s\n' "$(status_prereqs)"
        printf '  %s\n' "$(status_license)"
        printf '  %s\n' "$(status_cluster)"
        status_user

        section "Quick start"
        echo "   1. Deploy from scratch"
        echo "   2. Apps"

        section "Setup"
        echo "   3. Install prerequisites"
        echo "   4. License files"
        echo "   5. Generate certs + secrets"
        echo "   6. Configure (DNS, SSC token, LIM)"

        section "Operations"
        echo "   7. Cluster status"
        echo "   8. Pod logs"
        echo "   9. URLs & credentials"
        echo "  10. Image versions"
        echo "  11. Edit .env"

        echo
        echo "   q. Quit"
        echo
        ask choice "Select:"

        case "$choice" in
            1)  deploy_from_scratch ;;
            2)  apps_menu ;;
            3)  prereqs_menu ;;
            4)  license_menu ;;
            5)  certs_secrets_menu ;;
            6)  configure_menu ;;
            7)  cluster_status ;;
            8)  logs_menu ;;
            9)  urls_creds ;;
           10)  versions_menu ;;
           11)  edit_env ;;
            [Qq]) clear; exit 0 ;;
            *)   error "Invalid choice"; sleep 1 ;;
        esac
    done
}


# ============================================================
# Entry
# ============================================================

usage() {
    cat <<EOF
Fortify Lab management wizard.

Usage:
  ./start_wizard.sh                  Launch the interactive menu.
  ./start_wizard.sh -h | --help      Show this message.

Environment overrides:
  FORTIFY_HOME_K8S    Repo root (defaults to the script's directory).
  EDITOR              Editor used by 'Edit .env' (defaults to nano).
  NO_COLOR            Disable color output if set to any value.
  WIZARD_NOMAIN       Set to 1 to source this file without entering the menu
                      (for tests / scripting).

Run as your normal user — the wizard sudo's only the commands that genuinely
need root (apt, snap). Avoid 'sudo ./start_wizard.sh': it would create an
mkcert CA owned by root and rotate every cert the lab has issued.
EOF
}

case "${1:-}" in
    -h|--help) usage; exit 0 ;;
esac

# Allow sourcing the file for testing without entering the main menu.
if [ -z "${WIZARD_NOMAIN:-}" ]; then
    bootstrap_env
    main_menu
fi
