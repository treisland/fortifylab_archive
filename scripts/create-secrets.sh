#!/bin/bash
#
# CREATE SECRETS
# -----------------------------------
#
# Single entry point that builds every k8s Secret the Fortify charts need.
#
# Inputs:
#   secrets/input/       — user-provided files (license, etc.)
#   secrets/templates/   — committed templates rendered with envsubst
#   secrets/generated/   — wiped and rebuilt each run
#   .env                 — domain, credentials, image versions
#
# See secrets/README.md for the full file → secret → consumer map.
#========================================================

set -euo pipefail

if [ -z "${FORTIFY_HOME_K8S:-}" ]; then
    FORTIFY_HOME_K8S="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    export FORTIFY_HOME_K8S
fi

source "$FORTIFY_HOME_K8S/.env"

# Running under sudo would create files in secrets/generated/ owned by root,
# which then block subsequent normal-user runs from rebuilding the directory.
# microk8s group membership covers cluster ops without sudo; if you don't
# have it yet, run: sudo usermod -aG microk8s "$USER" && newgrp microk8s
if [ "$(id -u)" -eq 0 ] || [ -n "${SUDO_USER:-}" ]; then
  echo "❌ Do not run create-secrets.sh as root or via sudo."
  echo "   It writes to secrets/generated/; root ownership there will break"
  echo "   future runs by your normal user. Add yourself to the microk8s"
  echo "   group instead: sudo usermod -aG microk8s \"\$USER\" && newgrp microk8s"
  exit 1
fi

INPUT_DIR="$FORTIFY_HOME_K8S/secrets/input"
TEMPLATES_DIR="$FORTIFY_HOME_K8S/secrets/templates"
GENERATED_DIR="$FORTIFY_SECRETS_GENERATED"
SSC_GEN_DIR="$GENERATED_DIR/ssc"

KUBECTL="microk8s kubectl"


#--------------------------
# SECTION: PRE-FLIGHT CHECKS
#--------------------------

LICENSE_FILE="$INPUT_DIR/fortify.license"
if [ ! -s "$LICENSE_FILE" ]; then
  cat <<EOF
❌ Missing required license file: $LICENSE_FILE

  Fortify SSC and ScanCentral SAST require a valid fortify.license file.

  How to obtain one:
    • Customers: download from your OpenText / Fortify customer portal
    • Trial:     request at https://www.opentext.com/products/fortify

  Place the file at:
    $LICENSE_FILE

  Then re-run this script.
EOF
  exit 1
fi

if [ ! -f "$TRUSTSTORE" ] || [ ! -f "$JVM_KEYSTORE" ]; then
  echo "❌ Certs/keystores not found. Run scripts/create-certs.sh first."
  exit 1
fi


#--------------------------
# SECTION: NAMESPACE
#--------------------------

$KUBECTL get namespace "$NAMESPACE" &>/dev/null \
  || $KUBECTL create namespace "$NAMESPACE"


#--------------------------
# SECTION: REBUILD GENERATED/
#--------------------------
# Wipe everything under generated/ so stale files (old backups, removed
# license files, etc.) never leak into a Secret. Cert artifacts live in
# $FORTIFY_CERTS, not here, so this is safe.

rm -rf "$GENERATED_DIR"
mkdir -p "$SSC_GEN_DIR"

# Render ssc.autoconfig from template using DB credentials from .env.
# Uses ${VAR} substitution only — leaves $-prefixed db.username untouched.
SSC_DB_USER="${SSC_DB_USER:-root}"
SSC_DB_PASSWORD="${SSC_DB_PASSWORD:-$DEFAULT_PASS}"
export SSC_DB_USER SSC_DB_PASSWORD
envsubst '${SSC_DB_USER} ${SSC_DB_PASSWORD}' \
  < "$TEMPLATES_DIR/ssc.autoconfig.template" \
  > "$SSC_GEN_DIR/ssc.autoconfig"

# SSC's secret.key is NOT plain random bytes — it's a structured Fortify
# keystore with a specific binary header. `openssl rand` output is rejected
# by SSC's pwtool with "Unable to read secret key from Fortify key store".
#
# We use a committed sample key from templates/ for new deploys (fine for
# a lab/demo — every clone gets the same key). For production, generate
# a fresh one with Fortify's pwtool inside the SSC container and replace
# this file.
#
# Once an SSC instance has stored encrypted credentials in its DB with
# a given key, that key MUST stay constant. We therefore reuse the
# existing $SSC_GEN_DIR/secret.key if it's already present (e.g. on a
# re-run of create-secrets.sh against a live cluster) instead of
# rotating it.
if [ -s "$SSC_GEN_DIR/secret.key" ]; then
    : # already exists from a previous run; keep it
elif [ -s "$TEMPLATES_DIR/secret.key.sample" ]; then
    cp "$TEMPLATES_DIR/secret.key.sample" "$SSC_GEN_DIR/secret.key"
else
    echo "❌ No secret.key.sample found in templates/ and no existing key in generated/."
    echo "   For a fresh install you can copy a sample key from a Fortify SSC pod:"
    echo "     kubectl -n $NAMESPACE exec ssc-webapp-0 -- /app/tools/...  # see SSC docs"
    exit 1
fi


#--------------------------
# SECTION: DELETE EXISTING SECRETS
#--------------------------

$KUBECTL -n "$NAMESPACE" delete secret --ignore-not-found \
  regcred \
  fortify-secrets \
  tls \
  tls-pfx \
  tls-pfx-password \
  scdast-db-owner \
  scdast-db-standard \
  scdast-ssc-serviceaccount \
  scdast-service-token \
  lim-pool \
  lim-admin-credentials \
  lim-jwt-security-key \
  lim-server-certificate \
  lim-signing-certificate \
  lim-signing-certificate-password


#--------------------------
# SECTION: CREATE SECRETS
#--------------------------

# fortify-secrets: a single Secret that SSC AND ScanCentral SAST both pull
# from (chart contract — see apps/ssc/start.sh secretRef.keys.* and the SAST
# chart's valueFrom.secretKeyRef references). Keys are added explicitly by
# name — never --from-file <dir> — to keep stray files (READMEs, backups,
# public CAs) from leaking in.
#
# The scancentral-* tokens are required by the SAST chart even though our
# scripts don't read them directly: the controller and workers pull them
# via secretKeyRef. Generated fresh per install so two clones of this repo
# don't share authentication tokens.
$KUBECTL -n "$NAMESPACE" create secret generic fortify-secrets \
  --from-file=fortify.license="$LICENSE_FILE" \
  --from-file=ssc.autoconfig="$SSC_GEN_DIR/ssc.autoconfig" \
  --from-file=secret.key="$SSC_GEN_DIR/secret.key" \
  --from-file=keystore.jks="$JVM_KEYSTORE" \
  --from-file=truststore="$TRUSTSTORE" \
  --from-literal=default_password="$DEFAULT_PASS" \
  --from-literal=scancentral-client-auth-token="$(openssl rand -base64 32 | tr -d '[:punct:]\n' | head -c 48)" \
  --from-literal=scancentral-worker-auth-token="$(openssl rand -base64 32 | tr -d '[:punct:]\n' | head -c 48)" \
  --from-literal=scancentral-ssc-scancentral-ctrl-secret="$(openssl rand -base64 32 | tr -d '[:punct:]\n' | head -c 48)"

# Ingress server cert (kubernetes.io/tls type — required by nginx ingress).
$KUBECTL -n "$NAMESPACE" create secret tls tls \
  --cert="$SERVER_CERT" --key="$SERVER_KEY"

# LIM signing cert (PFX) + password.
$KUBECTL -n "$NAMESPACE" create secret generic tls-pfx \
  --type=Opaque --from-file=tls.pfx="$ROOTCA_PFX"
$KUBECTL -n "$NAMESPACE" create secret generic tls-pfx-password \
  --type=Opaque --from-literal=password="$DEFAULT_PASS"

# SCDAST DB users.
$KUBECTL -n "$NAMESPACE" create secret generic scdast-db-owner \
  --type=basic-auth \
  --from-literal=username="$SCDAST_DB_OWNER_USER" \
  --from-literal=password="$SCDAST_DB_OWNER_PASS"
$KUBECTL -n "$NAMESPACE" create secret generic scdast-db-standard \
  --type=basic-auth \
  --from-literal=username="$SCDAST_DB_STANDARD_USER" \
  --from-literal=password="$SCDAST_DB_STANDARD_PASS"

# SCDAST → SSC service account.
$KUBECTL -n "$NAMESPACE" create secret generic scdast-ssc-serviceaccount \
  --type=basic-auth \
  --from-literal=username="$SCDAST_SSC_USER" \
  --from-literal=password="$SCDAST_SSC_PASS"

# SCDAST core ↔ scanner shared secret (generated fresh).
$KUBECTL -n "$NAMESPACE" create secret generic scdast-service-token \
  --type=Opaque \
  --from-literal=service-token="$(openssl rand -base64 32)"

# LIM secrets.
$KUBECTL -n "$NAMESPACE" create secret generic lim-pool \
  --type=basic-auth \
  --from-literal=username="$LIM_POOL_NAME" \
  --from-literal=password="$LIM_POOL_PASS"
$KUBECTL -n "$NAMESPACE" create secret generic lim-admin-credentials \
  --type=basic-auth \
  --from-literal=username=lim_admin \
  --from-literal=password="$LIM_SIGNING_CERT_PWD"
$KUBECTL -n "$NAMESPACE" create secret generic lim-jwt-security-key \
  --type=Opaque \
  --from-literal=token="$(openssl rand -base64 32 | tr -d '[:punct:]')"
$KUBECTL -n "$NAMESPACE" create secret tls lim-server-certificate \
  --cert="$LIM_SERVER_CERT_PEM" --key="$LIM_SERVER_KEY_PEM"
$KUBECTL -n "$NAMESPACE" create secret generic lim-signing-certificate \
  --type=Opaque --from-file=tls.pfx="$LIM_SIGNING_CERT_PFX"
$KUBECTL -n "$NAMESPACE" create secret generic lim-signing-certificate-password \
  --type=Opaque --from-literal=pfx.password="$LIM_SIGNING_CERT_PWD"


#--------------------------
# SECTION: REGCRED (Docker Hub pull credentials)
#--------------------------
# Fall back to $SUDO_USER's Docker config when running under sudo.

DOCKER_CONFIG_PATH="${DOCKER_CONFIG_PATH:-$HOME/.docker/config.json}"
if [ ! -f "$DOCKER_CONFIG_PATH" ] && [ -n "${SUDO_USER:-}" ]; then
  DOCKER_CONFIG_PATH="$(getent passwd "$SUDO_USER" | cut -d: -f6)/.docker/config.json"
fi
if [ ! -f "$DOCKER_CONFIG_PATH" ]; then
  echo "❌ Docker config not found at $DOCKER_CONFIG_PATH"
  echo "   Run 'docker login' first so the cluster can pull Fortify images."
  exit 1
fi
$KUBECTL -n "$NAMESPACE" create secret docker-registry regcred \
  --from-file=.dockerconfigjson="$DOCKER_CONFIG_PATH"

echo
echo "✅ Secrets created in namespace '$NAMESPACE'."
