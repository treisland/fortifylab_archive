#!/bin/bash

#-------------------------------
# Requires mkcert be installed
#-------------------------------

if [ -z "$FORTIFY_HOME_K8S" ]; then
    FORTIFY_HOME_K8S="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    export FORTIFY_HOME_K8S
fi

source "$FORTIFY_HOME_K8S/.env"

CURRENT_DIR="$( dirname -- "${BASH_SOURCE[0]}" )"

#recreate ingress TLS secret with proper kubernetes.io/tls type (nginx ingress requires this type, not Opaque)
microk8s kubectl -n kube-system delete secret kubernetes-dashboard-tls --ignore-not-found
microk8s kubectl -n kube-system create secret tls kubernetes-dashboard-tls --cert="$SERVER_CERT" --key="$SERVER_KEY"

microk8s kubectl apply -f $CURRENT_DIR/dashboard.yaml

#wait briefly for the service-account token secret to populate
sleep 3
echo
echo "Dashboard URL: https://dashboard.fortifydemo.com"
echo "Token (paste this on the dashboard login page):"
echo
microk8s kubectl get secret admin-user -n kube-system -o jsonpath="{.data.token}" | base64 -d
echo