#!/bin/bash

#load the environment variables
if [ -z "$FORTIFY_HOME_K8S" ]; then
    FORTIFY_HOME_K8S="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    export FORTIFY_HOME_K8S
fi

source "$FORTIFY_HOME_K8S/.env"

#get the current directory where this script resides
CURRENT_DIR="$( dirname -- "${BASH_SOURCE[0]}" )"

STATEFULSET="lim"

microk8s kubectl apply -f $CURRENT_DIR/pvc.yaml

microk8s helm -n "$NAMESPACE" upgrade -i lim oci://registry-1.docker.io/fortifydocker/helm-lim --version "$FORTIFY_LIM_CHART_VERSION" \
--create-namespace \
 --set imagePullSecrets[0].name=regcred \
 --set defaultAdministrator.fullName=lim \
 --set defaultAdministrator.credentialsSecretName=lim-admin-credentials \
 --set jwt.securityKeySecretName=lim-jwt-security-key \
 --set serverCertificate.certificateSecretName=lim-server-certificate \
 --set signingCertificate.certificateSecretName=lim-signing-certificate \
 --set signingCertificate.certificatePasswordSecretName=lim-signing-certificate-password \
 --set dataPersistence.existingClaim=lim-pvc  

microk8s kubectl -n "$NAMESPACE" apply -f $CURRENT_DIR/ingress.yaml

microk8s kubectl -n "$NAMESPACE" scale statefulset lim --replicas=1
