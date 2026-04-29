#!/bin/bash

if [ -z "$FORTIFY_HOME_K8S" ]; then
    FORTIFY_HOME_K8S="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    export FORTIFY_HOME_K8S
fi

source "$FORTIFY_HOME_K8S/.env"

CURRENT_DIR="$( dirname "${BASH_SOURCE[0]}" )"

microk8s helm -n "$NAMESPACE" upgrade -i postgresql oci://registry-1.docker.io/bitnamicharts/postgresql \
--version "$FORTIFY_POSTGRES_CHART_VERSION" \
--create-namespace \
--set global.imagePullSecrets[0]=regcred \
--set image.repository=bitnamilegacy/postgresql \
--set image.tag="$FORTIFY_POSTGRES_IMAGE_TAG" \
--set auth.username="$SCDAST_DB_STANDARD_USER" \
--set auth.password="$SCDAST_DB_STANDARD_PASS" \
--set auth.postgresPassword="$SCDAST_DB_OWNER_PASS" \
--set primary.persistence.enabled=true \
--set primary.persistence.storageClass="nfs" \
--set primary.persistence.accessMode="ReadWriteOnce" \
--set primary.persistence.size=10Gi \
--set primary.resources.limits.memory=2Gi \
--set primary.configuration="listen_addresses ='*'"

microk8s kubectl -n $NAMESPACE scale statefulset postgresql --replicas=1
