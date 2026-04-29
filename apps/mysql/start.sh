#!/bin/bash

if [ -z "$FORTIFY_HOME_K8S" ]; then
    FORTIFY_HOME_K8S="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    export FORTIFY_HOME_K8S
fi

source "$FORTIFY_HOME_K8S/.env"

CURRENT_DIR="$( dirname "${BASH_SOURCE[0]}" )"

microk8s helm -n "$NAMESPACE" upgrade -i mysql oci://registry-1.docker.io/bitnamicharts/mysql --version "$FORTIFY_MYSQL_CHART_VERSION" \
--create-namespace \
--set global.imagePullSecrets[0]=regcred \
--set image.repository=bitnamilegacy/mysql \
--set image.tag="$FORTIFY_MYSQL_IMAGE_TAG" \
--set auth.rootPassword="$DEFAULT_PASS" \
-f $CURRENT_DIR/values.yaml
