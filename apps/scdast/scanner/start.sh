#!/bin/bash

if [ -z "$FORTIFY_HOME_K8S" ]; then
    FORTIFY_HOME_K8S="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
    export FORTIFY_HOME_K8S
fi

source "$FORTIFY_HOME_K8S/.env"

CURRENT_DIR="$( dirname "${BASH_SOURCE[0]}" )"

microk8s helm -n "$NAMESPACE" upgrade -i sdast-scanner oci://registry-1.docker.io/fortifydocker/helm-scancentral-dast-scanner --version "$FORTIFY_SCDAST_CHART_VERSION" --timeout 60m \
	--create-namespace \
	--set imagePullSecrets[0].name=regcred \
	--set dastApiServiceURL=$SCDAST_URL \
	--set serviceTokenSecretName=scdast-service-token \
	--set allowNonTrustedServerCertificate=true \
	-f $CURRENT_DIR/resource_override.yaml

microk8s kubectl -n "$NAMESPACE" scale statefulset sdast-scanner-scancentral-dast-scanner --replicas=1
