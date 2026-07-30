#!/bin/bash

# Load the environment variables
if [ -z "$FORTIFY_HOME_K8S" ]; then
    FORTIFY_HOME_K8S="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    export FORTIFY_HOME_K8S
fi

source "$FORTIFY_HOME_K8S/.env"

# Get the current directory where this script resides
CURRENT_DIR="$(dirname -- "${BASH_SOURCE[0]}")"

microk8s helm -n "$NAMESPACE" upgrade -i scancentral-sast oci://registry-1.docker.io/fortifydocker/helm-scancentral-sast --version "$FORTIFY_SCSAST_CHART_VERSION" \
--create-namespace \
--set imagePullSecrets[0].name=regcred \
--set-file trustedCertificates[0]=$ROOTCA_CERT \
--set-file trustedCertificates[1]=$SERVER_CERT \
--set secrets.secretName=fortify-secrets \
--set controller.image.tag="$FORTIFY_SCSAST_CTRL_IMAGE_TAG" \
--set controller.thisUrl="$SCSAST_CTRL_URL" \
--set controller.sscUrl="$SSC_URL" \
--set controller.sscScanCentralCtrlToken="$SSC_CTRL_TOKEN" \
--set controller.persistence.enabled=true \
--set controller.persistence.accessMode=ReadWriteOnce \
--set controller.persistence.storageClass=nfs \
--set controller.enabled=true \
--set controller.ingress.enabled=true \
--set controller.ingress.className=public \
--set controller.ingress.hosts[0].host="$SCSAST" \
--set controller.ingress.hosts[0].paths[0].path=/ \
--set controller.ingress.hosts[0].paths[0].pathType=Prefix \
--set controller.ingress.tls[0].secretName=tls \
--set controller.ingress.tls[0].hosts[0]="$SCSAST" \
--set controller.ingress.annotations."nginx\.ingress\.kubernetes\.io/proxy-body-size"=1G \
--set workers.linux.enabled=true \
--set workers.linux.persistence.enabled=false \
--set workers.linux.persistence.storageClass="nfs" \
--set workers.linux.persistence.size="20" \
--set workers.linux.image.tag="$FORTIFY_SCSAST_WORKER_IMAGE_TAG" \
-f $CURRENT_DIR/resource_override.yaml

microk8s kubectl -n "$NAMESPACE" scale statefulset scancentral-sast-controller --replicas=1
microk8s kubectl -n "$NAMESPACE" scale statefulset scancentral-sast-sensor-linux --replicas=1
