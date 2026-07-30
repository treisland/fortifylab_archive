#!/bin/bash

# Load the environment variables.
source "$FORTIFY_HOME_K8S/.env"

#get the current directory where this script resides
CURRENT_DIR="$( dirname -- "${BASH_SOURCE[0]}" )"

microk8s helm -n $NAMESPACE install scancentral-sast-sensor oci://registry-1.docker.io/fortifydocker/helm-scancentral-sast --version $FORTIFY_SCSAST_CHART_VERSION \
--set imagePullSecrets[0].name=regcred \
--set-file trustedCertificates[0]=$ROOTCA_CERT \
--set secrets.secretName=fortify-secrets \
--set controller.sscUrl="$SSC_URL" \
--set controller.enabled=false \
--set workers.linux.image.tag="$FORTIFY_SCSAST_WORKER_IMAGE_TAG" \
--set workers.linux.image.pullPolicy="IfNotPresent" \
--set workers.linux.controllerUrl="$SCSAST_CTRL_URL" \
--set workers.linux.autoUpdate.server.acceptKey=true \
--set workers.linux.autoUpdate.server.acceptSslCertificate=true \
--set workers.linux.resources.requests.memory=4Gi \
--set workers.linux.resources.limits.memory=8Gi
