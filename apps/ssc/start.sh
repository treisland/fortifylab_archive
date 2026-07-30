#!/bin/bash

if [ -z "$FORTIFY_HOME_K8S" ]; then
    FORTIFY_HOME_K8S="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    export FORTIFY_HOME_K8S
fi

source "$FORTIFY_HOME_K8S/.env"

CURRENT_DIR="$( dirname "${BASH_SOURCE[0]}" )"

microk8s helm -n "$NAMESPACE" upgrade -i ssc \
		--create-namespace \
		oci://registry-1.docker.io/fortifydocker/helm-ssc \
		--version "$FORTIFY_SSC_CHART_VERSION" \
		--set urlHost="$SSC" \
		--set image.tag="$FORTIFY_SSC_IMAGE_TAG" \
		--set imagePullSecrets[0].name=regcred \
		--set secretRef.name=fortify-secrets \
		--set secretRef.keys.sscLicenseEntry=fortify.license \
		--set secretRef.keys.sscSecretKeyEntry=secret.key \
		--set secretRef.keys.sscAutoconfigEntry=ssc.autoconfig \
		--set secretRef.keys.httpCertificateKeystoreFileEntry=keystore.jks \
		--set secretRef.keys.httpCertificateKeystorePasswordEntry=default_password \
		--set secretRef.keys.httpCertificateKeyPasswordEntry=default_password \
		--set secretRef.keys.jvmTruststoreFileEntry=truststore \
		--set secretRef.keys.jvmTruststorePasswordEntry=default_password \
		--set secretRef.keys.httpTruststoreFileEntry=truststore \
		--set secretRef.keys.httpTruststorePasswordEntry=default_password \
		--set persistentVolumeClaim.size=20Gi \
		--set persistentVolumeClaim.storageClassName=nfs \
		--set resources.limits.memory=8Gi \
		--set resources.limits.cpu=1 \
		--set service.type=ClusterIP

microk8s kubectl -n "$NAMESPACE" apply -f $CURRENT_DIR/ingress.yaml

microk8s kubectl -n "$NAMESPACE" scale statefulsets ssc-webapp --replicas=1
