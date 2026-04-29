#!/bin/bash

if [ -z "$FORTIFY_HOME_K8S" ]; then
    FORTIFY_HOME_K8S="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
    export FORTIFY_HOME_K8S
fi

source "$FORTIFY_HOME_K8S/.env"

CURRENT_DIR="$( dirname "${BASH_SOURCE[0]}" )"

microk8s helm -n "$NAMESPACE" upgrade -i \
	sdast-core oci://registry-1.docker.io/fortifydocker/helm-scancentral-dast-core \
	--create-namespace \
	--timeout 15m \
	--version "$FORTIFY_SCDAST_CHART_VERSION" \
	--set imagePullSecrets[0].name=regcred \
	--set upgradejob.prepJob.image.repository=bitnamilegacy/kubectl \
	--set appsettings.lIMSettings.limUrl="$LIM_URL" \
	--set appsettings.sSCSettings.sSCRootUrl="$SSC_URL" \
	--set appsettings.applySecureBase=false \
	--set appsettings.dASTApiSettings.disableCorsOrigins=true \
	--set appsettings.databaseSettings.server="postgresql" \
	--set appsettings.databaseSettings.databaseProvider="PostgreSQL" \
	--set appsettings.environmentSettings.allowNonTrustedServerCertificate=true \
	--set database.dboLevelAccountCredentialsSecret="scdast-db-owner" \
	--set database.standardAccountCredentialsSecret="scdast-db-standard" \
	--set sscServiceAccountSecretName="scdast-ssc-serviceaccount" \
	--set serviceTokenSecretName="scdast-service-token" \
	--set limServiceAccountSecretName="lim-admin-credentials" \
	--set limDefaultPoolSecretName="lim-pool" \
	--set api.certificate.certificateSecretName=tls-pfx \
	--set api.certificate.certificatePasswordSecretName=tls-pfx-password \
	--set utilityService.certificate.certificateSecretName=tls-pfx \
	--set utilityService.certificate.certificatePasswordSecretName=tls-pfx-password \
	--set api.certificate.enabled=false \
	--set api.ingress.enabled=true \
	--set api.ingress.hosts[0].host=$SCDAST \
	--set api.ingress.hosts[0].paths[0].path=/ \
	--set api.ingress.hosts[0].paths[0].pathType=Prefix \
	--set api.ingress.tls[0].secretName=tls \
	--set api.ingress.tls[0].hosts[0]=$SCDAST \
	-f $CURRENT_DIR/resource_override.yaml

microk8s kubectl -n "$NAMESPACE" scale statefulset sdast-core-scancentral-dast-core-api --replicas=1
microk8s kubectl -n "$NAMESPACE" scale statefulset sdast-core-scancentral-dast-core-globalservice --replicas=1
microk8s kubectl -n "$NAMESPACE" scale statefulset sdast-core-scancentral-dast-core-utilityservice --replicas=1

# Grant the standard runtime user (dast_user) access to objects the DBO
# (postgres) created via the upgradejob. The chart doesn't propagate these
# grants automatically, and without them the API crashes with
# "permission denied for table configurationsetting".
#
# The upgradejob is a Helm pre-upgrade hook that runs before this script
# returns, so the schema exists by now. Wait briefly for the
# 'configurationsetting' table to appear (handles the first install where
# helm returns before the hook fully writes data).
echo "Waiting for DAST schema to be ready..."
for _ in $(seq 1 60); do
  if microk8s kubectl -n "$NAMESPACE" exec postgresql-0 -- bash -c \
       "PGPASSWORD=\$(cat \$POSTGRES_POSTGRES_PASSWORD_FILE) /opt/bitnami/postgresql/bin/psql -U postgres -d DAST -tAc \"select to_regclass('public.configurationsetting')\"" \
       2>/dev/null | grep -q configurationsetting; then
    break
  fi
  sleep 5
done

echo "Granting $SCDAST_DB_STANDARD_USER privileges on the DAST database..."
microk8s kubectl -n "$NAMESPACE" exec postgresql-0 -- bash -c "
  PGPASSWORD=\$(cat \$POSTGRES_POSTGRES_PASSWORD_FILE) /opt/bitnami/postgresql/bin/psql -U postgres -d DAST <<SQL
  GRANT USAGE ON SCHEMA public TO $SCDAST_DB_STANDARD_USER;
  GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public TO $SCDAST_DB_STANDARD_USER;
  GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO $SCDAST_DB_STANDARD_USER;
  GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO $SCDAST_DB_STANDARD_USER;
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER ON TABLES TO $SCDAST_DB_STANDARD_USER;
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO $SCDAST_DB_STANDARD_USER;
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO $SCDAST_DB_STANDARD_USER;
SQL
" 2>&1 | tail -10
