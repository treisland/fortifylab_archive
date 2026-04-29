#!/bin/bash

CURRENT_DIR="$( dirname -- "${BASH_SOURCE[0]}" )"

#load the environment variables
source $FORTIFY_HOME_K8S/.env

microk8s kubectl -n $NAMESPACE delete secret lim-admin-credentials
microk8s kubectl -n $NAMESPACE delete secret lim-jwt-security-key
microk8s kubectl -n $NAMESPACE delete secret lim-server-certificate
microk8s kubectl -n $NAMESPACE delete secret lim-signing-certificate
microk8s kubectl -n $NAMESPACE delete secret lim-signing-certificate-password

microk8s kubectl -n $NAMESPACE create secret generic lim-admin-credentials --type=basic-auth --from-literal=username=lim_admin --from-literal=password="$LIM_SIGNING_CERT_PWD"

microk8s kubectl -n $NAMESPACE create secret generic lim-jwt-security-key --type=Opaque --from-literal=token="$(openssl rand -base64 32| tr -d [:punct:])"

microk8s kubectl -n $NAMESPACE create secret generic lim-server-certificate --type=TLS --from-file=tls.crt="$LIM_SERVER_CERT_PEM" --from-file=tls.key="$LIM_SERVER_KEY_PEM"

microk8s kubectl -n $NAMESPACE create secret generic lim-signing-certificate --type=Opaque --from-file=tls.pfx="$LIM_SIGNING_CERT_PFX"

microk8s kubectl -n $NAMESPACE create secret generic lim-signing-certificate-password --type=Opaque --from-literal=pfx.password="$LIM_SIGNING_CERT_PWD"
