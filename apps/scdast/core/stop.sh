#!/bin/bash

source "$FORTIFY_HOME_K8S/.env"

microk8s kubectl -n "$NAMESPACE" scale statefulset \
  sdast-core-scancentral-dast-core-api \
  sdast-core-scancentral-dast-core-globalservice \
  sdast-core-scancentral-dast-core-utilityservice \
  --replicas=0
