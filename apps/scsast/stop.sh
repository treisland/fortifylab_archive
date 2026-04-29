#!/bin/bash

source $FORTIFY_HOME_K8S/.env

microk8s kubectl -n $NAMESPACE scale statefulset scancentral-sast-controller --replicas=0
microk8s kubectl -n $NAMESPACE scale statefulset scancentral-sast-worker-linux --replicas=0
