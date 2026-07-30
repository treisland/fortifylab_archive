#!/bin/bash

source "$FORTIFY_HOME_K8S/.env"

microk8s kubectl -n "$NAMESPACE" scale statefulset scancentral-sast-controller --replicas=0
microk8s kubectl -n "$NAMESPACE" scale statefulset scancentral-sast-sensor-linux --replicas=0
