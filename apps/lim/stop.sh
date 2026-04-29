#!/bin/bash

source $FORTIFY_HOME_K8S/.env

microk8s kubectl -n $NAMESPACE scale statefulset lim --replicas=0
