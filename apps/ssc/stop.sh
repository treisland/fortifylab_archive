#!/bin/bash

source $FORTIFY_HOME_K8S/.env

#get the current directory where this script resides
CURRENT_DIR="$( dirname -- "${BASH_SOURCE[0]}" )"

microk8s kubectl -n $NAMESPACE scale statefulset ssc-webapp --replicas=0