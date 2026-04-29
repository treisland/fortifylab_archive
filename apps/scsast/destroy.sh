#!/bin/bash

CURRENT_DIR="$( dirname -- "${BASH_SOURCE[0]}" )"

#load the environment variables
source $FORTIFY_HOME_K8S/.env

microk8s helm -n $NAMESPACE delete scancentral-sast
