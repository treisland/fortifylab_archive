#!/bin/bash

source $FORTIFY_HOME_K8S/.env

POD_NAME="ssc-webapp-0"

microk8s helm -n $NAMESPACE delete ssc

# Wait for the pod to no longer exist
while microk8s kubectl -n $NAMESPACE get pods "$POD_NAME" &> /dev/null; do
    echo "Waiting for pod $POD_NAME to terminate..."
    sleep 5
done
