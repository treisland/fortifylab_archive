#!/bin/bash

#load the environment variables
source $FORTIFY_HOME_K8S/.env

microk8s helm -n $NAMESPACE delete scancentral-sast