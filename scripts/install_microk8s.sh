#!/bin/bash

set -euo pipefail

if [ -z "$FORTIFY_HOME_K8S" ]; then
    FORTIFY_HOME_K8S="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    export FORTIFY_HOME_K8S
fi

#load the environment variables
source "$FORTIFY_HOME_K8S/.env"

sudo snap install microk8s --classic

#used for dynamic provisioning of persistent volumes
sudo apt install nfs-common -y

#enable the ability to get community add-ons
sudo microk8s enable community

#enabling nfs allows for that dynamic provisioning of persistant volumes (requires nfs-common)
sudo microk8s enable nfs

#enable the kubernetes dashboard for a web gui
sudo microk8s enable dashboard

#so that pods can communicate via service names
sudo microk8s enable dns

#ability to allow ingress endpoints
sudo microk8s enable ingress

#start the cluster
sudo microk8s start
