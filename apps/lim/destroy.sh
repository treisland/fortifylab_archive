#get the current directory where this script resides
CURRENT_DIR="$( dirname -- "${BASH_SOURCE[0]}" )"

#load the environment variables
source $FORTIFY_HOME_K8S/.env

microk8s helm -n $NAMESPACE delete lim

microk8s kubectl -n $NAMESPACE delete -f $CURRENT_DIR/pvc.yaml

microk8s kubectl -n $NAMESPACE delete -f $CURRENT_DIR/ingress.yaml