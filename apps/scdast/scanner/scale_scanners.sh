#!/bin/bash

# Namespace and StatefulSet name
STATEFULSET="sdast-scanner-scancentral-dast-scanner"

# Function for scaling the StatefulSet
scale_statefulset() {
  read -p "Enter the number of scanners: " replicas
  if [[ "$replicas" =~ ^[0-9]+$ ]]; then
    echo "Scaling the number of scanners to $replicas"
    microk8s kubectl -n $NAMESPACE scale statefulset $STATEFULSET --replicas=$replicas
    echo "Scaling operation completed."
  else
    echo "Invalid input. Please enter a valid number."
  fi
}

# Loop for scaling StatefulSet
while true; do
  echo
  echo "----------------------------------"
  echo " Scale DAST Scanner Menu"
  echo "----------------------------------"
  echo "1. Scale Scan Machines"
  echo "2. Exit"
  echo

  read -p "Enter your choice (1-2): " choice
  echo

  case $choice in
    1)
      scale_statefulset
      ;;
    2)
      echo "Exiting the scaling loop. Goodbye!"
      break
      ;;
    *)
      echo "Invalid option. Please try again."
      ;;

  esac
done
