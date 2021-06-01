#!/usr/bin/env bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
REPO_DIR=$THIS_DIR/..
# Well known kubeconfig path.
BASE_KUBECONFIG="$HOME/.kube/config"
KUBECONFIG="/tmp/admin.conf"
ANTREA_YML="/tmp/antrea.yml"

# Generate antrea yaml for scale test, the yaml makes agent will not be scheduled to simulator nodes.
"$REPO_DIR"/hack/generate-manifest.sh --mode dev --simulator > $ANTREA_YML
cat "$REPO_DIR"/build/yamls/patches/simulator/antrea-agent-simulator.yml >> $ANTREA_YML
kubectl apply -f $ANTREA_YML

# Try best to clean up old config.
kubectl delete -f "$REPO_DIR/build/yamls/antrea-agent-simulator.yml" || true
kubectl delete secret kubeconfig || true

cp "$BASE_KUBECONFIG" $KUBECONFIG
# Create simulators.
kubectl create secret generic kubeconfig --type=Opaque --namespace=kube-system --from-file $KUBECONFIG
kubectl apply -f "$REPO_DIR/build/yamls/antrea-agent-simulator.yml"

# Create scale test job.
kubectl apply -f "$REPO_DIR/build/yamls/antrea-scale.yml"
