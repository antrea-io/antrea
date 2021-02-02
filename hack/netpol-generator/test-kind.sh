#!/usr/bin/env bash

set -eo pipefail
set -xv

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$THIS_DIR/../..

KIND_CONFIG=$ROOT_DIR/ci/kind/config-3nodes.yml

WAIT_TIMEOUT=240m
JOB_NAME=job.batch/cyclonus


kind create cluster --config "$KIND_CONFIG"
kind get nodes | xargs "$ROOT_DIR"/hack/kind-fix-networking.sh
kind load docker-image projects.registry.vmware.com/antrea/antrea-ubuntu:latest

# pre-load cyclonus image
docker pull mfenwick100/cyclonus:latest
kind load docker-image mfenwick100/cyclonus:latest
# pre-load agnhost image
docker pull k8s.gcr.io/e2e-test-images/agnhost:2.21
kind load docker-image k8s.gcr.io/e2e-test-images/agnhost:2.21

"$ROOT_DIR"/hack/generate-manifest.sh --kind --tun "vxlan" | kubectl apply -f -


kubectl create clusterrolebinding cyclonus --clusterrole=cluster-admin --serviceaccount=kube-system:cyclonus
kubectl create sa cyclonus -n kube-system
kubectl create -f "$THIS_DIR"/install-cyclonus.yml


time kubectl wait --for=condition=complete --timeout=$WAIT_TIMEOUT -n kube-system $JOB_NAME

echo "===> Checking cyclonus results <==="

LOG_FILE=$(mktemp)
kubectl logs -n kube-system job.batch/cyclonus > "$LOG_FILE"
cat "$LOG_FILE"

rc=0
cat "$LOG_FILE" | grep "discrepancy" > /dev/null 2>&1 || rc=$?
if [ $rc -ne 0 ]; then
    exit 1
fi
