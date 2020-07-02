#!/usr/bin/env bash

set -eo pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$THIS_DIR/../..

KIND_CONFIG=$ROOT_DIR/ci/kind/config-3nodes.yml

WAIT_TIMEOUT=15m
JOB_NAME=job.batch/netpol

echo "===> Creating Kind cluster <==="

kind create cluster --config $KIND_CONFIG
kind get nodes | xargs $ROOT_DIR/hack/kind-fix-networking.sh
kind load docker-image antrea/antrea-ubuntu:latest
kind load docker-image antrea/netpol:latest
# pre-load the test container image on all the Nodes
docker pull antrea/netpol-test
kind load docker-image antrea/netpol-test
$ROOT_DIR/hack/generate-manifest.sh --kind --tun "vxlan" | kubectl apply -f -

echo "===> Creating netpol ClusterRoleBinding, ServiceAccount and Job <==="

kubectl create clusterrolebinding netpol --clusterrole=cluster-admin --serviceaccount=kube-system:netpol
kubectl create sa netpol -n kube-system
kubectl create -f $THIS_DIR/install-latest.yml

echo "===> Waiting for netpol Job to complete. This can take a while... <==="

time kubectl wait --for=condition=complete --timeout=$WAIT_TIMEOUT -n kube-system $JOB_NAME

echo "===> Checking netpol results <==="

LOG_FILE=$(mktemp)
kubectl logs -n kube-system job.batch/netpol > $LOG_FILE
RESULT_STR=$(grep "TEST FAILURES" $LOG_FILE)
echo $RESULT_STR
rc=0
echo $RESULT_STR | grep "0/" > /dev/null 2>&1 || rc=$?
if [ $rc -ne 0 ]; then
    cat $LOG_FILE
    exit 1
fi
