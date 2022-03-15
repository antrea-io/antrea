#!/usr/bin/env bash
# Copyright 2022 Antrea Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


set -eo pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$THIS_DIR/../..

KIND_CONFIG=$ROOT_DIR/ci/kind/config-3nodes.yml

WAIT_TIMEOUT=15m
JOB_NAME=job.batch/netpol

echo "===> Creating Kind cluster <==="

kind create cluster --config $KIND_CONFIG
kind load docker-image projects.registry.vmware.com/antrea/antrea-ubuntu:latest
kind load docker-image antrea/netpol:latest
# pre-load the test container image on all the Nodes
docker pull antrea/netpol-test
kind load docker-image antrea/netpol-test
$ROOT_DIR/hack/generate-manifest.sh | kubectl apply -f -

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
