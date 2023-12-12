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
set -xv

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$THIS_DIR/../..

KIND_CONFIG=$ROOT_DIR/ci/kind/config-3nodes.yml

WAIT_TIMEOUT=240m
JOB_NAME=job.batch/cyclonus


kind create cluster --config "$KIND_CONFIG"
kind load docker-image antrea/antrea-agent-ubuntu:latest
kind load docker-image antrea/antrea-controller-ubuntu:latest

# pre-load cyclonus image
docker pull mfenwick100/cyclonus:v0.4.7
kind load docker-image mfenwick100/cyclonus:v0.4.7
# pre-load agnhost image
docker pull registry.k8s.io/e2e-test-images/agnhost:2.29
kind load docker-image registry.k8s.io/e2e-test-images/agnhost:2.29

"$ROOT_DIR"/hack/generate-manifest.sh | kubectl apply -f -


kubectl create clusterrolebinding cyclonus --clusterrole=cluster-admin --serviceaccount=kube-system:cyclonus
kubectl create sa cyclonus -n kube-system
kubectl create -f "$THIS_DIR"/install-cyclonus.yml


time kubectl wait --for=condition=complete --timeout=$WAIT_TIMEOUT -n kube-system $JOB_NAME

echo "===> Checking cyclonus results <==="

LOG_FILE=$(mktemp)
kubectl logs -n kube-system job.batch/cyclonus > "$LOG_FILE"
cat "$LOG_FILE"

rc=0
cat "$LOG_FILE" | grep "failure" > /dev/null 2>&1 || rc=$?
if [ $rc -eq 0 ]; then
    exit 1
fi
