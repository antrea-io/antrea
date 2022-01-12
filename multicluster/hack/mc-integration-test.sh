#!/usr/bin/env bash

# Copyright 2021 Antrea Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

clean_up() {
  kind delete cluster --name antrea-integration-kind
}

trap clean_up EXIT

BASEDIR=$(dirname $0)
WORKDIR=$1
if [[ "$WORKDIR" != "" ]];then
  export PATH=$PATH:$WORKDIR
fi

echo "" > /tmp/mc-integration-kubeconfig
kind create cluster --name=antrea-integration-kind --kubeconfig=/tmp/mc-integration-kubeconfig
sleep 5
export KUBECONFIG=/tmp/mc-integration-kubeconfig
kubectl create namespace leader-ns
# Here we simply create a cluster-admin user for member to access leader
kubectl apply -f test/integration/cluster-admin.yml

if [[ $NO_LOCAL == "true" ]];then
  # Run go test in a Docker container
  container_ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' antrea-integration-kind-control-plane)
  sed -i "s|server: https://.*|server: https://${container_ip}:6443|" /tmp/mc-integration-kubeconfig
  docker run --network kind --privileged --rm \
	  -w /usr/src/antrea.io/antrea \
    -v /tmp/mc-integration-kubeconfig:/tmp/mc-integration-kubeconfig \
	  -v ${BASEDIR}/../.coverage:/usr/src/antrea.io/antrea/multicluster/.coverage \
	  -v ${BASEDIR}/../..:/usr/src/antrea.io/antrea:ro \
	  antrea/mc-test test-integration
else
    go test -coverpkg=antrea.io/antrea/multicluster/controllers/multicluster/... -coverprofile=../.coverage/coverage-integration.txt -covermode=atomic -cover antrea.io/antrea/multicluster/test/integration/...
fi
