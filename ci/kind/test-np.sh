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

echo "===> Creating Kind cluster <==="

kind create cluster --config $KIND_CONFIG
kind load docker-image projects.registry.vmware.com/antrea/antrea-ubuntu:latest
# pre-load the test container image on all the Nodes
$ROOT_DIR/hack/generate-manifest.sh  --tun "vxlan" | kubectl apply -f -

echo "===> Creating netpol ClusterRoleBinding, ServiceAccount and Job <==="

$ROOT_DIR/ci/run-k8s-e2e-tests.sh --e2e-network-policy

