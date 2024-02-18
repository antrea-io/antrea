#!/usr/bin/env bash

# Copyright 2024 Antrea Authors
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

set -eo pipefail

function echoerr {
    >&2 echo "$@"
}

_usage="Usage: $0 [--setup-only|--test-only|--cleanup-only] [--help|-h]
        --setup-only                  Only perform setting up the cluster and run test.
        --test-only                   Only run test on current cluster. Not set up/clean up the cluster.
        --cleanup-only                Only perform cleaning up the cluster.
        --help, -h                    Print this message and exit.
"

function print_usage {
    echoerr -n "$_usage"
}

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
TESTBED_CMD=$THIS_DIR"/kind-setup.sh"
ATTACHMENT_DEFINITION_YAML=$THIS_DIR"/../../test/e2e-secondary-network/infra/network-attachment-definition-crd.yml"
SECONDARY_NETWORKS_YAML=$THIS_DIR"/../../test/e2e-secondary-network/infra/secondary-networks.yml"
ANTREA_CHART="$THIS_DIR/../../build/charts/antrea"

TIMEOUT="5m"
# Antrea is deployed by this script. Do not deploy it again in the test.
TEST_OPTIONS="--logs-export-dir=$ANTREA_LOG_DIR --deploy-antrea=false"
EXTRA_NETWORK="20.20.20.0/24"

setup_only=false
cleanup_only=false
test_only=false

function quit {
  result=$?
  if [[ $setup_only || $test_only ]]; then
    exit $result
  fi
  echoerr "Cleaning testbed"
  $TESTBED_CMD destroy kind
}

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --setup-only)
    setup_only=true
    shift
    ;;
    --cleanup-only)
    cleanup_only=true
    shift
    ;;
    --test-only)
    test_only=true
    shift
    ;;
    -h|--help)
    print_usage
    exit 0
    ;;
    *)    # unknown option
    echoerr "Unknown option $1"
    exit 1
    ;;
esac
done

if [[ $cleanup_only == "true" ]];then
  $TESTBED_CMD destroy kind
  exit 0
fi

trap "quit" INT EXIT

IMAGE_LIST=("projects.registry.vmware.com/antrea/toolbox:1.3-0" \
            "antrea/antrea-agent-ubuntu:latest" \
            "antrea/antrea-controller-ubuntu:latest")

printf -v IMAGES "%s " "${IMAGE_LIST[@]}"

function setup_cluster {
  args=$1
  echo "creating test bed with args $args"
  eval "timeout 600 $TESTBED_CMD create kind $args"
}

function run_test {
  echo "deploying Antrea to the kind cluster"
  # Create a secondary OVS bridge with the Node's physical interface on the extra
  # network.
  helm install antrea $ANTREA_CHART --namespace kube-system \
     --set featureGates.SecondaryNetwork=true,featureGates.AntreaIPAM=true \
     --set-json secondaryNetwork.ovsBridges='[{"bridgeName": "br-secondary", "physicalInterfaces": ["eth1"]}]'

  # Wait for antrea-controller start to make sure the IPPool validation webhook is ready.
  kubectl rollout status --timeout=1m deployment.apps/antrea-controller -n kube-system
  kubectl apply -f $ATTACHMENT_DEFINITION_YAML
  kubectl apply -f $SECONDARY_NETWORKS_YAML

  go test -v -timeout=$TIMEOUT antrea.io/antrea/test/e2e-secondary-network -run=TestVLANNetwork -provider=kind $TEST_OPTIONS
}

echo "======== Testing Antrea-native secondary network support =========="
if [[ $test_only == "false" ]];then
  setup_cluster "--extra-networks \"$EXTRA_NETWORK\" --images \"$IMAGES\" --num-workers 1"
fi
run_test
exit 0
