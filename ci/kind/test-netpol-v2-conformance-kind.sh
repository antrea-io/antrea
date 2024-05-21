#!/usr/bin/env bash

# Copyright 2023 Antrea Authors
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

# The script runs NetworkPolicy conformance tests on Kind with different traffic encapsulation modes.

set -eo pipefail

function echoerr {
    >&2 echo "$@"
}

_usage="Usage: $0 [--api-version <version>] [--ip-family <v4|v6>] [--help|-h]
        --api-version                 Set specific network-policy-api version for testing.
        --ip-family                   Configures the ipFamily for the KinD cluster.
        --feature-gates               A comma-separated list of key=value pairs that describe feature gates, e.g. AntreaProxy=true,Egress=false.
        --setup-only                  Only perform setting up the cluster and run test.
        --cleanup-only                Only perform cleaning up the cluster.
        --test-only                   Only run test on current cluster. Not set up/clean up the cluster.
        --help, -h                    Print this message and exit.
"

function print_usage {
    echoerr -n "$_usage"
}

TESTBED_CMD=$(dirname $0)"/kind-setup.sh"
YML_CMD=$(dirname $0)"/../../hack/generate-manifest.sh"

function quit {
  result=$?
  if [[ $setup_only || $test_only ]]; then
    exit $result
  fi
  echoerr "Cleaning testbed"
  $TESTBED_CMD destroy kind
}

api_version="v0.1.7"
ipfamily="v4"
feature_gates="AdminNetworkPolicy=true"
setup_only=false
cleanup_only=false
test_only=false
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --api-version)
    api_version="$2"
    shift 2
    ;;
    --feature-gates)
    feature_gates="$2"
    shift 2
    ;;
    --ip-family)
    ipfamily="$2"
    shift 2
    ;;
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

if [ -n "$feature_gates" ]; then
  manifest_args="$manifest_args --feature-gates $feature_gates"
fi

IMAGE_LIST=("registry.k8s.io/e2e-test-images/agnhost:2.43" \
            "antrea/antrea-agent-ubuntu:latest" \
            "antrea/antrea-controller-ubuntu:latest")

# Use Kubernetes 1.31+ for isCIDR CEL validation function support (required by network-policy-api v0.1.7)
K8S_VERSION="v1.31.2"
printf -v IMAGES "%s " "${IMAGE_LIST[@]}"

function setup_cluster {
  args=$1

  if [[ "$ipfamily" == "v6" ]]; then
    args="$args --ip-family ipv6 --pod-cidr fd00:10:244::/56"
  elif [[ "$ipfamily" != "v4" ]]; then
    echoerr "invalid value for --ip-family \"$ipfamily\", expected \"v4\" or \"v6\""
    exit 1
  fi

  echo "creating test bed with args $args"
  eval "timeout 600 $TESTBED_CMD create kind $args"
}

function run_test {
  # Install the network-policy-api CRDs in the kind cluster
  kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/"$api_version"/config/crd/experimental/policy.networking.k8s.io_adminnetworkpolicies.yaml
  kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/"$api_version"/config/crd/experimental/policy.networking.k8s.io_baselineadminnetworkpolicies.yaml
  echo "Generating Antrea manifest with args $manifest_args"
  $YML_CMD $manifest_args | kubectl apply -f -

  kubectl rollout status --timeout=1m deployment.apps/antrea-controller -n kube-system
  kubectl rollout status --timeout=1m daemonset/antrea-agent -n kube-system

  # KUBERNETES_CONFORMANCE_TEST=y prevents ginkgo e2e from trying to run provider setup
  export KUBERNETES_CONFORMANCE_TEST=y
  # The following env variables are required to make RuntimeClass tests work
  export KUBE_CONTAINER_RUNTIME=remote
  export KUBE_CONTAINER_RUNTIME_ENDPOINT=unix:///run/containerd/containerd.sock
  export KUBE_CONTAINER_RUNTIME_NAME=containerd

  git clone https://github.com/kubernetes-sigs/network-policy-api
  pushd network-policy-api
  # Checkout the specific version tag to match the API version being tested
  git checkout "$api_version"
  cd conformance
  go mod download
  go test -v -run TestConformanceProfiles -args --conformance-profiles=AdminNetworkPolicy,BaselineAdminNetworkPolicy \
    --supported-features=AdminNetworkPolicyNamedPorts,BaselineAdminNetworkPolicyNamedPorts,AdminNetworkPolicyEgressNodePeers,BaselineAdminNetworkPolicyEgressNodePeers \
    --organization=antrea-io -project=antrea -url=https://github.com/antrea-io/antrea -version=v2.4 \
    --additional-info=https://github.com/antrea-io/antrea/actions/workflows/kind.yml \
    --debug=true -test.timeout=15m
  popd
}

echo "======== Testing networkpolicy v2 conformance in encap mode =========="
if [[ $test_only == "false" ]];then
  setup_cluster "--images \"$IMAGES\" --k8s-version $K8S_VERSION"
fi
run_test
exit 0
