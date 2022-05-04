#!/usr/bin/env bash

# Copyright 2020 Antrea Authors
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

# The script runs kind e2e tests with different traffic encapsulation modes.

set -eo pipefail

function echoerr {
    >&2 echo "$@"
}

_usage="Usage: $0 [--encap-mode <mode>] [--ip-family <v4|v6>] [--no-proxy] [--np] [--coverage] [--help|-h]
        --encap-mode                  Traffic encapsulation mode. (default is 'encap').
        --ip-family                   Configures the ipFamily for the KinD cluster.
        --no-proxy                    Disables Antrea proxy.
        --proxy-all                   Enables Antrea proxy with all Service support.
        --endpointslice               Enables Antrea proxy and EndpointSlice support.
        --no-np                       Disables Antrea-native policies.
        --flow-visibility             Only run flow visibility related e2e tests.
        --skip                        A comma-separated list of keywords, with which tests should be skipped.
        --coverage                    Enables measure Antrea code coverage when run e2e tests on kind.
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
FLOWAGGREGATOR_YML_CMD=$(dirname $0)"/../../hack/generate-manifest-flow-aggregator.sh"
FLOW_VISIBILITY_CMD=$(dirname $0)"/../../hack/generate-manifest-flow-visibility.sh --mode e2e"
FLOW_VISIBILITY_HELM_VALUES=$(dirname $0)"/values-flow-exporter.yml"
CH_OPERATOR_YML=$(dirname $0)"/../../build/yamls/clickhouse-operator-install-bundle.yml"

function quit {
  result=$?
  if [[ $setup_only || $test_only ]]; then
    exit $result
  fi
  echoerr "Cleaning testbed"
  $TESTBED_CMD destroy kind
}

mode=""
ipfamily="v4"
proxy=true
proxy_all=false
endpointslice=false
np=true
flow_visibility=false
coverage=false
skiplist=""
setup_only=false
cleanup_only=false
test_only=false
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --no-proxy)
    proxy=false
    shift
    ;;
    --proxy-all)
    proxy_all=true
    shift
    ;;
    --ip-family)
    ipfamily="$2"
    shift 2
    ;;
    --endpointslice)
    endpointslice=true
    shift
    ;;
    --no-np)
    np=false
    shift
    ;;
    --flow-visibility)
    flow_visibility=true
    shift
    ;;
    --skip)
    skiplist="$2"
    shift 2
    ;;
    --encap-mode)
    mode="$2"
    shift 2
    ;;
    --coverage)
    coverage=true
    shift
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

manifest_args=""
if ! $proxy; then
    manifest_args="$manifest_args --no-proxy"
fi
if $proxy_all; then
    if ! $proxy; then
      echoerr "--proxy-all requires AntreaProxy, so it cannot be used with --no-proxy"
      exit 1
    fi
    manifest_args="$manifest_args --proxy-all"
fi
if $endpointslice; then
    manifest_args="$manifest_args --endpointslice"
fi
if ! $np; then
    manifest_args="$manifest_args --no-np"
fi
if $flow_visibility; then
    manifest_args="$manifest_args --flow-exporter --extra-helm-values-file $FLOW_VISIBILITY_HELM_VALUES"
fi

COMMON_IMAGES_LIST=("k8s.gcr.io/e2e-test-images/agnhost:2.29" \
                    "projects.registry.vmware.com/library/busybox"  \
                    "projects.registry.vmware.com/antrea/nginx:1.21.6-alpine" \
                    "projects.registry.vmware.com/antrea/perftool")

FLOW_VISIBILITY_IMAGE_LIST=("projects.registry.vmware.com/antrea/ipfix-collector:v0.5.12" \
                            "projects.registry.vmware.com/antrea/flow-visibility-clickhouse-operator:0.18.2" \
                            "projects.registry.vmware.com/antrea/flow-visibility-metrics-exporter:0.18.2" \
                            "projects.registry.vmware.com/antrea/flow-visibility-clickhouse-server:21.11" \
                            "projects.registry.vmware.com/antrea/flow-visibility-clickhouse-monitor:latest")
if $coverage; then
    manifest_args="$manifest_args --coverage"
    COMMON_IMAGES_LIST+=("antrea/antrea-ubuntu-coverage:latest")
    COMMON_IMAGES_LIST+=("antrea/flow-aggregator-coverage:latest")
else
    COMMON_IMAGES_LIST+=("projects.registry.vmware.com/antrea/antrea-ubuntu:latest")
    COMMON_IMAGES_LIST+=("projects.registry.vmware.com/antrea/flow-aggregator:latest")
fi
if $proxy_all; then
    COMMON_IMAGES_LIST+=("k8s.gcr.io/echoserver:1.10")
fi
if $flow_visibility; then
    COMMON_IMAGES_LIST+=("${FLOW_VISIBILITY_IMAGE_LIST[@]}")
    if $coverage; then
        COMMON_IMAGES_LIST+=("antrea/flow-aggregator-coverage:latest")
    else
        COMMON_IMAGES_LIST+=("projects.registry.vmware.com/antrea/flow-aggregator:latest")
    fi
fi
for image in "${COMMON_IMAGES_LIST[@]}"; do
    for i in `seq 3`; do
        docker pull $image && break
        sleep 1
    done
done

printf -v COMMON_IMAGES "%s " "${COMMON_IMAGES_LIST[@]}"

function setup_cluster {
  args=$1

  if [[ "$ipfamily" == "v6" ]]; then
    args="$args --ip-family ipv6 --pod-cidr fd00:10:244::/56"
  elif [[ "$ipfamily" != "v4" ]]; then
    echoerr "invalid value for --ip-family \"$ipfamily\", expected \"v4\" or \"v6\""
    exit 1
  fi
  if $proxy_all; then
    args="$args --no-kube-proxy"
  fi

  echo "creating test bed with args $args"
  eval "timeout 600 $TESTBED_CMD create kind $args"
}

function run_test {
  current_mode=$1
  coverage_args=""
  flow_visibility_args=""

  if $coverage; then
      $YML_CMD --encap-mode $current_mode $manifest_args | docker exec -i kind-control-plane dd of=/root/antrea-coverage.yml
      $YML_CMD --ipsec $manifest_args | docker exec -i kind-control-plane dd of=/root/antrea-ipsec-coverage.yml
      timeout="80m"
      coverage_args="--coverage --coverage-dir $ANTREA_COV_DIR"
  else
      $YML_CMD --encap-mode $current_mode $manifest_args | docker exec -i kind-control-plane dd of=/root/antrea.yml
      $YML_CMD --ipsec $manifest_args | docker exec -i kind-control-plane dd of=/root/antrea-ipsec.yml
      timeout="75m"
  fi

  if $flow_visibility; then
      timeout="10m"
      flow_visibility_args="-run=TestFlowAggregator --flow-visibility"
      if $coverage; then
          $FLOWAGGREGATOR_YML_CMD --coverage | docker exec -i kind-control-plane dd of=/root/flow-aggregator-coverage.yml
      else
          $FLOWAGGREGATOR_YML_CMD | docker exec -i kind-control-plane dd of=/root/flow-aggregator.yml
      fi
      $FLOW_VISIBILITY_CMD | docker exec -i kind-control-plane dd of=/root/flow-visibility.yml
      cat $CH_OPERATOR_YML | docker exec -i kind-control-plane dd of=/root/clickhouse-operator-install-bundle.yml
  fi

  if $proxy_all; then
      apiserver=$(docker exec -i kind-control-plane kubectl get endpoints kubernetes --no-headers | awk '{print $2}')
      if $coverage; then
        docker exec -i kind-control-plane sed -i.bak -E "s/^[[:space:]]*[#]?kubeAPIServerOverride[[:space:]]*:[[:space:]]*[a-z\"]+[[:space:]]*$/    kubeAPIServerOverride: \"$apiserver\"/" /root/antrea-coverage.yml /root/antrea-ipsec-coverage.yml
      else
        docker exec -i kind-control-plane sed -i.bak -E "s/^[[:space:]]*[#]?kubeAPIServerOverride[[:space:]]*:[[:space:]]*[a-z\"]+[[:space:]]*$/    kubeAPIServerOverride: \"$apiserver\"/" /root/antrea.yml /root/antrea-ipsec.yml
      fi
  fi
  sleep 1

  go test -v -timeout=$timeout antrea.io/antrea/test/e2e $flow_visibility_args -provider=kind --logs-export-dir=$ANTREA_LOG_DIR --skip=$skiplist $coverage_args
}

if [[ "$mode" == "" ]] || [[ "$mode" == "encap" ]]; then
  echo "======== Test encap mode =========="
  if [[ $test_only == "false" ]];then
    setup_cluster "--images \"$COMMON_IMAGES\""
  fi
  run_test encap
fi
if [[ "$mode" == "" ]] || [[ "$mode" == "noEncap" ]]; then
  echo "======== Test noencap mode =========="
  if [[ $test_only == "false" ]];then
    setup_cluster "--images \"$COMMON_IMAGES\""
  fi
  run_test noEncap
fi
if [[ "$mode" == "" ]] || [[ "$mode" == "hybrid" ]]; then
  echo "======== Test hybrid mode =========="
  if [[ $test_only == "false" ]];then
    setup_cluster "--subnets \"20.20.20.0/24\" --images \"$COMMON_IMAGES\""
  fi
  run_test hybrid
fi
exit 0

