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
        --skip                        A comma-separated list of keywords, with which tests should be skipped.
        --coverage                    Enables measure Antrea code coverage when run e2e tests on kind.
        --help, -h                    Print this message and exit.
"

function print_usage {
    echoerr "$_usage"
}


TESTBED_CMD=$(dirname $0)"/kind-setup.sh"
YML_CMD=$(dirname $0)"/../../hack/generate-manifest.sh"
FLOWAGGREGATOR_YML_CMD=$(dirname $0)"/../../hack/generate-manifest-flow-aggregator.sh"

function quit {
  if [[ $? != 0 ]]; then
    echoerr " Test failed cleaning testbed"
    $TESTBED_CMD destroy kind
  fi
}
trap "quit" INT EXIT

mode=""
ipfamily="v4"
proxy=true
proxy_all=false
endpointslice=false
np=true
coverage=false
skiplist=""
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

COMMON_IMAGES_LIST=("k8s.gcr.io/e2e-test-images/agnhost:2.29" \
                    "projects.registry.vmware.com/library/busybox"  \
                    "projects.registry.vmware.com/antrea/nginx:1.21.6-alpine" \
                    "projects.registry.vmware.com/antrea/perftool" \
                    "projects.registry.vmware.com/antrea/ipfix-collector:v0.5.11" \
                    "projects.registry.vmware.com/antrea/wireguard-go:0.0.20210424")
for image in "${COMMON_IMAGES_LIST[@]}"; do
    for i in `seq 3`; do
        docker pull $image && break
        sleep 1
    done
done
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

printf -v COMMON_IMAGES "%s " "${COMMON_IMAGES_LIST[@]}"

function run_test {
  current_mode=$1
  args=$2

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

  if $coverage; then
      $YML_CMD --kind --encap-mode $current_mode $manifest_args | docker exec -i kind-control-plane dd of=/root/antrea-coverage.yml
      $YML_CMD --kind --encap-mode $current_mode --wireguard-go $manifest_args | docker exec -i kind-control-plane dd of=/root/antrea-wireguard-go-coverage.yml
      $FLOWAGGREGATOR_YML_CMD --coverage | docker exec -i kind-control-plane dd of=/root/flow-aggregator-coverage.yml
  else
      $YML_CMD --kind --encap-mode $current_mode $manifest_args | docker exec -i kind-control-plane dd of=/root/antrea.yml
      $YML_CMD --kind --encap-mode $current_mode --wireguard-go $manifest_args | docker exec -i kind-control-plane dd of=/root/antrea-wireguard-go.yml
      $FLOWAGGREGATOR_YML_CMD | docker exec -i kind-control-plane dd of=/root/flow-aggregator.yml
  fi
  if $proxy_all; then
      apiserver=$(docker exec -i kind-control-plane kubectl get endpoints kubernetes --no-headers | awk '{print $2}')
      if $coverage; then
        docker exec -i kind-control-plane sed -i.bak -E "s/^[[:space:]]*#kubeAPIServerOverride[[:space:]]*:[[:space:]]*[a-z\"]+[[:space:]]*$/    kubeAPIServerOverride: \"$apiserver\"/" /root/antrea-coverage.yml /root/antrea-wireguard-go-coverage.yml
      else
        docker exec -i kind-control-plane sed -i.bak -E "s/^[[:space:]]*#kubeAPIServerOverride[[:space:]]*:[[:space:]]*[a-z\"]+[[:space:]]*$/    kubeAPIServerOverride: \"$apiserver\"/" /root/antrea.yml /root/antrea-wireguard-go.yml
      fi
  fi
  sleep 1

  if $coverage; then
      go test -v -timeout=70m antrea.io/antrea/test/e2e -provider=kind --logs-export-dir=$ANTREA_LOG_DIR --coverage --coverage-dir $ANTREA_COV_DIR --skip=$skiplist
  else
      go test -v -timeout=65m antrea.io/antrea/test/e2e -provider=kind --logs-export-dir=$ANTREA_LOG_DIR --skip=$skiplist
  fi
  $TESTBED_CMD destroy kind
}

if [[ "$mode" == "" ]] || [[ "$mode" == "encap" ]]; then
  echo "======== Test encap mode =========="
  run_test encap "--images \"$COMMON_IMAGES\""
fi
if [[ "$mode" == "" ]] || [[ "$mode" == "noEncap" ]]; then
  echo "======== Test noencap mode =========="
  run_test noEncap "--images \"$COMMON_IMAGES\""
fi
if [[ "$mode" == "" ]] || [[ "$mode" == "hybrid" ]]; then
  echo "======== Test hybrid mode =========="
  run_test hybrid "--subnets \"20.20.20.0/24\" --images \"$COMMON_IMAGES\""
fi
exit 0

