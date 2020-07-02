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

_usage="Usage: $0 [--encap-mode <mode>] [--proxy] [--np] [--help|-h]
        --encap-mode                  Traffic encapsulation mode. (default is 'encap')
        --proxy                       Enables Antrea proxy.
        --np                          Enables Namespaced Antrea NetworkPolicy CRDs and ClusterNetworkPolicy related CRDs.
        --help, -h                    Print this message and exit
"

function print_usage {
    echoerr "$_usage"
}


TESTBED_CMD=$(dirname $0)"/kind-setup.sh"
YML_CMD=$(dirname $0)"/../../hack/generate-manifest.sh"
COMMON_IMAGES="busybox nginx antrea/antrea-ubuntu:latest"

function quit {
  if [[ $? != 0 ]]; then
    echoerr " Test failed cleaning testbed"
    $TESTBED_CMD destroy kind
  fi
}
trap "quit" INT EXIT

mode=""
proxy=false
np=false
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --proxy)
    proxy=true
    shift
    ;;
    --np)
    np=true
    shift
    ;;
    --encap-mode)
    mode="$2"
    shift 2
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
if $proxy; then
    manifest_args="$manifest_args --proxy"
fi
if $np; then
    # See https://github.com/vmware-tanzu/antrea/issues/897
    manifest_args="$manifest_args --np --tun vxlan"
fi

function run_test {
  current_mode=$1
  args=$2

  echo "creating test bed with args $args"
  eval "timeout 600 $TESTBED_CMD create kind --antrea-cni false $args"

  $YML_CMD --kind --encap-mode $current_mode $manifest_args | docker exec -i kind-control-plane dd of=/root/antrea.yml
  sleep 1
  go test -v -timeout=30m github.com/vmware-tanzu/antrea/test/e2e -provider=kind
  $TESTBED_CMD destroy kind
}

docker pull busybox
docker pull nginx

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

