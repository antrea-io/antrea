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

TESTBED_CMD=$(dirname $0)"/kind-setup.sh"
YML_CMD=$(dirname $0)"/../../hack/generate-manifest.sh"
COMMON_IMAGES="busybox nginx antrea/antrea-ubuntu:latest"

function quit {
  if [[ $? != 0 ]]; then
    echo " Test failed cleaning testbed"
    $TESTBED_CMD destroy kind
  fi
}
trap "quit" INT EXIT

function run_test {
  mode=$1
  proxy=$2
  args=$3
  if [[ $proxy != "--proxy" ]]; then
    proxy=""
    args=$2
  fi

  echo "create test bed with args $args"
  eval "timeout 600 $TESTBED_CMD create kind --antrea-cni false $args"

  $YML_CMD --kind --encap-mode $mode $proxy | docker exec -i kind-control-plane dd of=/root/antrea.yml
  sleep 1
  go test -v -timeout=20m github.com/vmware-tanzu/antrea/test/e2e -provider=kind
  $TESTBED_CMD destroy kind
}

docker pull busybox
docker pull nginx

if [[ $# == 0 ]] || [[ $1 == "encap" ]]; then
  echo "======== Test encap mode =========="
  run_test encap $2 "--images \"$COMMON_IMAGES\""
fi
if [[ $# == 0 ]] || [[ $1 == "noEncap" ]]; then
  echo "======== Test noencap mode =========="
  run_test noEncap $2 "--images \"$COMMON_IMAGES\""
fi
if [[ $# == 0 ]] || [[ $1 == "hybrid" ]]; then
  echo "======== Test hybrid mode =========="
  run_test hybrid $2 "--subnets \"20.20.20.0/24\" --images \"$COMMON_IMAGES\""
fi
exit 0

