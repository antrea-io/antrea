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

set -eo pipefail
LATEST_KIND_VERSION=$(head -n1 ./ci/kind/version)

# on linux
function upgrade_kind {
    arch_name="$(uname -m)"
    binary_name=""
    case "$arch_name" in
     "x86_64")
      binary_name="kind-linux-amd64"
      ;;
      "aarch64")
      binary_name="kind-linux-arm64"
      ;;
      *)
      echoerr "Unsupported platform $arch_name"
      exit 1
      ;;
    esac

    curl -Lo ./kind https://kind.sigs.k8s.io/dl/$LATEST_KIND_VERSION/$binary_name
    chmod +x ./kind
    sudo mv kind /usr/local/bin
}

CMD_RETURN_CODE=0
kind_version=$(kind version | awk  '{print $2}') || CMD_RETURN_CODE=$?
if [[ ${CMD_RETURN_CODE} -ne 0 ]]; then  
    echo "=== Installing Kind ==="
    upgrade_kind
    exit 0  
elif [[ "$kind_version" != "$LATEST_KIND_VERSION" ]]; then
    echo "=== Upgrading Kind to the latest version $LATEST_KIND_VERSION ==="
    upgrade_kind 
else
    echo "=== Existing Kind version $kind_version is up to date ==="
    exit 0
fi

