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

expected_kubectl_version=""
if [[ -n $1 ]];then
    expected_kubectl_version=$1
elif ! which kubectl > /dev/null; then
    expected_kubectl_version=$(head -n1 ./k8s-version)
else
    # Check both Client and Server versions. If the Server version is not found, make sure the
    # version of kubectl matches the version in the file k8s-version. If Client and Server versions
    # are not matched, reinstall kubectl to the same version as K8s server.
    installed_kubectl_version=$(kubectl version | grep "Client Version" | awk '{print $3}')
    cmd_return_code=0
    k8s_server_version=$(kubectl version | grep "Server Version" | awk '{print $3}') || cmd_return_code=$?
    if [[ $cmd_return_code -ne 0 ]]; then
      expected_kubectl_version=$(head -n1 ./k8s-version)
      if [[ "$installed_kubectl_version" == "$expected_kubectl_version" ]]; then
        echo "=== Existing kubectl version $installed_kubectl_version is up to date ==="
        exit 0
      fi
    elif [[ "$installed_kubectl_version" != "$k8s_server_version" ]]; then
      expected_kubectl_version=$k8s_server_version
    else
      echo "=== Existing kubectl version $installed_kubectl_version is up to date ==="
      exit 0
    fi
fi

# Linux only
function install_kubectl {
    arch_name="$(uname -m)"
    arch=""
    case "$arch_name" in
     "x86_64")
      arch="amd64"
      ;;
      "aarch64")
      arch="arm64"
      ;;
      *)
      echoerr "Unsupported platform $arch_name"
      exit 1
      ;;
    esac

    curl -LO "https://dl.k8s.io/release/$expected_kubectl_version/bin/linux/$arch/kubectl"
    chmod +x ./kubectl
    sudo mv kubectl /usr/local/bin
}

echo "=== Install kubectl to the expected version $expected_kubectl_version ==="
install_kubectl
exit 0
