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

# This script makes sure that the tools required by integration tests are installed
# including Kind and kubectl.

WORKDIR=$1

kind_version="v0.20.0"
kubectl_version="v1.27.3"

os=$(echo $(uname) | tr '[:upper:]' '[:lower:]')

function install_kind(){
    if [[ ${os} == 'darwin' || ${os} == 'linux' ]]; then
      curl -Lo ./kind https://github.com/kubernetes-sigs/kind/releases/download/${kind_version}/kind-${os}-amd64
      chmod +x ./kind
      if [[ "$WORKDIR" != "" ]];then
        mv kind "$WORKDIR"
      else
        sudo mv kind /usr/local/bin
      fi
    fi
}

function install_kubectl() {
    if [[ ${os} == 'darwin' || ${os} == 'linux' ]]; then
        curl -LO https://dl.k8s.io/release/${kubectl_version}/bin/${os}/amd64/kubectl
        chmod +x ./kubectl
        if [[ "$WORKDIR" != "" ]];then
          mv kubectl "$WORKDIR"
        else
          sudo mv kubectl /usr/local/bin
        fi
    fi
}

if ! which kind > /dev/null; then
    install_kind
else
    installed_kind_version=$(kind version | awk  '{print $2}')
    if [[ "${installed_kind_version}" != "${kind_version}" ]];then
      install_kind
    fi
fi

if ! which kubectl > /dev/null; then
    install_kubectl
else
    installed_kubectl_version=$(kubectl version --short 2>/dev/null | grep "Client" |awk -F':' '{print $2}' | tr -d ' ')
    if [[ "${installed_kubectl_version}" != "${kubectl_version}" ]];then
    install_kubectl
    fi
fi
