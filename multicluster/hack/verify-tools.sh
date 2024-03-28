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

os=$(echo $(uname) | tr '[:upper:]' '[:lower:]')
if ! which kind > /dev/null; then
    if [[ ${os} == 'darwin' || ${os} == 'linux' ]]; then
        curl -Lo ./kind https://github.com/kubernetes-sigs/kind/releases/download/v0.22.0/kind-${os}-amd64
        chmod +x ./kind
        if [[ "$WORKDIR" != "" ]];then
          mv kind "$WORKDIR"
        else
          sudo mv kind /usr/local/bin
        fi
    fi
fi

if ! which kubectl > /dev/null; then
    if [[ ${os} == 'darwin' || ${os} == 'linux' ]]; then
        curl -LO https://dl.k8s.io/release/v1.29.2/bin/${os}/amd64/kubectl
        chmod +x ./kubectl
        if [[ "$WORKDIR" != "" ]];then
          mv kubectl "$WORKDIR"
        else
          sudo mv kubectl /usr/local/bin
        fi
    fi
fi
