#!/usr/bin/env bash

# Copyright 2019 Antrea Authors
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

_GOPATH_BIN="$(go env GOPATH)/bin"
_MIN_KUSTOMIZE_VERSION="v3.3.0"

# Ensure the kustomize tool exists and is a viable version, or installs it
verify_kustomize() {
    # If kustomize is not available on the path, get it.
    local kustomize="$(PATH=$PATH:$_GOPATH_BIN command -v kustomize)"
    if [ ! -x "$kustomize" ]; then
        local ostype=""
        if [[ "$OSTYPE" == "linux-gnu" ]]; then
            ostype="linux"
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            ostype="darwin"
        else
            >&2 echo "Unsupported OS type $OSTYPE"
            return 1
        fi
        >&2 echo "Installing kustomize"
        local kustomize_url="https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/${_MIN_KUSTOMIZE_VERSION}/kustomize_${_MIN_KUSTOMIZE_VERSION}_${ostype}_amd64.tar.gz"
        curl -sLo kustomize.tar.gz "${kustomize_url}" || return 1
        mkdir -p "$_GOPATH_BIN" || return 1
        tar -xzf kustomize.tar.gz -C "$_GOPATH_BIN" || return 1
        rm -f kustomize.tar.gz
        kustomize="$_GOPATH_BIN/kustomize"
        echo "$kustomize"
        return 0
    fi

    # Verify version if kustomize was already installed.
    local kustomize_version="$($kustomize version --short)"
    kustomize_version="${kustomize_version##*/}"
    if [ "${kustomize_version}" == "${_MIN_KUSTOMIZE_VERSION}" ]; then
        # If version is exact match, stop here.
        echo "$kustomize"
        return 0
    fi
    if [[ "${_MIN_KUSTOMIZE_VERSION}" != $(echo -e "${_MIN_KUSTOMIZE_VERSION}\n${kustomize_version}" | sort -V | head -n1) ]]; then
        >&2 echo "Your version of kustomize is not recent enough, please install version ${_MIN_KUSTOMIZE_VERSION}"
        return 2
    fi
    echo "$kustomize"
}
