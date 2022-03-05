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

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
_BINDIR="$THIS_DIR/.bin"
# Must be an exact match, as the generated YAMLs may not be consistent across
# versions
_KUSTOMIZE_VERSION="v4.4.1"

# Ensure the kustomize tool exists and is the correct version, or installs it
verify_kustomize() {
    # Check if there is already a kustomize binary in $_BINDIR and if yes, check
    # if the version matches the expected one.
    local kustomize="$(PATH=$_BINDIR command -v kustomize)"
    if [ -x "$kustomize" ]; then
        # Verify version if kustomize was already installed.
        local kustomize_version="$($kustomize version --short)"
        # Should work with:
        #  - kustomize/v3.3.0
        #  - {kustomize/v3.8.2  2020-08-29T17:44:01Z  }
        kustomize_version="${kustomize_version##*/}"
        kustomize_version="${kustomize_version%% *}"
        if [ "${kustomize_version}" == "${_KUSTOMIZE_VERSION}" ]; then
            # If version is exact match, stop here.
            echo "$kustomize"
            return 0
        fi
        >&2 echo "Detected kustomize version ($kustomize_version) does not match expected one ($_KUSTOMIZE_VERSION), installing correct version"
    fi
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
    local kustomize_url="https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/${_KUSTOMIZE_VERSION}/kustomize_${_KUSTOMIZE_VERSION}_${ostype}_amd64.tar.gz"
    curl -sLo kustomize.tar.gz "${kustomize_url}" || return 1
    mkdir -p "$_BINDIR" || return 1
    tar -xzf kustomize.tar.gz -C "$_BINDIR" || return 1
    rm -f kustomize.tar.gz
    kustomize="$_BINDIR/kustomize"
    echo "$kustomize"
    return 0
}
