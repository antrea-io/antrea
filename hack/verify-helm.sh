#!/usr/bin/env bash

# Copyright 2022 Antrea Authors
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
_HELM_VERSION="v3.8.1"

# Ensure the helm tool exists and is the correct version, or install it
verify_helm() {
    # Check if there is already a helm binary in $_BINDIR and if yes, check if
    # the version matches the expected one.
    local helm="$(PATH=$_BINDIR command -v helm)"
    if [ -x "$helm" ]; then
        # Verify version if helm was already installed.
        local helm_version="$($helm version --short 2> >(grep -v 'This is insecure' >&2))"
        # Should work with:
        #  - v3.8.1
        #  - v3.8.1+g5cb9af4
        helm_version="${helm_version%+*}"
        if [ "${helm_version}" == "${_HELM_VERSION}" ]; then
            # If version is exact match, stop here.
            echo "$helm"
            return 0
        fi
        >&2 echo "Detected helm version ($helm_version) does not match expected one ($_HELM_VERSION), installing correct version"
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
    rc=0
    local unameArch="$(uname -m)" || rc=$?
    if [ $rc -ne 0 ]; then
        >&2 echo "Cannot detect architecture type, uname not available?"
        return 1
    fi
    local arch=""
    case "$unameArch" in
        x86_64) arch="amd64";;
        arm64) arch="arm64";;
        *) >&2 echo "Unsupported architecture type $unameArch"; return 1;;
    esac
    
    >&2 echo "Installing helm"
    local helm_url="https://get.helm.sh/helm-${_HELM_VERSION}-${ostype}-${arch}.tar.gz"
    curl -sLo helm.tar.gz "${helm_url}" || return 1
    mkdir -p "$_BINDIR" || return 1
    tar -xzf helm.tar.gz -C "$_BINDIR" --strip-components=1 "${ostype}-${arch}/helm" || return 1
    rm -f helm.tar.gz
    helm="$_BINDIR/helm"
    echo "$helm"
    return 0
}
