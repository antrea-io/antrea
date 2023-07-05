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

_SONOBUOY_BINDIR="/tmp/antrea"
_SONOBUOY_TARBALL="/tmp/sonobuoy.tar.gz"
_MIN_SONOBUOY_VERSION="v0.56.16"

install_sonobuoy() {
    local ostype=""
    if [[ "$OSTYPE" == "linux-gnu" ]]; then
        ostype="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        ostype="darwin"
    else
        >&2 echo "Unsupported OS type $OSTYPE"
        return 1
    fi
    local machinetype=$(uname -m)
    local arch=""
    if [[ "$machinetype" == "x86_64" ]]; then
        arch="amd64"
    elif [[ "$machinetype" == "aarch64" ]]; then
        arch="arm64"
    else
        >&2 echo "Unsupported machine type $machinetype"
        return 1
    fi
    >&2 echo "Installing sonobuoy"
    local sonobuoy_url="https://github.com/vmware-tanzu/sonobuoy/releases/download/${_MIN_SONOBUOY_VERSION}/sonobuoy_${_MIN_SONOBUOY_VERSION:1}_${ostype}_${arch}.tar.gz"
    curl -sLo "$_SONOBUOY_TARBALL" "${sonobuoy_url}" || return 1
    mkdir -p "$_SONOBUOY_BINDIR" || return 1
    tar -xzf "$_SONOBUOY_TARBALL" -C "$_SONOBUOY_BINDIR" || return 1
    rm -f "$_SONOBUOY_TARBALL"
    sonobuoy="$_SONOBUOY_BINDIR/sonobuoy"
    chmod +x "$sonobuoy"
    echo "$sonobuoy"
}

# Ensures the sonobuoy tool exists and is a viable version, or installs it.
verify_sonobuoy() {
    # If sonobuoy is not available on the path, get it.
    local sonobuoy="$(PATH=$PATH:$_SONOBUOY_BINDIR command -v sonobuoy)"
    if [ ! -x "$sonobuoy" ]; then
        install_sonobuoy
        return $?
    fi

    # Verify version if sonobuoy was already installed.
    local sonobuoy_version="$($sonobuoy version --short)"
    sonobuoy_version="${sonobuoy_version##*/}"
    if [ "${sonobuoy_version}" == "${_MIN_SONOBUOY_VERSION}" ]; then
        # If version is exact match, stop here.
        echo "$sonobuoy"
        return 0
    fi
    if [[ "${_MIN_SONOBUOY_VERSION}" != $(echo -e "${_MIN_SONOBUOY_VERSION}\n${sonobuoy_version}" | sort -V | head -n1) ]]; then
        >&2 echo "Your version of sonobuoy is not recent enough, installing version ${_MIN_SONOBUOY_VERSION}"
        install_sonobuoy
        return $?
    fi
    echo "$sonobuoy"
}
