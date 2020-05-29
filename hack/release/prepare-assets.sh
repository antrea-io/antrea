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

# This script generates all the assets required for an Antrea Github release to
# the provided directory.
# Usage: VERSION=v1.0.0 ./prepare-artifacts.sh <output dir>

set -eo pipefail

function echoerr {
    >&2 echo "$@"
    exit 1
}

if [ -z "$VERSION" ]; then
    echoerr "Environment variable VERSION must be set"
fi

if [ -z "$1" ]; then
    echoerr "Argument required: output directory for assets"
fi

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $THIS_DIR/../.. > /dev/null

ANTCTL_BUILDS=(
    "linux amd64 linux-x86_64"
    "linux arm64 linux-arm64"
    "linux arm linux-arm"
    "windows amd64 windows-x86_64.exe"
    "darwin amd64 darwin-x86_64"
)

for build in "${ANTCTL_BUILDS[@]}"; do
    args=($build)
    os="${args[0]}"
    arch="${args[1]}"
    suffix="${args[2]}"

    GOOS=$os GOARCH=$arch ANTCTL_BINARY_NAME="antctl-$suffix" BINDIR=$1/ make antctl-release
done

export IMG_TAG=$VERSION

export IMG_NAME=antrea/antrea-ubuntu
./hack/generate-manifest.sh --mode release > $1/antrea.yml
./hack/generate-manifest.sh --mode release --ipsec > $1/antrea-ipsec.yml
./hack/generate-manifest.sh --mode release --encap-mode networkPolicyOnly > $1/antrea-eks.yml
./hack/generate-manifest.sh --mode release --cloud GKE --encap-mode noEncap > $1/antrea-gke.yml

export IMG_NAME=antrea/octant-antrea-ubuntu
./hack/generate-manifest-octant.sh --mode release > $1/antrea-octant.yml

export IMG_NAME=antrea/antrea-windows
./hack/generate-manifest-windows.sh --mode release > $1/antrea-windows.yml

ls $1 | cat
