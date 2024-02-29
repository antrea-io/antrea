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
# Usage: VERSION=v1.0.0 ./prepare-assets.sh <output dir>
# In addition to the VERSION environment variable (which is required), the
# PRERELEASE environment variable can also be set to true or false (it will
# default to false).

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

: "${PRERELEASE:=false}"
if [ "$PRERELEASE" != "true" ] && [ "$PRERELEASE" != "false" ]; then
    echoerr "Environment variable PRERELEASE should only be set to 'true' or 'false'"
fi
export PRERELEASE

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $THIS_DIR/../.. > /dev/null

mkdir -p "$1"
OUTPUT_DIR=$(cd "$1" && pwd)

# Cgo should always be disabled for release assets.
export CGO_ENABLED=0

ANTREA_BUILDS=(
    "linux amd64 linux-x86_64"
    "linux arm64 linux-arm64"
    "linux arm linux-arm"
    "windows amd64 windows-x86_64.exe"
    "darwin amd64 darwin-x86_64"
)

for build in "${ANTREA_BUILDS[@]}"; do
    args=($build)
    os="${args[0]}"
    arch="${args[1]}"
    suffix="${args[2]}"

    GOOS=$os GOARCH=$arch ANTCTL_BINARY_NAME="antctl-$suffix" BINDIR="$OUTPUT_DIR" make antctl-release
done

ANTREA_AGENT_BUILDS=(
    "linux amd64 linux-x86_64"
    "linux arm64 linux-arm64"
    "linux arm linux-arm"
    "windows amd64 windows-x86_64.exe"
)

for build in "${ANTREA_AGENT_BUILDS[@]}"; do
    args=($build)
    os="${args[0]}"
    arch="${args[1]}"
    suffix="${args[2]}"

    GOOS=$os GOARCH=$arch BINDIR="$OUTPUT_DIR" ANTREA_AGENT_BINARY_NAME="antrea-agent-$suffix" make antrea-agent-release
done

ANTREA_CNI_BUILDS=(
    "windows amd64 windows-x86_64.exe"
)

for build in "${ANTREA_CNI_BUILDS[@]}"; do
    args=($build)
    os="${args[0]}"
    arch="${args[1]}"
    suffix="${args[2]}"

    GOOS=$os GOARCH=$arch BINDIR="$OUTPUT_DIR" ANTREA_CNI_BINARY_NAME="antrea-cni-$suffix" make antrea-cni-release
done

sed "s/AntreaVersion=\"latest\"/AntreaVersion=\"$VERSION\"/" ./hack/windows/Start-AntreaAgent.ps1 > "$OUTPUT_DIR"/Start-AntreaAgent.ps1

cp ./hack/externalnode/install-vm.sh "$OUTPUT_DIR/"
cp ./hack/externalnode/install-vm.ps1 "$OUTPUT_DIR/"

export IMG_TAG=$VERSION

export AGENT_IMG_NAME=antrea/antrea-agent-ubuntu
export CONTROLLER_IMG_NAME=antrea/antrea-controller-ubuntu
./hack/generate-standard-manifests.sh --mode release --out "$OUTPUT_DIR"

export IMG_NAME=antrea/antrea-windows
./hack/generate-manifest-windows.sh --mode release > "$OUTPUT_DIR"/antrea-windows.yml
./hack/generate-manifest-windows.sh --mode release --containerd > "$OUTPUT_DIR"/antrea-windows-containerd.yml
./hack/generate-manifest-windows.sh --mode release --containerd --include-ovs > "$OUTPUT_DIR"/antrea-windows-containerd-with-ovs.yml

export IMG_NAME=antrea/flow-aggregator
./hack/generate-manifest-flow-aggregator.sh --mode release > "$OUTPUT_DIR"/flow-aggregator.yml

# Generate multicluster manifests
export IMG_NAME=antrea/antrea-mc-controller
cd multicluster
./hack/generate-manifest.sh -g > "$OUTPUT_DIR"/antrea-multicluster-leader-global.yml
./hack/generate-manifest.sh -r -n antrea-multicluster > "$OUTPUT_DIR"/antrea-multicluster-leader-namespaced.yml
./hack/generate-manifest.sh -r -l antrea-multicluster > "$OUTPUT_DIR"/antrea-multicluster-leader.yml
./hack/generate-manifest.sh -r -m > "$OUTPUT_DIR"/antrea-multicluster-member.yml
cd -

# Package the Antrea chart
# We need to strip the leading "v" from the version string to ensure that we use
# a valid SemVer 2 version.
VERSION=${VERSION:1} ./hack/generate-helm-release.sh --out "$OUTPUT_DIR"

ls "$OUTPUT_DIR" | cat
