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

mkdir -p "$1"
OUTPUT_DIR=$(cd "$1" && pwd)

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

    # cgo is disabled by default when cross-compiling, but enabled by default
    # for native builds. We ensure it is always disabled for portability since
    # these binaries will be distributed as release assets.
    GOOS=$os GOARCH=$arch CGO_ENABLED=0 ANTCTL_BINARY_NAME="antctl-$suffix" BINDIR="$OUTPUT_DIR"/ make antctl-release
    cd ./plugins/octant && GOOS=$os GOARCH=$arch CGO_ENABLED=0 ANTREA_OCTANT_PLUGIN_BINARY_NAME="antrea-octant-plugin-$suffix" \
    BINDIR="$OUTPUT_DIR" make antrea-octant-plugin-release && cd ../..
done

# the windows-bin Makefile target builds antrea-cni and antrea-agent with cgo
# explicitly disabled.
BINDIR="$OUTPUT_DIR" make windows-bin
sed "s/AntreaVersion=\"latest\"/AntreaVersion=\"$VERSION\"/" ./hack/windows/Start.ps1 > "$OUTPUT_DIR"/Start.ps1

export IMG_TAG=$VERSION

export IMG_NAME=projects.registry.vmware.com/antrea/antrea-ubuntu
./hack/generate-manifest.sh --mode release > "$OUTPUT_DIR"/antrea.yml
./hack/generate-manifest.sh --mode release --ipsec > "$OUTPUT_DIR"/antrea-ipsec.yml
./hack/generate-manifest.sh --mode release --cloud EKS --encap-mode networkPolicyOnly > "$OUTPUT_DIR"/antrea-eks.yml
./hack/generate-manifest.sh --mode release --cloud GKE --encap-mode noEncap > "$OUTPUT_DIR"/antrea-gke.yml
./hack/generate-manifest.sh --mode release --cloud AKS --encap-mode networkPolicyOnly > "$OUTPUT_DIR"/antrea-aks.yml
./hack/generate-manifest.sh --mode release --kind > "$OUTPUT_DIR"/antrea-kind.yml

export IMG_NAME=projects.registry.vmware.com/antrea/octant-antrea-ubuntu
./hack/generate-manifest-octant.sh --mode release > "$OUTPUT_DIR"/antrea-octant.yml

export IMG_NAME=projects.registry.vmware.com/antrea/antrea-windows
./hack/generate-manifest-windows.sh --mode release > "$OUTPUT_DIR"/antrea-windows.yml

export IMG_NAME=projects.registry.vmware.com/antrea/flow-aggregator
./hack/generate-manifest-flow-aggregator.sh --mode release > "$OUTPUT_DIR"/flow-aggregator.yml

# Generate multicluster manifests
export IMG_NAME=projects.registry.vmware.com/antrea/antrea-mc-controller
multicluster/hack/generate-manifest.sh -g > "$OUTPUT_DIR"/antrea-multicluster-leader-global.yml
multicluster/hack/generate-manifest.sh -r -l changeme > "$OUTPUT_DIR"/antrea-multicluster-leader-namespaced.yml
multicluster/hack/generate-manifest.sh -r -m > "$OUTPUT_DIR"/antrea-multicluster-member.yml

ls "$OUTPUT_DIR" | cat
