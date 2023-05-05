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

# This script must be run on a Windows machine and requires a Bash shell to be
# available, e.g., Git Bash (https://gitforwindows.org/).

set -eo pipefail

function echoerr {
    >&2 echo "$@"
}

_usage="Usage: $0 [--pull] [--push-base-images]
Build the antrea/antrea-windows image, as well as all the base images in the build chain. This is
typically used in CI to build the image with the latest version of all dependencies, taking into
account changes to all Dockerfiles.
        --pull                  Always attempt to pull a newer version of the base images.
        --push-base-images      Push built images to the registry. Only base images will be pushed.
This script must run on a Windows machine!"

function print_usage {
    echoerr "$_usage"
}

PULL=false
PUSH=false

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --pull)
    PULL=true
    shift
    ;;
    --push-base-images)
    PUSH=true
    shift
    ;;
    -h|--help)
    print_usage
    exit 0
    ;;
    *)    # unknown option
    echoerr "Unknown option $1"
    exit 1
    ;;
esac
done

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd "$THIS_DIR/.." > /dev/null

NANOSERVER_VERSION=$(head -n 1 build/images/deps/nanoserver-version)
CNI_BINARIES_VERSION=$(head -n 1 build/images/deps/cni-binaries-version)
GO_VERSION=$(head -n 1 build/images/deps/go-version)
WIN_OVS_VERSION=$(head -n 1 build/images/deps/ovs-version-windows)
WIN_BUILD_OVS_TAG=$(echo $NANOSERVER_VERSION-$WIN_OVS_VERSION)
WIN_BUILD_TAG=$(echo $GO_VERSION $CNI_BINARIES_VERSION $NANOSERVER_VERSION| md5sum| head -c 10)

echo "WIN_BUILD_TAG=$WIN_BUILD_TAG"

if $PULL; then
    docker pull mcr.microsoft.com/windows/servercore:$NANOSERVER_VERSION
    docker pull golang:$GO_VERSION-nanoserver
    docker pull mcr.microsoft.com/windows/nanoserver:$NANOSERVER_VERSION
    docker pull mcr.microsoft.com/powershell:lts-nanoserver-$NANOSERVER_VERSION
    docker pull antrea/windows-utility-base:$WIN_BUILD_TAG || true
    docker pull antrea/windows-golang:$WIN_BUILD_TAG || true
    docker pull antrea/base-windows:$WIN_BUILD_TAG || true
    docker pull antrea/windows-ovs:$WIN_BUILD_OVS_TAG || true
fi

cd build/images/base-windows
docker build --target windows-utility-base \
       --cache-from antrea/windows-utility-base:$WIN_BUILD_TAG \
       -t antrea/windows-utility-base:$WIN_BUILD_TAG \
       --build-arg CNI_BINARIES_VERSION=$CNI_BINARIES_VERSION \
       --build-arg NANOSERVER_VERSION=$NANOSERVER_VERSION .
docker build --target windows-golang \
       --cache-from antrea/windows-golang:$WIN_BUILD_TAG \
       -t antrea/windows-golang:$WIN_BUILD_TAG \
       --build-arg CNI_BINARIES_VERSION=$CNI_BINARIES_VERSION \
       --build-arg GO_VERSION=$GO_VERSION \
       --build-arg NANOSERVER_VERSION=$NANOSERVER_VERSION .
docker build \
       --cache-from antrea/windows-utility-base:$WIN_BUILD_TAG \
       --cache-from antrea/windows-golang:$WIN_BUILD_TAG \
       --cache-from antrea/base-windows:$WIN_BUILD_TAG \
       -t antrea/base-windows:$WIN_BUILD_TAG \
       --build-arg CNI_BINARIES_VERSION=$CNI_BINARIES_VERSION \
       --build-arg GO_VERSION=$GO_VERSION \
       --build-arg NANOSERVER_VERSION=$NANOSERVER_VERSION .
cd -

cd build/images/ovs

docker build --target windows-ovs -f Dockerfile.windows \
        -t antrea/windows-ovs:$WIN_BUILD_OVS_TAG \
        --build-arg WIN_OVS_VERSION=$WIN_OVS_VERSION \
        --build-arg NANOSERVER_VERSION=$NANOSERVER_VERSION .
cd -

if $PUSH; then
    docker push antrea/windows-utility-base:$WIN_BUILD_TAG
    docker push antrea/windows-golang:$WIN_BUILD_TAG
    docker push antrea/base-windows:$WIN_BUILD_TAG
    docker push antrea/windows-ovs:$WIN_BUILD_OVS_TAG
fi

export NO_PULL=1

make build-windows

popd > /dev/null
