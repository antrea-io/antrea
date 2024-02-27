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

set -eo pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source $THIS_DIR/../build/images/build-utils.sh

_usage="Usage: $0 [--pull] [--push-base-images] [--coverage] [--platform <PLATFORM>] [--distro [ubuntu|ubi]]
Build the antrea image, as well as all the base images in the build chain. This is typically used in
CI to build the image with the latest version of all dependencies, taking into account changes to
all Dockerfiles.
        --pull                  Always attempt to pull a newer version of the base images.
        --push-base-images      Push built images to the registry. Only base images will be pushed.
        --coverage              Build the image with support for code coverage.
        --platform <PLATFORM>   Target platform for the images if server is multi-platform capable.
        --distro <distro>       Target Linux distribution.
        --no-cache              Do not use the local build cache nor the cached image from the registry."

PULL=false
PUSH=false
NO_CACHE=false
COVERAGE=false
PLATFORM=""
DISTRO="ubuntu"

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
    --coverage)
    COVERAGE=true
    shift
    ;;
    --platform)
    PLATFORM="$2"
    shift 2
    ;;
    --distro)
    DISTRO="$2"
    shift 2
    ;;
    --no-cache)
    NO_CACHE=true
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

# To support Docker versions where buildx is not the default build client (i.e.,
# versions prior to Docker Engine 23.0 and Docker Desktop 4.19).
export DOCKER_CLI_EXPERIMENTAL=enabled

if ! check_for_buildx; then
    echoerr "Buildx is required to execute this script"
    exit 1
fi

pushd "$THIS_DIR/.." > /dev/null

ARGS=""
PLATFORM_ARG=""
if $PUSH; then
   ARGS="$ARGS --push"
fi
if $NO_CACHE; then
    ARGS="$ARGS --no-cache"
fi
if [ "$PLATFORM" != "" ]; then
    ARGS="$ARGS --platform $PLATFORM"
    PLATFORM_ARG="--platform $PLATFORM"
fi
if [ "$DISTRO" != "ubuntu" ] && [ "$DISTRO" != "ubi" ]; then
    echoerr "Invalid distribution $DISTRO"
    exit 1
fi
if [ "$DISTRO" == "ubi" ]; then
    if $COVERAGE ; then
        echoerr "No coverage build for UBI8"
        exit 1
    fi
    ARGS="$ARGS --distro ubi"
fi

CNI_BINARIES_VERSION=$(head -n 1 build/images/deps/cni-binaries-version)
GO_VERSION=$(head -n 1 build/images/deps/go-version)

BUILD_TAG=$(build/images/build-tag.sh)
echo "BUILD_TAG: $BUILD_TAG"

# We pull all images ahead of time, instead of calling the independent build.sh
# scripts with "--pull". We do not want to overwrite the antrea/openvswitch
# image we just built when calling build.sh to build the antrea/base-ubuntu
# image!
if $PULL; then
    if [[ ${DOCKER_REGISTRY} == "" ]]; then
        docker pull $PLATFORM_ARG ubuntu:22.04
        docker pull $PLATFORM_ARG golang:$GO_VERSION
    else
        docker pull ${DOCKER_REGISTRY}/antrea/ubuntu:22.04
        docker tag ${DOCKER_REGISTRY}/antrea/ubuntu:22.04 ubuntu:22.04
        docker pull ${DOCKER_REGISTRY}/antrea/golang:$GO_VERSION
        docker tag ${DOCKER_REGISTRY}/antrea/golang:$GO_VERSION golang:$GO_VERSION
    fi
    if [ "$DISTRO" == "ubi" ]; then
        docker pull $PLATFORM_ARG centos:centos7
        docker pull $PLATFORM_ARG registry.access.redhat.com/ubi8
    fi
fi

cd build/images/ovs
./build.sh $ARGS
cd -

cd build/images/base
./build.sh $ARGS
cd -

if $NO_CACHE; then
    export NO_CACHE=1
fi
export NO_PULL=1
# To support Docker versions where buildx is not the default build client (i.e.,
# versions prior to Docker Engine 23.0 and Docker Desktop 4.19).
# This can be removed when the Makefile is updated to use "docker buildx"
# explicitly (note that we already set DOCKER_CLI_EXPERIMENTAL=enabled at the
# beginning of the script).
export DOCKER_BUILDKIT=1
if [ "$DISTRO" == "ubuntu" ]; then
    if $COVERAGE; then
        make build-controller-ubuntu-coverage
        make build-agent-ubuntu-coverage
        make build-ubuntu-coverage
    else
        make build-controller-ubuntu
        make build-agent-ubuntu
        make build-ubuntu
    fi
elif [ "$DISTRO" == "ubi" ]; then
    make build-controller-ubi
    make build-agent-ubi
    make build-ubi
fi

popd > /dev/null
