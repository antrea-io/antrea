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

# This is a very simple script that builds the base image for Antrea and pushes it to
# the Antrea Dockerhub (https://hub.docker.com/u/antrea). The image is tagged with the OVS version.

set -eo pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source $THIS_DIR/../build-utils.sh

_usage="Usage: $0 [--pull] [--push] [--platform <PLATFORM>] [--distro [ubuntu|ubi]]
Build the antrea base image.
        --pull                  Always attempt to pull a newer version of the base images
        --push                  Push the built image to the registry
        --platform <PLATFORM>   Target platform for the image if server is multi-platform capable
        --distro <distro>       Target Linux distribution
        --no-cache              Do not use the local build cache nor the cached image from the registry
        --build-tag             Custom build tag for images."

function print_usage {
    echoerr "$_usage"
}

PULL=false
PUSH=false
NO_CACHE=false
PLATFORM=""
DISTRO="ubuntu"
BUILD_TAG=""

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --push)
    PUSH=true
    shift
    ;;
    --pull)
    PULL=true
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
    --build-tag)
    BUILD_TAG="$2"
    shift 2
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

# When --push is provided, we assume that we want to use --cache-to, which will
# push the "cache image" to the registry. This functionality is not supported
# with the default docker driver.
# See https://docs.docker.com/build/cache/backends/registry/
if $PUSH && ! check_docker_build_driver "docker-container"; then
    echoerr "--push requires the docker-container build driver"
    exit 1
fi

TARGETARCH=$(set -e; get_target_arch "$PLATFORM" "$THIS_DIR/../.targetarch")
echo "Target arch: $TARGETARCH"

PLATFORM_ARG=""
if [ "$PLATFORM" != "" ]; then
    PLATFORM_ARG="--platform $PLATFORM"
fi

if [ "$DISTRO" != "ubuntu" ] && [ "$DISTRO" != "ubi" ]; then
    echoerr "Invalid distribution $DISTRO"
    exit 1
fi

pushd $THIS_DIR > /dev/null

CNI_BINARIES_VERSION=$(head -n 1 ../deps/cni-binaries-version)
SURICATA_VERSION=$(head -n 1 ../deps/suricata-version)

BUILD_CACHE_TAG=$(../build-tag.sh)

if [[ $BUILD_TAG == "" ]]; then
    BUILD_TAG=$BUILD_CACHE_TAG
fi

ANTREA_OPENVSWITCH_IMAGE=""
if [ "$DISTRO" == "ubuntu" ]; then
    ANTREA_OPENVSWITCH_IMAGE="antrea/openvswitch-$TARGETARCH:$BUILD_TAG"
elif [ "$DISTRO" == "ubi" ]; then
    ANTREA_OPENVSWITCH_IMAGE="antrea/openvswitch-ubi-$TARGETARCH:$BUILD_TAG"
fi

if $PULL; then
    # The ubuntu image is also used for the UBI build (for the cni-binaries intermediate image).
    if [[ ${DOCKER_REGISTRY} == "" ]]; then
        docker pull $PLATFORM_ARG ubuntu:24.04
    else
        docker pull $PLATFORM_ARG ${DOCKER_REGISTRY}/antrea/ubuntu:24.04
        docker tag ${DOCKER_REGISTRY}/antrea/ubuntu:24.04 ubuntu:24.04
    fi

    IMAGES_LIST=("$ANTREA_OPENVSWITCH_IMAGE")
    for image in "${IMAGES_LIST[@]}"; do
        if [[ ${DOCKER_REGISTRY} == "" ]]; then
            docker pull $PLATFORM_ARG "${image}" || true
        else
            rc=0
            docker pull "${DOCKER_REGISTRY}/${image}" || rc=$?
            if [[ $rc -eq 0 ]]; then
                docker tag "${DOCKER_REGISTRY}/${image}" "${image}"
            fi
        fi
    done
fi

function docker_build_and_push() {
    local image="$1"
    local dockerfile="$2"
    local build_args="--build-arg CNI_BINARIES_VERSION=$CNI_BINARIES_VERSION --build-arg SURICATA_VERSION=$SURICATA_VERSION"
    local build_context="--build-context antrea-openvswitch=docker-image://$ANTREA_OPENVSWITCH_IMAGE"
    local cache_args=""
    if [[ ${DOCKER_REGISTRY} != "" ]]; then
        build_context+=" --build-context ubuntu-lts=docker-image://$DOCKER_REGISTRY/ubuntu:24.04"
    else
        build_context+=" --build-context ubuntu-lts=docker-image://ubuntu:24.04"
    fi
    if $PUSH; then
        cache_args="$cache_args --cache-to type=registry,ref=$image-cache:$BUILD_CACHE_TAG,mode=max"
    fi
    if $NO_CACHE; then
        cache_args="$cache_args --no-cache"
    else
        cache_args="$cache_args --cache-from type=registry,ref=$image-cache:$BUILD_CACHE_TAG,mode=max"
    fi
    docker buildx build $PLATFORM_ARG -o type=docker -t $image:$BUILD_TAG $cache_args $build_args $build_context -f $dockerfile .

    if $PUSH; then
        docker push $image:$BUILD_TAG
    fi
}


if [ "$DISTRO" == "ubuntu" ]; then
    docker_build_and_push "antrea/base-ubuntu-$TARGETARCH" Dockerfile
elif [ "$DISTRO" == "ubi" ]; then
    docker_build_and_push "antrea/base-ubi-$TARGETARCH" Dockerfile.ubi
fi

popd > /dev/null
