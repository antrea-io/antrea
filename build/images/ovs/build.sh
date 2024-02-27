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

# This is a very simple script that builds the Open vSwitch base image for Antrea and pushes it to
# the Antrea Dockerhub (https://hub.docker.com/u/antrea). The image is tagged with the OVS version.

set -eo pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source $THIS_DIR/../build-utils.sh

_usage="Usage: $0 [--pull] [--push] [--platform <PLATFORM>] [--distro [ubuntu|ubi]]
Build the antrea openvswitch image.
        --pull                  Always attempt to pull a newer version of the base images
        --push                  Push the built image to the registry
        --platform <PLATFORM>   Target platform for the image if server is multi-platform capable
        --distro <distro>       Target Linux distribution
        --no-cache              Do not use the local build cache nor the cached image from the registry"

PULL=false
PUSH=false
NO_CACHE=false
PLATFORM=""
DISTRO="ubuntu"

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

if [ "$PLATFORM" != "" ] && $PUSH; then
    echoerr "Cannot use --platform with --push"
    exit 1
fi

PLATFORM_ARG=""
if [ "$PLATFORM" != "" ]; then
    PLATFORM_ARG="--platform $PLATFORM"
fi

if [ "$DISTRO" != "ubuntu" ] && [ "$DISTRO" != "ubi" ]; then
    echoerr "Invalid distribution $DISTRO"
    exit 1
fi

pushd $THIS_DIR > /dev/null

OVS_VERSION=$(head -n 1 ../deps/ovs-version)

BUILD_TAG=$(../build-tag.sh)

if $PULL; then
    if [ "$DISTRO" == "ubuntu" ]; then
        if [[ ${DOCKER_REGISTRY} == "" ]]; then
            docker pull $PLATFORM_ARG ubuntu:22.04
        else
            docker pull ${DOCKER_REGISTRY}/antrea/ubuntu:22.04
            docker tag ${DOCKER_REGISTRY}/antrea/ubuntu:22.04 ubuntu:22.04
        fi
    elif [ "$DISTRO" == "ubi" ]; then
        docker pull $PLATFORM_ARG centos:centos7
        docker pull $PLATFORM_ARG registry.access.redhat.com/ubi8
    fi
fi

function docker_build_and_push() {
    local image="$1"
    local dockerfile="$2"
    local build_args="--build-arg OVS_VERSION=$OVS_VERSION"
    local cache_args=""
    if $PUSH; then
        cache_args="$cache_args --cache-to type=registry,ref=$image-cache:$BUILD_TAG,mode=max"
    fi
    if $NO_CACHE; then
        cache_args="$cache_args --no-cache"
    else
        cache_args="$cache_args --cache-from type=registry,ref=$image-cache:$BUILD_TAG,mode=max"
    fi
    docker buildx build $PLATFORM_ARG -o type=docker -t $image:$BUILD_TAG $cache_args $build_args -f $dockerfile .

    if $PUSH; then
        docker push $image:$BUILD_TAG
    fi
}

if [ "$DISTRO" == "ubuntu" ]; then
    docker_build_and_push "antrea/openvswitch" "Dockerfile"
elif [ "$DISTRO" == "ubi" ]; then
    docker_build_and_push "antrea/openvswitch-ubi" "Dockerfile.ubi"
fi

popd > /dev/null
