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

function echoerr {
    >&2 echo "$@"
}

_usage="Usage: $0 [--pull] [--push-base-images] [--coverage] [--platform <PLATFORM>]
Build the antrea/antrea-ubuntu image, as well as all the base images in the build chain. This is
typically used in CI to build the image with the latest version of all dependencies, taking into
account changes to all Dockerfiles.
        --pull                  Always attempt to pull a newer version of the base images.
        --push-base-images      Push built images to the registry. Only base images will be pushed.
        --coverage              Build the image with support for code coverage.
        --platform <PLATFORM>   Target platform for the images if server is multi-platform capable."

function print_usage {
    echoerr "$_usage"
}

PULL=false
PUSH=false
COVERAGE=false
PLATFORM=""

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

ARGS=""
PLATFORM_ARG=""
if $PUSH; then
   ARGS="$ARGS --push"
fi
if [ "$PLATFORM" != "" ]; then
    ARGS="$ARGS --platform $PLATFORM"
    PLATFORM_ARG="--platform $PLATFORM"
fi

OVS_VERSION=$(head -n 1 build/images/deps/ovs-version)
CNI_BINARIES_VERSION=$(head -n 1 build/images/deps/cni-binaries-version)

# We pull all images ahead of time, instead of calling the independent build.sh
# scripts with "--pull". We do not want to overwrite the antrea/openvswitch
# image we just built when calling build.sh to build the antrea/base-ubuntu
# image! This is a bit more inconvenient to maintain, but we rarely introduce
# new base images in the build chain.
if $PULL; then
    if [[ ${DOCKER_REGISTRY} == "" ]]; then
        docker pull $PLATFORM_ARG ubuntu:20.04
        docker pull $PLATFORM_ARG golang:1.15
    else
        docker pull ${DOCKER_REGISTRY}/antrea/ubuntu:20.04
        docker tag ${DOCKER_REGISTRY}/antrea/ubuntu:20.04 ubuntu:20.04
        docker pull ${DOCKER_REGISTRY}/antrea/golang:1.15
        docker tag ${DOCKER_REGISTRY}/antrea/golang:1.15 golang:1.15
    fi
    IMAGES_LIST=(
        "antrea/openvswitch-debs:$OVS_VERSION"
        "antrea/openvswitch:$OVS_VERSION"
        "antrea/cni-binaries:$CNI_BINARIES_VERSION"
        "antrea/base-ubuntu:$OVS_VERSION"
    )
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

cd build/images/ovs
./build.sh $ARGS
cd -

cd build/images/base
./build.sh $ARGS
cd -

export NO_PULL=1
if $COVERAGE; then
    make build-ubuntu-coverage
else
    make
fi

popd > /dev/null
