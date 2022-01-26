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

function echoerr {
    >&2 echo "$@"
}

_usage="Usage: $0 [--pull] [--push] [--platform <PLATFORM>] [--distro [ubuntu|ubi]]
Build the antrea/base-ubuntu:<OVS_VERSION> image.
        --pull                  Always attempt to pull a newer version of the base images
        --push                  Push the built image to the registry
        --platform <PLATFORM>   Target platform for the image if server is multi-platform capable
        --distro <distro>       Target Linux distribution"

function print_usage {
    echoerr "$_usage"
}

PULL=false
PUSH=false
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

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $THIS_DIR > /dev/null

OVS_VERSION=$(head -n 1 ../deps/ovs-version)

# This is a bit complicated but we make sure that we only build OVS if
# necessary, and at the moment --cache-from does not play nicely with multistage
# builds: we need to push the intermediate image to the registry. Note that the
# --cache-from option will have no effect if the image doesn't exist
# locally.
# See https://github.com/moby/moby/issues/34715.

if $PULL; then
    if [[ ${DOCKER_REGISTRY} == "" ]]; then
        docker pull $PLATFORM_ARG ubuntu:20.04
    else
        docker pull ${DOCKER_REGISTRY}/antrea/ubuntu:20.04
        docker tag ${DOCKER_REGISTRY}/antrea/ubuntu:20.04 ubuntu:20.04
    fi
    if [ "$DISTRO" == "ubuntu" ]; then
        IMAGES_LIST=(
            "antrea/openvswitch-debs:$OVS_VERSION"
            "antrea/openvswitch:$OVS_VERSION"
        )
    elif [ "$DISTRO" == "ubi" ]; then
        IMAGES_LIST=(
            "antrea/openvswitch-rpms:$OVS_VERSION"
            "antrea/openvswitch-ubi:$OVS_VERSION"
        )
    fi
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

if [ "$DISTRO" == "ubuntu" ]; then
    docker build $PLATFORM_ARG --target ovs-debs \
           --cache-from antrea/openvswitch-debs:$OVS_VERSION \
           -t antrea/openvswitch-debs:$OVS_VERSION \
           --build-arg OVS_VERSION=$OVS_VERSION .

    docker build $PLATFORM_ARG \
           --cache-from antrea/openvswitch-debs:$OVS_VERSION \
           --cache-from antrea/openvswitch:$OVS_VERSION \
           -t antrea/openvswitch:$OVS_VERSION \
           --build-arg OVS_VERSION=$OVS_VERSION .
elif [ "$DISTRO" == "ubi" ]; then
    docker build $PLATFORM_ARG --target ovs-rpms \
           --cache-from antrea/openvswitch-rpms:$OVS_VERSION \
           -t antrea/openvswitch-rpms:$OVS_VERSION \
           --build-arg OVS_VERSION=$OVS_VERSION \
           -f Dockerfile.ubi .

    docker build \
           --cache-from antrea/openvswitch-rpms:$OVS_VERSION \
           --cache-from antrea/openvswitch-ubi:$OVS_VERSION \
           -t antrea/openvswitch-ubi:$OVS_VERSION \
           --build-arg OVS_VERSION=$OVS_VERSION \
           -f Dockerfile.ubi .
fi

if $PUSH; then
    if [ "$DISTRO" == "ubuntu" ]; then
        docker push antrea/openvswitch-debs:$OVS_VERSION
        docker push antrea/openvswitch:$OVS_VERSION
    elif [ "$DISTRO" == "ubi" ]; then
        docker push antrea/openvswitch-rpms:$OVS_VERSION
        docker push antrea/openvswitch-ubi:$OVS_VERSION
    fi
fi

popd > /dev/null
