#!/usr/bin/env bash

# Copyright 2024 Antrea Authors
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

source $THIS_DIR/build-utils.sh

_usage="Usage: $0 [--pull] [--push] [--agent-tag]
Build the antrea base image.
        --pull                 Always attempt to pull a newer version of Window OVS image.
        --push                 Push the built image to the registry
        --agent-tag            Antrea Agent image tag"

PULL_OPTION=""
PUSH=false
BUILD_TAG="latest"

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --pull)
    PULL_OPTION="--pull"
    shift
    ;;
    --push)
    PUSH=true
    shift
    ;;
    --agent-tag)
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

pushd $THIS_DIR > /dev/null

BUILD_ARGS=""
docker_file=""
CNI_BINARIES_VERSION=$(head -n 1 deps/cni-binaries-version)
GO_VERSION=$(head -n 1 deps/go-version)
OVS_VERSION=$(head -n 1 deps/ovs-version-windows)

registry="antrea"
image_name="antrea-windows"
image="${registry}/${image_name}"
BUILD_ARGS="--build-arg GO_VERSION=${GO_VERSION} --build-arg OVS_VERSION=${OVS_VERSION} --build-arg CNI_BINARIES_VERSION=${CNI_BINARIES_VERSION}"

ANTREA_DIR=${THIS_DIR}/../../
pushd $ANTREA_DIR > /dev/null
docker_file="build/images/Dockerfile.build.windows"
docker_build_and_push_windows "${image}" "${docker_file}" "${BUILD_ARGS}" "${BUILD_TAG}" $PUSH "${PULL_OPTION}"
popd > /dev/null

popd > /dev/null
