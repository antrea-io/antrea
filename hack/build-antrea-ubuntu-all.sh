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

# Change this when updating the OVS version!
: "${OVS_VERSION:=2.14.0}"
export OVS_VERSION

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

if [ -z "$OVS_VERSION" ]; then
    echoerr "The OVS_VERSION env variable must be set to a valid value (e.g. 2.14.0)"
    exit 1
fi

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd "$THIS_DIR/.." > /dev/null

ARGS=""
if $PUSH; then
   ARGS="$ARGS --push"
fi
if $PULL; then
   ARGS="$ARGS --pull"
fi
if [ "$PLATFORM" != "" ]; then
    ARGS="$ARGS --platform $PLATFORM"
fi

cd build/images/ovs
./build.sh $ARGS
cd -

cd build/images/base
./build.sh $ARGS
cd -

# This hack ensures that the Makefile will not be pulling dependencies.
export DOCKER_REGISTRY=1
if $COVERAGE; then
    make build-ubuntu-coverage
else
    make
fi

popd > /dev/null
