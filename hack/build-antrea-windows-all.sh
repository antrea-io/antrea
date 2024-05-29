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

_usage="Usage: $0 [--pull] [--push] [--push-base-images]
Build the antrea/antrea-windows image, as well as all the base images in the build chain. This is
typically used in CI to build the image with the latest version of all dependencies, taking into
account changes to all Dockerfiles.
        --pull                  Always attempt to pull a newer version of the base images.
        --push                  Push built antrea/antrea-windows image to the registry.
        --push-base-images      Push built images to the registry. Only Windows OVS image will be pushed.

This script is run on a Linux machine."

function print_usage {
    echoerr "$_usage"
}

PULL=false
PUSH_BASE=false
PUSH_AGENT=false

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --pull)
    PULL=true
    shift
    ;;
    --push-base-images)
    PUSH_BASE=true
    shift
    ;;
    --push)
    PUSH_AGENT=true
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

ARGS=""
if $PULL; then
    ARGS="$ARGS --pull"
fi

if $PUSH_BASE; then
   ARGS="$ARGS --push"
fi

cd build/images/ovs
./build.sh --distro windows $ARGS
cd -

if $PUSH_AGENT; then
    make build-and-push-windows
else
    make build-windows
fi

popd > /dev/null
