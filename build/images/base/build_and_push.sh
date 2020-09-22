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

function echoerr {
    >&2 echo "$@"
}

if [ -z "$OVS_VERSION" ]; then
    echoerr "The OVS_VERSION env variable must be set to a valid value (e.g. 2.14.0)"
    exit 1
fi

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $THIS_DIR > /dev/null

docker pull ubuntu:20.04

docker pull antrea/openvswitch:$OVS_VERSION

docker build \
       -t antrea/base-ubuntu:$OVS_VERSION \
       -f Dockerfile \
       --build-arg OVS_VERSION=$OVS_VERSION .

docker push antrea/base-ubuntu:$OVS_VERSION

docker pull antrea/openvswitch-ubi:$OVS_VERSION

docker build \
       -t antrea/base-ubi:$OVS_VERSION \
       -f Dockerfile.ubi \
       --build-arg OVS_VERSION=$OVS_VERSION .

popd > /dev/null
