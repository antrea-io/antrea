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

# This script makes sure that the checked-in manifest YAML is up-to-date.

set -eo pipefail

function echoerr {
    >&2 echo "$@"
}

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd $THIS_DIR/.. > /dev/null

YAMLS=(
    "build/yamls/antrea.yml"
    "build/yamls/antrea-ipsec.yml"
    "build/yamls/antrea-eks.yml"
    "build/yamls/antrea-gke.yml"
    "build/yamls/antrea-aks.yml"
    "build/yamls/antrea-octant.yml"
    "build/yamls/antrea-windows.yml"
    "build/yamls/flow-aggregator.yml"
)

rm "${YAMLS[@]}"
make manifest
diff="$(git status --porcelain ${YAMLS[@]})"

if [ ! -z "$diff" ]; then
    echoerr "The generated manifest YAMLs are not up-to-date"
    echoerr "You can regenerate them with 'make manifest' and commit the changes"
    exit 1
fi
