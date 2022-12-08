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

# build_tag is used to generate the tag for all the base images
# (e.g. antrea/openvswitch) used as part of the build chain to produce the
# Antrea (Linux) images.
function build_tag() {
    local this_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
    local antrea_version=$(head -n 1 $this_dir/../../VERSION | cut -f1,2 -d'.')
    local tag="antrea-${antrea_version}"
    echo "$tag"
}

echo "$(build_tag "$@")"
