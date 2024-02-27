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

function echoerr {
    >&2 echo "$@"
}

function print_usage {
    echoerr "$_usage"
}

function check_for_buildx() {
    local rc=0
    docker buildx inspect > /dev/null 2>&1 || rc=1
    return $rc
}

function get_docker_build_driver() {
    local driver=$(docker buildx inspect | grep "^Driver:" | awk '{print $2}')
    echo "$driver"
}

function check_docker_build_driver() {
    local expected="$1"
    local actual="$(get_docker_build_driver)"
    if [ "$actual" != "$expected" ]; then
       return 1
    fi
    return 0
}
