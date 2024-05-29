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

function switch_windows_buildx() {
    local windows_buildx_name="windows-img-builder"
    original_buildx_instance=$(docker buildx inspect | grep '^Name:' | awk '{print $2}' | head -n 1)
    if [ "$original_buildx_instance" = "${windows_buildx_name}" ]; then
        return
    fi
    trap 'docker buildx use --default ${original_buildx_instance}' EXIT
    set +e
    docker buildx ls | grep "${windows_buildx_name}" > /dev/null 2>&1
    if [ $? -eq 0 ] ; then
        docker buildx use --builder windows/amd64 "${windows_buildx_name}"
    else
        docker buildx create --name "${windows_buildx_name}" --use --platform windows/amd64
    fi
    set -e
}

function docker_build_and_push_windows() {
    local image="$1"
    local dockerfile="$2"
    local build_args="$3"
    local build_tag="$4"
    local push=$5
    local pull_option="$6"

    switch_windows_buildx
    if $push; then
        output="type=registry"
    else
        local_file=$(echo "${image}" | awk -F'/' '{print $NF}')
        output="type=docker,dest=./${local_file}.tar"
    fi

    docker buildx build --platform windows/amd64 -o ${output} -t ${image}:${build_tag} ${pull_option} ${build_args} -f $dockerfile .
}
