#!/usr/bin/env bash

# Copyright 2026 Antrea Authors
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

function docker_get_ip {
    local cid="${1}"
    local network="${2}"
    local property="${3:-IPAddress}"
    local ip=$(docker inspect "$cid" -f "{{(index .NetworkSettings.Networks \"$network\").$property}}")
    if [[ "$ip" == "invalid IP" ]]; then
        ip=""
    fi
    echo "$ip"
}

function docker_get_ipv4 {
    docker_get_ip "$@" "IPAddress"
}

function docker_get_ipv6 {
    docker_get_ip "$@" "GlobalIPv6Address"
}

function docker_get_ips {
    local ipv4=$(docker_get_ip "$@" "IPAddress")
    local ipv6=$(docker_get_ip "$@" "GlobalIPv6Address")
    echo "$ipv4,$ipv6"
}

function docker_get_ipv6_prefix_len {
    local cid="${1}"
    local network="${2}"
    local prefix_len=$(docker inspect "$cid" -f "{{(index .NetworkSettings.Networks \"$network\").GlobalIPv6PrefixLen}}")
    echo "$prefix_len"
}
