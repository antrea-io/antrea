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

_usage="Usage: $0 [--docker-user <dockerUser>] [--docker-password <dockerPassword>]
Run Docker login script.
        --docker-user             Username for Docker account.
        --docker-password         Password for Docker account."

function print_usage {
  echoerr "$_usage"
}

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --docker-user)
    DOCKER_USERNAME="$2"
    shift 2
    ;;
    --docker-password)
    DOCKER_PASSWORD="$2"
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

function docker_login() {
    for i in `seq 5`; do
        output=$(echo $2 | docker login --username=$1 --password-stdin 2>&1)
        # Check if the exit code is 0
        if [[ $? -eq 0 ]]; then
            echo "Docker login successful."
            return 0
        else
            echo "Docker login failed, retrying in 5s"
            echo "Error output: $output"
            sleep 5
        fi
    done

    # Exit with a non-zero code if it never succeeds
    echo "Docker login failed after multiple attempts."
    return 1
}

# Never trace, to avoid logging password.
# Dont exit on error, docker_login handles errors directly.
set +ex

# Exit if credentials are not set
if [[ -z "$DOCKER_USERNAME" || -z "$DOCKER_PASSWORD" ]]; then
    echoerr "Docker username or password not provided."
    exit 1
fi

docker_login "${DOCKER_USERNAME}" "${DOCKER_PASSWORD}"
