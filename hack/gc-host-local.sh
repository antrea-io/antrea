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

set -eo pipefail

function echoerr {
    >&2 echo "$@"
}

CLEAN=false
DATA_DIR="/run/antrea/cni/networks/antrea"
LOCK_FILE="${DATA_DIR}/lock"
BACKUP_DIR="${DATA_DIR}/leaked"

_usage="Usage: $0 [--clean]

Clean up leaked IPs from host-local IPAM plugin used by Antrea. The crictl tool and proper permissions are required.

        --clean                  Clean mode. If not set, this script will only print the leaked IPs and won't remove them."

function print_usage {
    echoerr "$_usage"
}

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --clean)
    CLEAN=true
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

LEAKED_IPS=()

function generate_leaked_ips() {
    ALLOCATED_IPS=()
    for IPV4 in `ls ${DATA_DIR}/*.*.*.*`; do
        ALLOCATED_IPS+=(${IPV4})
    done
    for IPV6 in `ls ${DATA_DIR}/*:*:*`; do
        ALLOCATED_IPS+=(${IPV6})
    done
    CONTAINER_IDS=( $(crictl pods -q) )
    for IP in "${ALLOCATED_IPS[@]}"; do
        IP_CONTAINER_ID=`head -1 ${IP}`
        LEAKED=true
        for CONTAINER_ID in "${CONTAINER_IDS[@]}"; do
            if [[ ${IP_CONTAINER_ID} == ${CONTAINER_ID}* ]]; then
                LEAKED=false
                break
            fi
        done
        if [[ ${LEAKED} == true ]]; then
            LEAKED_IPS+=(${IP})
        fi
    done
}

function clean_leaked_ips() {
    echo "====== Cleaning up leaked IPs ======"
    mkdir -p "${BACKUP_DIR}"
    for LEAKED_IP in "${LEAKED_IPS[@]}"; do
        mv "${LEAKED_IP}" "${BACKUP_DIR}/"
    done
    echo "====== All leaked IPs are moved to ${BACKUP_DIR} ======"
}

if [[ ! -d ${DATA_DIR} ]] || [[ ! -f ${LOCK_FILE} ]]; then
    echo "====== host-local IPs do not exist ======"
    exit 0
fi

exec 3<${LOCK_FILE}
flock 3
generate_leaked_ips
if [ ${#LEAKED_IPS[@]} -eq 0 ]; then
    echo "====== No leaked IPs ======"
    exit 0
fi
echo "====== Found leaked IPs ======"
echo ${LEAKED_IPS[*]}
if $CLEAN; then
    clean_leaked_ips
fi
