#!/usr/bin/env bash

# Copyright 2023 Antrea Authors
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

function check_and_cleanup_docker_build_cache() {
    free_space=$(df -h -B 1G / | awk 'NR==2 {print $4}')
    free_space_threshold=40
    if [[ $free_space -lt $free_space_threshold ]]; then
        # If cleaning up unused dangling images doesn't free up sufficient disk space,
        # we will have to reduce the builder cache to 10GB to release enough disk space.
        docker builder prune -af --keep-storage=10gb > /dev/null
        free_space=$(df -h -B 1G / | awk 'NR==2 {print $4}')
        if [[ $free_space -lt $free_space_threshold ]]; then
            # If the first round cleanup doesn't free up sufficient disk space,
            # we will have to clean up all builder cache to release enough disk space.
            docker builder prune -af > /dev/null
        fi
    fi
    docker system df -v
}

function check_and_upgrade_golang() {
    if [ -z "${GOLANG_RELEASE_DIR}" ]; then
        GOLANG_RELEASE_DIR="/var/lib/jenkins/golang-releases"
    fi
    if [ ! -d ${GOLANG_RELEASE_DIR} ]; then
        mkdir -p ${GOLANG_RELEASE_DIR}
    fi
    echo "====== Checking installed Golang version ======"
    antrea_golang_version="go$(grep -E "^go\ " ${WORKSPACE}/go.mod | awk '{print $2}' | cut -d. -f1-2)"

    while read -r i; do
        version=$(echo ${i} | jq .version | tr -d '"')
        if [[ "${version}" =~ "${antrea_golang_version}" ]]; then
            if [ -d "${GOLANG_RELEASE_DIR}/${antrea_golang_version}" ]; then
                current_version=$(${GOLANG_RELEASE_DIR}/${antrea_golang_version}/bin/go version | awk '{print $3}')
                if [[ "${version}" == "${current_version}" ]]; then
                    echo "====== Golang ${version} is installed on the testbed, no need to download ======"
                    switch_golang "${version}"
                    break
                fi
            fi
            echo "====== Installing Golang version "${version}" ======"
            install_golang "${version}"
            switch_golang "${version}"
            break
        fi
    done < <(curl -s "https://go.dev/dl/?mode=json&include=all" | jq -c -r '.[]')
}

function install_golang() {
    golang_version=$1
    echo "====== Downloading Golang ${golang_version} ======"
    curl https://dl.google.com/go/${golang_version}.linux-amd64.tar.gz -o /tmp/${golang_version}.linux-amd64.tar.gz
    rm -rf /tmp/go || true
    tar xf /tmp/${golang_version}.linux-amd64.tar.gz -C /tmp/
    golang_version=$(echo ${golang_version} | cut -d. -f1-2)
    rm -rf ${GOLANG_RELEASE_DIR}/${golang_version} || true
    mv /tmp/go ${GOLANG_RELEASE_DIR}/${golang_version}
}

function switch_golang() {
    golang_version=$1
    golang_version=$(echo ${golang_version} | cut -d. -f1-2)
    rm -rf ${GOLANG_RELEASE_DIR}/go
    echo "====== Switching to Golang ${golang_version} ======"
    ln -s ${GOLANG_RELEASE_DIR}/${golang_version} ${GOLANG_RELEASE_DIR}/go
}
