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

set -eo pipefail

WORK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
YAMLS_DIR="${WORK_DIR}"/../build/yamls
MANIFESTS=$(ls $YAMLS_DIR/antrea-windows*.yml)
WINDOWS_DIR="${YAMLS_DIR}"/windows
BASE_CONF_FILES="${WINDOWS_DIR}/base/conf/antrea-agent.conf ${WINDOWS_DIR}/base/conf/antrea-cni.conflist"
DEFAULT_CONF_FILES="${WINDOWS_DIR}/default/conf/Run-AntreaAgent.ps1"
CONTAINERD_CONF_FILES="${WINDOWS_DIR}/containerd/conf/Install-WindowsCNI-Containerd.ps1 \
    ${WINDOWS_DIR}/containerd/conf/Run-AntreaAgent-Containerd.ps1"
CONTAINERD_WITH_OVS_CONF_FILES="${WINDOWS_DIR}/containerd-with-ovs/conf/Run-AntreaOVS-Containerd.ps1 \
    ${WINDOWS_DIR}/containerd-with-ovs/conf/VMSwitchExtension-AntreaAgent-Containerd.ps1"

checksum_windows_config=$(cat ${BASE_CONF_FILES} | sha256sum | cut -d " " -f 1)

checksum_default=$(cat ${DEFAULT_CONF_FILES} | sha256sum | cut -d " " -f 1)

checksum_containerd=$( cat ${CONTAINERD_CONF_FILES} | sha256sum | cut -d " " -f 1)

checksum_containerd_with_ovs=$(cat ${CONTAINERD_CONF_FILES} ${CONTAINERD_WITH_OVS_CONF_FILES} | sha256sum | cut -d " " -f 1)

for file in ${MANIFESTS[@]}; do
    sed -i.bak "s/windows-config-checksum-placeholder/${checksum_windows_config}/g" ${file}
done

sed -i.bak "s/agent-windows-checksum-placeholder/${checksum_default}/g" ${YAMLS_DIR}/antrea-windows.yml
sed -i.bak "s/agent-windows-checksum-placeholder/${checksum_containerd}/g" ${YAMLS_DIR}/antrea-windows-containerd.yml
sed -i.bak "s/agent-windows-checksum-placeholder/${checksum_containerd_with_ovs}/g" ${YAMLS_DIR}/antrea-windows-containerd-with-ovs.yml
