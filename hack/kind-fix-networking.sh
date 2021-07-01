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

# This script is required for Antrea to work properly in a Kind cluster on Linux. It takes care of
# disabling TX hardware checksum offload for the veth interface (in the host's network namespace) of
# each Kind Node. This is required when using OVS in userspace mode. Refer to
# https://github.com/antrea-io/antrea/issues/14 for more information.

# The script uses the antrea/ethtool Docker image (so that ethtool does not need to be installed on
# the Linux host).

set -eo pipefail

for node in "$@"; do
    peerIdx=$(docker exec "$node" ip link | grep eth0 | awk -F[@:] '{ print $3 }' | cut -c 3-)
    peerName=$(docker run --net=host antrea/ethtool:latest ip link | grep ^"$peerIdx": | awk -F[:@] '{ print $2 }' | cut -c 2-)
    echo "Disabling TX checksum offload for node $node ($peerName)"
    docker run --net=host --privileged antrea/ethtool:latest ethtool -K "$peerName" tx off
done
