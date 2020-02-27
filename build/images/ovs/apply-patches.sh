#!/usr/bin/env bash

# Copyright 2020 Antrea Authors
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

# This script applies unreleased patches (or released in a more recent version
# of OVS than the one Antrea is using) to OVS before building it. It needs to be
# run from the root of the OVS source tree.

set -eo pipefail

# We cannot use 3-way merge unless we are in a git repository. If we need 3-way
# merge, we will need to clone the repository with git instead of downloading a
# release tarball (see Dockerfile).

# These 2 patches (post 2.13.0) ensures that datapath flows are not deleted on
# ovs-vswitchd exit by default. Antrea relies on this to support hitless upgrade
# of the Agent DaemonSet.
# The second patch depends on the first one.
curl https://github.com/openvswitch/ovs/commit/586cd3101e7fda54d14fb5bf12d847f35d968627.patch | \
    git apply
# We exclude 2 files which are likely to cause conflicts.
curl https://github.com/openvswitch/ovs/commit/79eadafeb1b47a3871cb792aa972f6e4d89d1a0b.patch | \
    git apply --exclude NEWS --exclude vswitchd/ovs-vswitchd.8.in
