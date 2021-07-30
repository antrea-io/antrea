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

function echoerr {
    >&2 echo "$@"
}

# Inspired from https://stackoverflow.com/a/24067243/4538702
# 'sort -V' is available on Ubuntu 20.04
# less than
function version_lt() { test "$(printf '%s\n' "$@" | sort -rV | head -n 1)" != "$1"; }
# greater than
function version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }
# less than or equal to
function version_let() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" == "$1"; }
# greater than or equal to
function version_get() { test "$(printf '%s\n' "$@" | sort -rV | head -n 1)" == "$1"; }

if version_lt "$OVS_VERSION" "2.13.0" || version_gt "$OVS_VERSION" "2.15.1"; then
    echoerr "OVS_VERSION $OVS_VERSION is not supported (must be >= 2.13.0 and <= 2.15.1)"
    exit 1
fi

# We cannot use 3-way merge unless we are in a git repository. If we need 3-way
# merge, we will need to clone the repository with git instead of downloading a
# release tarball (see Dockerfile).

# This patch (post 2.13.0) ensures that ct_nw_src/ct_nw_dst supports IP Mask.
if version_let "$OVS_VERSION" "2.13.0"; then
    curl https://github.com/openvswitch/ovs/commit/1740aaf49dad6f533705dc3dce8d955a1840052a.patch | \
        git apply
fi

if version_get "$OVS_VERSION" "2.13.0" && version_lt "$OVS_VERSION" "2.14.0" ; then
    # These 2 patches (post 2.13.x) ensures that datapath flows are not deleted on
    # ovs-vswitchd exit by default. Antrea relies on this to support hitless upgrade
    # of the Agent DaemonSet.
    # The second patch depends on the first one.
    curl https://github.com/openvswitch/ovs/commit/586cd3101e7fda54d14fb5bf12d847f35d968627.patch | \
        git apply
    # We exclude 2 files which are likely to cause conflicts.
    curl https://github.com/openvswitch/ovs/commit/79eadafeb1b47a3871cb792aa972f6e4d89d1a0b.patch | \
        git apply --exclude NEWS --exclude vswitchd/ovs-vswitchd.8.in

    # This patch (post 2.13.x) ensures that ovs-vswitchd does not delete datapath
    # ports on exit.
    curl https://github.com/openvswitch/ovs/commit/7cc77b301f80a63cd4893198d82be0eef303f731.patch | \
        git apply

    # These patches (post 2.13.x) are needed to fix the debian build on Ubuntu 20.04.
    curl https://github.com/openvswitch/ovs/commit/c101cd4171cfe04e214f858b4bbe089e56f13f9b.patch | \
        git apply
    curl https://github.com/openvswitch/ovs/commit/3c18bb0fe9f23308061217f72e2245f0e311b20b.patch | \
        git apply
    curl https://github.com/openvswitch/ovs/commit/fe175ac17352ceb2dbc9958112b4b1bc114d82f0.patch | \
        git apply

    # The OVS ovs-monitor-ipsec script has a Python3 shebang but still includes some Python2-specific code.
    # Until the patch which fixes the script is merged upstream, we apply it here, or Antrea IPsec support will be broken.
    curl https://github.com/openvswitch/ovs/commit/8a09c2590ef2ea0edc250ec46e3d41bd5874b4ab.patch | \
        git apply
fi

# Starting from version 5.7.0, strongSwan no longer supports specifying a configuration parameter
# with the path delimited by dots in a configuration file. This patch fixes the strongSwan
# configuration parameters that ovs-monitor-ipsec writes, to comply with the new strongSwan format.
if version_lt "$OVS_VERSION" "2.14.1" ; then
    curl https://github.com/openvswitch/ovs/commit/b424becaac58d8cb08fb19ea839be6807d3ed57f.patch | \
        git apply
fi

# OVS hardcodes the installation path to /usr/lib/python3.7/dist-packages/ but this location
# does not seem to be in the Python path in Ubuntu 20.04. There may be a better way to do this,
# but this seems like an acceptable workaround.
sed -i 's/python3\.7/python3\.8/' debian/openvswitch-test.install
sed -i 's/python3\.7/python3\.8/' debian/python3-openvswitch.install
