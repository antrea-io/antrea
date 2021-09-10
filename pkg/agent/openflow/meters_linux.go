//go:build linux
// +build linux

// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openflow

import (
	"github.com/blang/semver"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/runtime"
)

func ovsMetersAreSupported(ovsDatapathType ovsconfig.OVSDatapathType) bool {
	if ovsDatapathType == ovsconfig.OVSDatapathNetdev {
		return true
	}
	// According to the OVS documentation, meters are supported in the kernel module since 4.15
	// (https://docs.openvswitch.org/en/latest/faq/releases/). However, it turns out that
	// because of a bug meters cannot be used with kernel versions older than 4.18, which is
	// when this patch was merged: https://github.com/torvalds/linux/commit/25432eba9cd.
	// To avoid increasing the minimum required kernel version for Antrea, we will avoid using
	// meters altogether if they are not supported, instead of erroring out.
	minKernelVersion := semver.MustParse("4.18.0") // patch version is required
	kernelVersion, err := runtime.GetKernelVersion()
	if err != nil {
		klog.Warningf("Cannot retrieve Linux kernel version, cannot use OVS meters: %v", err)
		return false
	}
	if kernelVersion.GTE(minKernelVersion) {
		return true
	}
	klog.Infof("Linux kernel version (%s) is less than %s and therefore the OVS kernel datapath does not support meters", kernelVersion, minKernelVersion)
	return false
}
