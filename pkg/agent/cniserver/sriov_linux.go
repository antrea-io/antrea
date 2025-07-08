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

package cniserver

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Mellanox/sriovnet"
)

var (
	// SysBusPCI is the /sysfs PCI device directory
	SysBusPCI = "/sys/bus/pci/devices"
)

// getVFLinkName returns a VF's network interface name given its PCI address.
func (ic *ifConfigurator) getVFLinkName(pciAddress string) (string, error) {
	return ic.sriovnet.GetVFLinkNames(pciAddress)
}

type sriovNet struct{}

func (n *sriovNet) GetNetDevicesFromPCI(pciAddress string) ([]string, error) {
	return sriovnet.GetNetDevicesFromPci(pciAddress)
}

func (n *sriovNet) GetUplinkRepresentor(pciAddress string) (string, error) {
	return sriovnet.GetUplinkRepresentor(pciAddress)
}

func (n *sriovNet) GetVFIndexByPCIAddress(vfPCIAddress string) (int, error) {
	return sriovnet.GetVfIndexByPciAddress(vfPCIAddress)
}

func (n *sriovNet) GetVFRepresentor(uplink string, vfIndex int) (string, error) {
	return sriovnet.GetVfRepresentor(uplink, vfIndex)
}

func (n *sriovNet) GetVFLinkNames(pciAddr string) (string, error) {
	return GetVFLinkName(pciAddr)
}

func newSriovNet() *sriovNet {
	return &sriovNet{}
}

// Note: The following fuction is coming from https://github.com/k8snetworkplumbingwg/sriov-cni/blob/master/pkg/utils/utils.go
// The permanent link is https://github.com/k8snetworkplumbingwg/sriov-cni/blob/3d9014b16bd22ed3381f41cd6ad097b8b741cab2/pkg/utils/utils.go#L186-L211
// We can't directly import the package in go.mod due to the sriov-cni repo has no v2 module yet. it reports:
// "require github.com/k8snetworkplumbingwg/sriov-cni: version “v2.9.0” invalid: should be v0 or v1, not v2.""

// GetVFLinkName returns VF's network interface name given it's PCI addr
func GetVFLinkName(pciAddr string) (string, error) {
	var names []string
	vfDir := filepath.Join(SysBusPCI, pciAddr, "net")
	if _, err := os.Lstat(vfDir); err != nil {
		return "", err
	}

	fInfos, err := os.ReadDir(vfDir)
	if err != nil {
		return "", fmt.Errorf("failed to read net dir of the device %s: %v", pciAddr, err)
	}

	if len(fInfos) == 0 {
		return "", fmt.Errorf("VF device %s sysfs path (%s) has no entries", pciAddr, vfDir)
	}

	names = make([]string, len(fInfos))
	for idx, f := range fInfos {
		names[idx] = f.Name()
	}

	if len(names) < 1 {
		return "", fmt.Errorf("VF device %s has no entries", pciAddr)
	}
	return names[0], nil
}
