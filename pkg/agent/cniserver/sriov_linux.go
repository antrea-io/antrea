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
	"github.com/Mellanox/sriovnet"
	sriovcniutils "github.com/k8snetworkplumbingwg/sriov-cni/pkg/utils"
)

// getVFLinkName returns a VF's network interface name given its PCI address.
func (ic *ifConfigurator) getVFLinkName(pciAddress string) (string, error) {
	return ic.sriovnet.GetVFLinkNames(pciAddress)
}

type sriovNet struct{}

func (n *sriovNet) GetNetDevicesFromPci(pciAddress string) ([]string, error) {
	return sriovnet.GetNetDevicesFromPci(pciAddress)
}

func (n *sriovNet) GetUplinkRepresentor(pciAddress string) (string, error) {
	return sriovnet.GetUplinkRepresentor(pciAddress)
}

func (n *sriovNet) GetVfIndexByPciAddress(vfPciAddress string) (int, error) {
	return sriovnet.GetVfIndexByPciAddress(vfPciAddress)
}

func (n *sriovNet) GetVfRepresentor(uplink string, vfIndex int) (string, error) {
	return sriovnet.GetVfRepresentor(uplink, vfIndex)
}

func (n *sriovNet) GetVFLinkNames(pciAddr string) (string, error) {
	return sriovcniutils.GetVFLinkNames(pciAddr)
}

func newSriovNet() *sriovNet {
	return &sriovNet{}
}
