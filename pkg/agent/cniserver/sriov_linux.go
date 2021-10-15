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
	sriovcniutils "github.com/k8snetworkplumbingwg/sriov-cni/pkg/utils"
)

// getVFInfo takes in a VF's PCI device ID and returns its PF and VF ID.
func getVFInfo(vfPCI string) (string, int, error) {
	var vfID int

	pf, err := sriovcniutils.GetPfName(vfPCI)
	if err != nil {
		return "", vfID, err
	}

	vfID, err = sriovcniutils.GetVfid(vfPCI, pf)
	if err != nil {
		return "", vfID, err
	}

	return pf, vfID, nil
}

// getVFLinkName returns a VF's network interface name given its PCI address.
func getVFLinkName(pciAddress string) (string, error) {
	return sriovcniutils.GetVFLinkNames(pciAddress)
}
