// Copyright 2022 Antrea Authors
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
	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
)

type postInterfaceCreateHook func() error

// podInterfaceConfigurator is for testing.
type podInterfaceConfigurator interface {
	configureContainerLink(podName string, podNamespace string, containerID string, containerNetNS string, containerIfaceName string, mtu int, brSriovVFDeviceID string, podSriovVFDeviceID string, result *current.Result, containerAccess *containerAccessArbitrator) error
	removeContainerLink(containerID, hostInterfaceName string) error
	advertiseContainerAddr(containerNetNS string, containerIfaceName string, result *current.Result) error
	validateVFRepInterface(sriovVFDeviceID string) (string, error)
	validateContainerPeerInterface(interfaces []*current.Interface, containerVeth *vethPair) (*vethPair, error)
	getInterceptedInterfaces(sandbox string, containerNetNS string, containerIFDev string) (*current.Interface, *current.Interface, error)
	checkContainerInterface(containerNetns, containerID string, containerIface *current.Interface, containerIPs []*current.IPConfig, containerRoutes []*cnitypes.Route, sriovVFDeviceID string) (interface{}, error)
	addPostInterfaceCreateHook(containerID, endpointName string, containerAccess *containerAccessArbitrator, hook postInterfaceCreateHook) error
	changeContainerMTU(containerNetNS string, containerIFDev string, mtuDeduction int) error
}

type SriovNet interface {
	GetNetDevicesFromPci(pciAddress string) ([]string, error)
	GetUplinkRepresentor(pciAddress string) (string, error)
	GetVfIndexByPciAddress(vfPciAddress string) (int, error)
	GetVfRepresentor(uplink string, vfIndex int) (string, error)
	GetPfName(vf string) (string, error)
	GetVfid(addr string, pfName string) (int, error)
	GetVFLinkNames(pciAddr string) (string, error)
}
