// Copyright 2024 Antrea Authors
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

package winnet

import (
	"net"
)

// Interface is the interface for manipulating Windows network.
type Interface interface {
	NewNetRoute(route *Route) error

	RemoveNetRoute(route *Route) error

	ReplaceNetRoute(route *Route) error

	RouteListFiltered(family uint16, filter *Route, filterMask uint64) ([]Route, error)

	ReplaceNetNeighbor(neighbor *Neighbor) error

	NewNetNat(netNatName string, subnetCIDR *net.IPNet) error

	AddNetNatStaticMapping(mapping *NetNatStaticMapping) error

	ReplaceNetNatStaticMapping(mapping *NetNatStaticMapping) error

	RemoveNetNatStaticMapping(mapping *NetNatStaticMapping) error

	RemoveNetNatStaticMappings(netNatName string) error

	EnableNetAdapter(adapterName string) error

	NetAdapterExists(adapterName string) bool

	ConfigureNetAdapterIPAddress(adapterName string, ipConfig *net.IPNet, gateway string) error

	RemoveNetAdapterIPAddress(adapterName string, ipAddr net.IP) error

	RenameNetAdapter(oriName string, newName string) error

	SetNetAdapterMTU(adapterName string, mtu int) error

	SetNetAdapterMACAddress(adapterName string, macConfig *net.HardwareAddr) error

	SetNetAdapterDNSServers(adapterName, dnsServers string) error

	NetAdapterIPv4DHCPEnabled(adapterName string) (bool, error)

	IsVirtualNetAdapter(adapterName string) (bool, error)

	EnableIPForwarding(adapterName string) error

	EnableRSCOnVSwitch(vSwitch string) error

	GetDNServersByNetAdapterIndex(adapterIndex int) (string, error)

	CreateVMSwitch(adapterName string, vmSwitch string) error

	VMSwitchExists(vmSwitch string) (bool, error)

	RemoveVMSwitch(vmSwitch string) error

	GetVMSwitchNetAdapterName(vmSwitch string) (string, error)

	RenameVMNetworkAdapter(networkName, macStr, newName string, renameNetAdapter bool) error
}
