//go:build windows
// +build windows

// Copyright 2020 Antrea Authors
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

package util

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	antreasyscall "antrea.io/antrea/pkg/agent/util/syscall"
	"antrea.io/antrea/pkg/agent/util/winnet"
)

const (
	LocalHNSNetwork = "antrea-hnsnetwork"
	HNSNetworkType  = "Transparent"
	namedPipePrefix = `\\.\pipe\`

	AntreaNatName = "antrea-nat"
	LocalVMSwitch = "antrea-switch"
)

var (
	winnetUtil winnet.Interface = &winnet.Handle{}

	getHNSNetworkByName = hcsshim.GetHNSNetworkByName
	hnsNetworkRequest   = hcsshim.HNSNetworkRequest
	hnsNetworkCreate    = (*hcsshim.HNSNetwork).Create
	hnsNetworkDelete    = (*hcsshim.HNSNetwork).Delete
)

func GetNSPath(containerNetNS string) (string, error) {
	return containerNetNS, nil
}

// CreateHNSNetwork creates a new HNS Network, whose type is "Transparent". The NetworkAdapter is using the host
// interface which is configured with Node IP. HNS Network properties "ManagementIP" and "SourceMac" are used to record
// the original IP and MAC addresses on the network adapter.
func CreateHNSNetwork(hnsNetName string, subnetCIDR *net.IPNet, nodeIP *net.IPNet, adapter *net.Interface) (*hcsshim.HNSNetwork, error) {
	adapterMAC := adapter.HardwareAddr
	adapterName := adapter.Name
	gateway := GetGatewayIPForPodCIDR(subnetCIDR)
	network := &hcsshim.HNSNetwork{
		Name:               hnsNetName,
		Type:               HNSNetworkType,
		NetworkAdapterName: adapterName,
		Subnets: []hcsshim.Subnet{
			{
				AddressPrefix:  subnetCIDR.String(),
				GatewayAddress: gateway.String(),
			},
		},
		ManagementIP: nodeIP.String(),
		SourceMac:    adapterMAC.String(),
	}
	hnsNet, err := hnsNetworkCreate(network)
	if err != nil {
		return nil, err
	}
	return hnsNet, nil
}

func DeleteHNSNetwork(hnsNetName string) error {
	hnsNet, err := getHNSNetworkByName(hnsNetName)
	if err != nil {
		if _, ok := err.(hcsshim.NetworkNotFoundError); !ok {
			return nil
		}
		return err
	}
	_, err = hnsNetworkDelete(hnsNet)
	return err
}

type vSwitchExtensionPolicy struct {
	ExtensionID string `json:"Id,omitempty"`
	IsEnabled   bool
}

type ExtensionsPolicy struct {
	Extensions []vSwitchExtensionPolicy `json:"Extensions"`
}

// EnableHNSNetworkExtension enables the specified vSwitchExtension on the target HNS Network. Antrea calls this function
// to enable OVS Extension on the HNS Network.
func EnableHNSNetworkExtension(hnsNetID string, vSwitchExtension string) error {
	extensionPolicy := vSwitchExtensionPolicy{
		ExtensionID: vSwitchExtension,
		IsEnabled:   true,
	}
	jsonString, _ := json.Marshal(
		ExtensionsPolicy{
			Extensions: []vSwitchExtensionPolicy{extensionPolicy},
		})

	_, err := hnsNetworkRequest("POST", hnsNetID, string(jsonString))
	if err != nil {
		return err
	}
	return nil
}

func SetLinkUp(name string) (net.HardwareAddr, int, error) {
	if err := wait.PollUntilContextTimeout(context.TODO(), time.Second, 5*time.Second, true, func(ctx context.Context) (done bool, err error) {
		if err := winnetUtil.EnableNetAdapter(name); err != nil {
			klog.Errorf("Failed to enable network adapter %s: %v", name, err)
			return false, nil
		}
		enabled, err := winnetUtil.IsNetAdapterStatusUp(name)
		if err != nil {
			klog.Errorf("Failed to get network adapter status %s: %v", name, err)
			return false, nil
		}
		if !enabled {
			klog.Infof("Waiting for network adapter %s to be up", name)
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, 0, fmt.Errorf("failed to enable network adapter %s: %v", name, err)
	}

	iface, err := netInterfaceByName(name)
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "no such network adapter" {
			return nil, 0, newLinkNotFoundError(name)
		}
		return nil, 0, err
	}
	mac := iface.HardwareAddr
	index := iface.Index
	return mac, index, nil
}

func addrEqual(addr1, addr2 *net.IPNet) bool {
	size1, _ := addr1.Mask.Size()
	size2, _ := addr2.Mask.Size()
	return addr1.IP.Equal(addr2.IP) && size1 == size2
}

// addrSliceDifference returns elements in s1 but not in s2.
func addrSliceDifference(s1, s2 []*net.IPNet) []*net.IPNet {
	var diff []*net.IPNet

	for _, e1 := range s1 {
		found := false
		for _, e2 := range s2 {
			if addrEqual(e1, e2) {
				found = true
				break
			}
		}
		if !found {
			diff = append(diff, e1)
		}
	}

	return diff
}

// ConfigureLinkAddresses adds the provided addresses to the interface identified by index idx, if
// they are missing from the interface. Any other existing address already configured for the
// interface will be removed, unless it is a link-local address. At the moment, this function only
// supports IPv4 addresses and will ignore any address in ipNets that is not IPv4.
func ConfigureLinkAddresses(idx int, ipNets []*net.IPNet) error {
	iface, err := netInterfaceByIndex(idx)
	if err != nil {
		return err
	}
	ifaceName := iface.Name
	var addrs []*net.IPNet
	ifaceAddrs, err := netInterfaceAddrs(iface)
	if err != nil {
		return fmt.Errorf("failed to query IPv4 address list for interface %s: %v", ifaceName, err)
	}
	for _, addr := range ifaceAddrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.IP.To4() != nil && !ipNet.IP.IsLinkLocalUnicast() {
				addrs = append(addrs, ipNet)
			}
		}
	}

	addrsToAdd := addrSliceDifference(ipNets, addrs)
	addrsToRemove := addrSliceDifference(addrs, ipNets)

	if len(addrsToAdd) == 0 && len(addrsToRemove) == 0 {
		klog.V(2).Infof("IP configuration for interface %s does not need to change", ifaceName)
		return nil
	}

	for _, addr := range addrsToRemove {
		klog.V(2).Infof("Removing address %v from interface %s", addr, ifaceName)
		if err := winnetUtil.RemoveNetAdapterIPAddress(ifaceName, addr.IP); err != nil {
			return fmt.Errorf("failed to remove address %v from interface %s: %v", addr, ifaceName, err)
		}
	}

	for _, addr := range addrsToAdd {
		klog.V(2).Infof("Adding address %v to interface %s", addr, ifaceName)
		if addr.IP.To4() == nil {
			klog.Warningf("Windows only supports IPv4 addresses, skipping this address %v", addr)
			return nil
		}
		if err := winnetUtil.AddNetAdapterIPAddress(ifaceName, addr, ""); err != nil {
			return fmt.Errorf("failed to add address %v to interface %s: %v", addr, ifaceName, err)
		}
	}

	return nil
}

// PrepareHNSNetwork creates HNS Network for containers.
func PrepareHNSNetwork(subnetCIDR *net.IPNet, nodeIPNet *net.IPNet, uplinkAdapter *net.Interface, nodeGateway string, dnsServers string, routes []interface{}, newName string) error {
	klog.InfoS("Creating HNSNetwork", "name", LocalHNSNetwork, "subnet", subnetCIDR, "nodeIP", nodeIPNet, "adapter", uplinkAdapter)
	hnsNet, err := CreateHNSNetwork(LocalHNSNetwork, subnetCIDR, nodeIPNet, uplinkAdapter)
	if err != nil {
		return fmt.Errorf("error creating HNSNetwork: %v", err)
	}

	success := false
	defer func() {
		if !success {
			hnsNetworkDelete(hnsNet)
		}
	}()
	var adapter *net.Interface
	var ipFound bool
	// On the current Windows testbed, it takes a maximum of 1.8 seconds to obtain a valid IP.
	// Therefore, we set the timeout limit to triple of that value, allowing a maximum wait of 6 seconds here.
	err = wait.PollUntilContextTimeout(context.TODO(), 1*time.Second, 6*time.Second, true, func(ctx context.Context) (bool, error) {
		var checkErr error
		adapter, ipFound, checkErr = adapterIPExists(nodeIPNet.IP, uplinkAdapter.HardwareAddr, winnet.ContainerVNICPrefix)
		if checkErr != nil {
			return false, checkErr
		}
		return ipFound, nil
	})
	if err != nil {
		if wait.Interrupted(err) {
			dhcpStatus, err := winnetUtil.IsNetAdapterIPv4DHCPEnabled(uplinkAdapter.Name)
			if err != nil {
				klog.ErrorS(err, "Failed to get IPv4 DHCP status on the network adapter", "adapter", uplinkAdapter.Name)
			} else {
				klog.ErrorS(err, "Timeout acquiring IP for the adapter", "dhcpStatus", dhcpStatus)
			}
		} else {
			return err
		}
	}
	vNicName, index := adapter.Name, adapter.Index
	// By default, "ipFound" should be true after Windows creates the HNSNetwork. The following check is for some corner
	// cases that Windows fails to move the physical adapter's IP address to the virtual network adapter, e.g., DHCP
	// Server fails to allocate IP to new virtual network.
	if !ipFound {
		klog.InfoS("Moving uplink configuration to the management virtual network adapter", "adapter", vNicName)
		if err := winnetUtil.AddNetAdapterIPAddress(vNicName, nodeIPNet, nodeGateway); err != nil {
			klog.ErrorS(err, "Failed to configure IP and gateway on the management virtual network adapter", "adapter", vNicName, "ip", nodeIPNet.String())
			return err
		}
		if dnsServers != "" {
			if err := winnetUtil.SetNetAdapterDNSServers(vNicName, dnsServers); err != nil {
				klog.ErrorS(err, "Failed to configure DNS servers on the management virtual network adapter", "adapter", vNicName, "dnsServers", dnsServers)
				return err
			}
		}
		for _, route := range routes {
			rt := route.(winnet.Route)
			newRt := winnet.Route{
				LinkIndex:         index,
				DestinationSubnet: rt.DestinationSubnet,
				GatewayAddress:    rt.GatewayAddress,
				RouteMetric:       rt.RouteMetric,
			}
			if err := winnetUtil.AddNetRoute(&newRt); err != nil {
				return err
			}
		}
		klog.InfoS("Moved uplink configuration to the management virtual network adapter", "adapter", vNicName)
	}
	if newName != "" {
		// Rename the vnic created by Windows host with the given newName, then it can be used by OVS when creating bridge port.
		uplinkMACStr := strings.Replace(uplinkAdapter.HardwareAddr.String(), ":", "", -1)
		// Rename NetAdapter in the meanwhile, then the network adapter can be treated as a host network adapter other than
		// a vm network adapter.
		if err = winnetUtil.RenameVMNetworkAdapter(LocalHNSNetwork, uplinkMACStr, newName, true); err != nil {
			return err
		}
	}

	// Enable OVS Extension on the HNS Network. If an error occurs, delete the HNS Network and return the error.
	// While the hnsshim API allows for enabling the OVS extension when creating an HNS network, it can cause the adapter being unable
	// to obtain a valid DHCP IP in case of network interruption. Therefore, we have to enable the OVS extension after running adapterIPExists.
	if err = EnableHNSNetworkExtension(hnsNet.Id, winnet.OVSExtensionID); err != nil {
		return err
	}

	if err = winnetUtil.EnableRSCOnVSwitch(LocalHNSNetwork); err != nil {
		return err
	}

	success = true
	klog.InfoS("Created HNSNetwork", "name", hnsNet.Name, "id", hnsNet.Id)
	return nil
}

// adapterIPExists finds the network adapter configured with the provided IP, MAC and its name has the given prefix.
// If "namePrefix" is empty, it returns the first network adapter with the provided IP and MAC.
// It returns true if the IP is found on the adapter, otherwise it returns false.
func adapterIPExists(ip net.IP, mac net.HardwareAddr, namePrefix string) (*net.Interface, bool, error) {
	adapters, err := netInterfaces()
	if err != nil {
		return nil, false, err
	}
	ipExists := false
	for idx, adapter := range adapters {
		if bytes.Equal(adapter.HardwareAddr, mac) {
			if namePrefix == "" || strings.Contains(adapter.Name, namePrefix) {
				addrList, err := netInterfaceAddrs(&adapters[idx])
				if err != nil {
					return nil, false, err
				}
				for _, addr := range addrList {
					if ipNet, ok := addr.(*net.IPNet); ok {
						if ipNet.IP.Equal(ip) {
							ipExists = true
							break
						}
					}
				}
				return &adapter, ipExists, nil
			}
		}
	}
	return nil, false, fmt.Errorf("unable to find a network adapter with MAC %s, IP %s, and name prefix %s", mac.String(), ip.String(), namePrefix)
}

// GetDefaultGatewayByInterfaceIndex returns the default gateway configured on the specified interface.
func GetDefaultGatewayByInterfaceIndex(ifIndex int) (string, error) {
	ip, defaultDestination, _ := net.ParseCIDR("0.0.0.0/0")
	family := winnet.AddressFamilyByIP(ip)
	filter := &winnet.Route{
		LinkIndex:         ifIndex,
		DestinationSubnet: defaultDestination,
	}
	routes, err := winnetUtil.RouteListFiltered(family, filter, winnet.RT_FILTER_IF|winnet.RT_FILTER_DST)
	if err != nil {
		return "", err
	}
	if len(routes) == 0 {
		return "", nil
	}
	return routes[0].GatewayAddress.String(), nil
}

// ListenLocalSocket creates a listener on a Unix domain socket or a Windows named pipe.
// - If the specified address starts with "\\.\pipe\",  create a listener on a Windows named pipe path.
// - Else create a listener on a local Unix domain socket.
func ListenLocalSocket(address string) (net.Listener, error) {
	if strings.HasPrefix(address, namedPipePrefix) {
		return winio.ListenPipe(address, nil)
	}
	return listenUnix(address)
}

func HostInterfaceExists(ifaceName string) bool {
	return winnetUtil.NetAdapterExists(ifaceName)
}

func GetInterfaceConfig(ifName string) (*net.Interface, []*net.IPNet, []interface{}, error) {
	iface, err := netInterfaceByName(ifName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get interface %s: %v", ifName, err)
	}
	addrs, err := getIPNetsByLink(iface)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get address for interface %s: %v", iface.Name, err)
	}
	rts, err := winnetUtil.RouteListFiltered(antreasyscall.AF_UNSPEC, &winnet.Route{LinkIndex: iface.Index}, winnet.RT_FILTER_IF)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get routes for interface index %d: %v", iface.Index, err)
	}
	var routes []interface{}
	for _, rt := range rts {
		// Skip the routes automatically generated by Windows host when adding IP address on the network adapter.
		if rt.GatewayAddress != nil && rt.GatewayAddress.IsUnspecified() {
			continue
		}
		routes = append(routes, rt)
	}
	return iface, addrs, routes, nil
}

func RenameInterface(from, to string) error {
	var renameErr error
	pollErr := wait.PollUntilContextTimeout(context.TODO(), time.Millisecond*100, time.Second, false, func(ctx context.Context) (done bool, err error) {
		renameErr = winnetUtil.RenameNetAdapter(from, to)
		if renameErr != nil {
			klog.ErrorS(renameErr, "Failed to rename adapter, retrying")
			return false, nil
		}
		return true, nil
	})
	if pollErr != nil {
		return fmt.Errorf("failed to rename host interface name %s to %s", from, to)
	}
	return nil
}

func GenHostInterfaceName(upLinkIfName string) string {
	return strings.TrimSuffix(upLinkIfName, bridgedUplinkSuffix)
}
