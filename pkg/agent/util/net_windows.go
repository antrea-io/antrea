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
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/Microsoft/hcsshim"
	ps "github.com/benmoss/go-powershell"
	"github.com/benmoss/go-powershell/backend"
	"github.com/containernetworking/plugins/pkg/ip"
	"k8s.io/klog"
)

const (
	ContainerVNICPrefix = "vEthernet"
	HNSNetworkType      = "Transparent"
	LocalHNSNetwork     = "antrea-hnsnetwork"
	OVSExtensionID      = "583CC151-73EC-4A6A-8B47-578297AD7623"
)

func GetNSPath(containerNetNS string) (string, error) {
	return containerNetNS, nil
}

// EnableHostInterface sets the specified interface status as UP.
func EnableHostInterface(ifaceName string) error {
	cmd := fmt.Sprintf("Enable-NetAdapter -InterfaceAlias %s", ifaceName)
	return invokePSCommand(cmd)
}

// ConfigureInterfaceAddress adds IPAddress on the specified interface.
func ConfigureInterfaceAddress(ifaceName string, ipConfig *net.IPNet) error {
	ipStr := strings.Split(ipConfig.String(), "/")
	cmd := fmt.Sprintf("New-NetIPAddress -InterfaceAlias %s -IPAddress %s -PrefixLength %s", ifaceName, ipStr[0], ipStr[1])
	return invokePSCommand(cmd)
}

// EnableIPForwarding enables the IP interface to forward packets that arrive on this interface to other interfaces.
func EnableIPForwarding(ifaceName string) error {
	cmd := fmt.Sprintf("Set-NetIPInterface -InterfaceAlias %s -Forwarding Enabled", ifaceName)
	return invokePSCommand(cmd)
}

func invokePSCommand(cmd string) error {
	_, err := callPSCommand(cmd)
	if err != nil {
		return err
	}
	return nil
}

func callPSCommand(cmd string) (string, error) {
	// Create a backend shell.
	back := &backend.Local{}

	// start a local powershell process
	shell, err := ps.New(back)
	if err != nil {
		return "", err
	}
	defer shell.Exit()
	stdout, stderr, err := shell.Execute(cmd)
	if err != nil {
		return stdout, err
	}
	if stderr != "" {
		return stdout, fmt.Errorf("%s", stderr)
	}
	return stdout, nil
}

// RemoveManagementInterface removes the management interface of the HNS Network, and then the physical interface can be
// added to the OVS bridge. This function is called only if Hyper-V feature is installed on the host.
func RemoveManagementInterface(networkName string) error {
	var err error
	var maxRetry = 3
	var i = 0
	cmd := fmt.Sprintf("Get-VMSwitch -Name %s  | Set-VMSwitch -AllowManagementOS $false ", networkName)
	// Retry the operation here because an error is returned at the first invocation.
	for i < maxRetry {
		err = invokePSCommand(cmd)
		if err == nil {
			return nil
		}
		i++
	}
	return err
}

// WindowsHyperVInstalled checks if the Hyper-V feature is enabled on the host.
func WindowsHyperVInstalled() (bool, error) {
	cmd := "$(Get-WindowsFeature Hyper-V).InstallState"
	result, err := callPSCommand(cmd)
	if err != nil {
		return true, err
	}
	return strings.HasPrefix(result, "Installed"), nil
}

// CreateHNSNetwork creates a new HNS Network, whose type is "Transparent". The NetworkAdapter is using the host
// interface which is configured with Node IP. HNS Network properties "ManagementIP" and "SourceMac" are used to record
// the original IP and MAC addresses on the network adapter.
func CreateHNSNetwork(hnsNetName string, subnetCIDR *net.IPNet, nodeIP *net.IPNet) (*hcsshim.HNSNetwork, error) {
	_, adapter, err := GetIPNetDeviceFromIP(nodeIP.IP)
	if err != nil {
		return nil, err
	}
	adapterMAC := adapter.HardwareAddr
	adapterName := adapter.Name
	gateway := ip.NextIP(subnetCIDR.IP.Mask(subnetCIDR.Mask))
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
	hnsNet, err := network.Create()
	if err != nil {
		return nil, err
	}
	return hnsNet, nil
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

	_, err := hcsshim.HNSNetworkRequest("POST", hnsNetID, string(jsonString))
	if err != nil {
		return err
	}
	return nil
}

// GetIPNetDeviceFromIP returns a local IP/mask and associated device from IP.
func GetIPNetDeviceFromIP(localIP net.IP) (*net.IPNet, *net.Interface, error) {
	linkList, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, link := range linkList {
		addrList, err := link.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrList {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.Equal(localIP) {
					return ipNet, &link, nil
				}
			}
		}
	}
	return nil, nil, fmt.Errorf("unable to find local IP and device")
}

func SetLinkUp(name string) (net.HardwareAddr, int, error) {
	// Set host gateway interface up.
	if err := EnableHostInterface(name); err != nil {
		klog.Errorf("Failed to set host link for %s up: %v", name, err)
		return nil, 0, err
	}

	iface, err := net.InterfaceByName(name)
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "no such network interface" {
			return nil, 0, newLinkNoteFoundError(name)
		}
		return nil, 0, err
	}
	mac := iface.HardwareAddr
	index := iface.Index
	return mac, index, nil
}

func ConfigureLinkAddress(idx int, gwIPNet *net.IPNet) error {
	iface, _ := net.InterfaceByIndex(idx)
	gwIP := gwIPNet.IP
	name := iface.Name
	if addrs, err := iface.Addrs(); err != nil {
		klog.Errorf("Failed to query IPv4 address list for interface %s: %v", name, err)
		return err
	} else if addrs != nil {
		for _, addr := range addrs {
			// Check with IPv4 address.
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.To4() != nil && ipNet.IP.Equal(gwIPNet.IP) {
					return nil
				}
			}
		}
	}

	klog.V(2).Infof("Adding address %v to gateway interface %s", gwIP, name)
	if err := ConfigureInterfaceAddress(iface.Name, gwIPNet); err != nil {
		klog.Errorf("Failed to set gateway interface %s with address %v: %v", iface, gwIP, err)
		return err
	}
	return nil
}

// PrepareHostNetworking creates HNS Network for containers.
func PrepareHostNetworking(subnetCIDR *net.IPNet, nodeIPNet *net.IPNet) error {
	_, err := hcsshim.GetHNSNetworkByName(LocalHNSNetwork)
	// If the HNS Network already exists, return immediately.
	if err == nil {
		return nil
	}
	if _, ok := err.(hcsshim.NetworkNotFoundError); !ok {
		return err
	}
	hnsNet, err := CreateHNSNetwork(LocalHNSNetwork, subnetCIDR, nodeIPNet)
	if err != nil {
		return err
	}

	// Enable OVS Extension on the HNS Network. If an error occurs, delete the HNS Network and return the error.
	if err = enableHNSOnOVS(hnsNet); err != nil {
		hnsNet.Delete()
		return err
	}
	klog.Infof("Created HNSNetwork with name %s id %s", hnsNet.Name, hnsNet.Id)
	return nil
}

func enableHNSOnOVS(hnsNet *hcsshim.HNSNetwork) error {
	// Release OS management for HNS Network if Hyper-V is enabled.
	hypervEnabled, err := WindowsHyperVInstalled()
	if err != nil {
		return err
	}
	if hypervEnabled {
		if err := RemoveManagementInterface(LocalHNSNetwork); err != nil {
			klog.Errorf("Failed to remove the interface managed by OS for HNSNetwork %s", LocalHNSNetwork)
			return err
		}
	}

	// Enable the HNS Network with OVS extension.
	if err := EnableHNSNetworkExtension(hnsNet.Id, OVSExtensionID); err != nil {
		return err
	}
	return err
}
