// +build windows

//Copyright 2020 Antrea Authors
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
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	ps "github.com/benmoss/go-powershell"
	"github.com/benmoss/go-powershell/backend"
	"k8s.io/klog"
)

const (
	ContainerVNICPrefix = "vEthernet"
	HNSNetworkType      = "Transparent"
	LocalHNSNetwork     = "antrea-hnsnetwork"
)

func GetNSPath(containerNetNS string) (string, error) {
	return containerNetNS, nil
}

// EnableHostInterface sets the specified interface status as UP.
func EnableHostInterface(ifaceName string) error {
	cmd := fmt.Sprintf("Enable-NetAdapter -InterfaceAlias %s", ifaceName)
	return InvokePSCommand(cmd)
}

// ConfigureInterfaceAddress adds IPAddress on the specified interface.
func ConfigureInterfaceAddress(ifaceName string, ipConfig *net.IPNet) error {
	ipStr := strings.Split(ipConfig.String(), "/")
	cmd := fmt.Sprintf("New-NetIPAddress -InterfaceAlias %s -IPAddress %s -PrefixLength %s", ifaceName, ipStr[0], ipStr[1])
	return InvokePSCommand(cmd)
}

// EnableIPForwarding enables the IP interface to forward packets that arrive on this interface to other interfaces.
func EnableIPForwarding(ifaceName string) error {
	cmd := fmt.Sprintf("Set-NetIPInterface -InterfaceAlias %s -Forwarding Enabled", ifaceName)
	return InvokePSCommand(cmd)
}

func InvokePSCommand(cmd string) error {
	_, err := CallPSCommand(cmd)
	if err != nil {
		return err
	}
	return nil
}

func CallPSCommand(cmd string) (string, error) {
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

// WindowsHyperVInstalled checks if the Hyper-V feature is enabled on the host.
func WindowsHyperVInstalled() (bool, error) {
	cmd := "$(Get-WindowsFeature Hyper-V).InstallState"
	result, err := CallPSCommand(cmd)
	if err != nil {
		return true, err
	}
	return strings.HasPrefix(result, "Installed"), nil
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

// GetLocalBroadcastIP returns the last IP address in a subnet. This IP is always working as the broadcast address in
// the subnet on Windows, and an active route entry that uses it as the destination is added by default when a new IP is
// configured on the interface.
func GetLocalBroadcastIP(ipNet *net.IPNet) net.IP {
	lastAddr := make(net.IP, len(ipNet.IP.To4()))
	binary.BigEndian.PutUint32(lastAddr, binary.BigEndian.Uint32(ipNet.IP.To4())|^binary.BigEndian.Uint32(net.IP(ipNet.Mask).To4()))
	return lastAddr
}
