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
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim"
	ps "github.com/antoninbas/go-powershell"
	"github.com/antoninbas/go-powershell/backend"
	"github.com/containernetworking/plugins/pkg/ip"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

const (
	ContainerVNICPrefix  = "vEthernet"
	HNSNetworkType       = "Transparent"
	LocalHNSNetwork      = "antrea-hnsnetwork"
	OVSExtensionID       = "583CC151-73EC-4A6A-8B47-578297AD7623"
	namedPipePrefix      = `\\.\pipe\`
	commandRetryTimeout  = 5 * time.Second
	commandRetryInterval = time.Second
)

func GetNSPath(containerNetNS string) (string, error) {
	return containerNetNS, nil
}

func GetHostInterfaceStatus(ifaceName string) (string, error) {
	cmd := fmt.Sprintf(`Get-NetAdapter -InterfaceAlias "%s" | Select-Object -Property Status | Format-Table -HideTableHeaders`, ifaceName)
	out, err := CallPSCommand(cmd)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// EnableHostInterface sets the specified interface status as UP.
func EnableHostInterface(ifaceName string) error {
	cmd := fmt.Sprintf(`Enable-NetAdapter -InterfaceAlias "%s"`, ifaceName)
	// Enable-NetAdapter is not a blocking operation based on our testing.
	// It returns immediately no matter whether the interface has been enabled or not.
	// So we need to check the interface status to ensure it is up before returning.
	if err := wait.PollImmediate(commandRetryInterval, commandRetryTimeout, func() (done bool, err error) {
		if err := InvokePSCommand(cmd); err != nil {
			klog.Errorf("Failed to run command %s: %v", cmd, err)
			return false, nil
		}
		status, err := GetHostInterfaceStatus(ifaceName)
		if err != nil {
			klog.Errorf("Failed to run command %s: %v", cmd, err)
			return false, nil
		}
		if !strings.EqualFold(status, "Up") {
			klog.Infof("Waiting for host interface %s to be up", ifaceName)
			return false, nil
		}
		return true, nil
	}); err != nil {
		return fmt.Errorf("failed to enable interface %s: %v", ifaceName, err)
	}
	return nil
}

// ConfigureInterfaceAddress adds IPAddress on the specified interface.
func ConfigureInterfaceAddress(ifaceName string, ipConfig *net.IPNet) error {
	ipStr := strings.Split(ipConfig.String(), "/")
	cmd := fmt.Sprintf(`New-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -PrefixLength %s`, ifaceName, ipStr[0], ipStr[1])
	err := InvokePSCommand(cmd)
	// If the address already exists, ignore the error.
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}

// RemoveInterfaceAddress removes IPAddress from the specified interface.
func RemoveInterfaceAddress(ifaceName string, ipAddr net.IP) error {
	cmd := fmt.Sprintf(`Remove-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -Confirm:$false`, ifaceName, ipAddr.String())
	err := InvokePSCommand(cmd)
	// If the address does not exist, ignore the error.
	if err != nil && !strings.Contains(err.Error(), "No matching") {
		return err
	}
	return nil
}

// ConfigureInterfaceAddressWithDefaultGateway adds IPAddress on the specified interface and sets the default gateway
// for the host.
func ConfigureInterfaceAddressWithDefaultGateway(ifaceName string, ipConfig *net.IPNet, gateway string) error {
	ipStr := strings.Split(ipConfig.String(), "/")
	cmd := fmt.Sprintf(`New-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -PrefixLength %s -DefaultGateway %s`, ifaceName, ipStr[0], ipStr[1], gateway)
	err := InvokePSCommand(cmd)
	// If the address already exists, ignore the error.
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}

// EnableIPForwarding enables the IP interface to forward packets that arrive on this interface to other interfaces.
func EnableIPForwarding(ifaceName string) error {
	cmd := fmt.Sprintf(`Set-NetIPInterface -InterfaceAlias "%s" -Forwarding Enabled`, ifaceName)
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

// RemoveManagementInterface removes the management interface of the HNS Network, and then the physical interface can be
// added to the OVS bridge. This function is called only if Hyper-V feature is installed on the host.
func RemoveManagementInterface(networkName string) error {
	var err error
	var maxRetry = 3
	var i = 0
	cmd := fmt.Sprintf("Get-VMSwitch -Name %s  | Set-VMSwitch -AllowManagementOS $false ", networkName)
	// Retry the operation here because an error is returned at the first invocation.
	for i < maxRetry {
		err = InvokePSCommand(cmd)
		if err == nil {
			return nil
		}
		i++
	}
	return err
}

// ConfigureMACAddress set specified MAC address on interface.
func SetAdapterMACAddress(adapterName string, macConfig *net.HardwareAddr) error {
	macAddr := strings.Replace(macConfig.String(), ":", "", -1)
	cmd := fmt.Sprintf("Set-NetAdapterAdvancedProperty -Name %s -RegistryKeyword NetworkAddress -RegistryValue %s",
		adapterName, macAddr)
	return InvokePSCommand(cmd)
}

// WindowsHyperVEnabled checks if the Hyper-V is enabled on the host.
// Hyper-V feature contains multiple components/sub-features. According to the
// test, OVS requires "Microsoft-Hyper-V" feature to be enabled.
func WindowsHyperVEnabled() (bool, error) {
	cmd := "$(Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).State"
	result, err := CallPSCommand(cmd)
	if err != nil {
		return true, err
	}
	return strings.HasPrefix(result, "Enabled"), nil
}

// CreateHNSNetwork creates a new HNS Network, whose type is "Transparent". The NetworkAdapter is using the host
// interface which is configured with Node IP. HNS Network properties "ManagementIP" and "SourceMac" are used to record
// the original IP and MAC addresses on the network adapter.
func CreateHNSNetwork(hnsNetName string, subnetCIDR *net.IPNet, nodeIP *net.IPNet, adapter *net.Interface) (*hcsshim.HNSNetwork, error) {
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

func DeleteHNSNetwork(hnsNetName string) error {
	hnsNet, err := hcsshim.GetHNSNetworkByName(hnsNetName)
	if err != nil {
		if _, ok := err.(hcsshim.NetworkNotFoundError); !ok {
			return nil
		} else {
			return err
		}
	}
	_, err = hnsNet.Delete()
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

	_, err := hcsshim.HNSNetworkRequest("POST", hnsNetID, string(jsonString))
	if err != nil {
		return err
	}
	return nil
}

func SetLinkUp(name string) (net.HardwareAddr, int, error) {
	// Set host gateway interface up.
	if err := EnableHostInterface(name); err != nil {
		klog.Errorf("Failed to set host link for %s up: %v", name, err)
		if strings.Contains(err.Error(), "ObjectNotFound") {
			return nil, 0, newLinkNotFoundError(name)
		}
		return nil, 0, err
	}

	iface, err := net.InterfaceByName(name)
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "no such network interface" {
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
	iface, _ := net.InterfaceByIndex(idx)
	ifaceName := iface.Name
	var addrs []*net.IPNet
	if ifaceAddrs, err := iface.Addrs(); err != nil {
		return fmt.Errorf("failed to query IPv4 address list for interface %s: %v", ifaceName, err)
	} else {
		for _, addr := range ifaceAddrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.To4() != nil && !ipNet.IP.IsLinkLocalUnicast() {
					addrs = append(addrs, ipNet)
				}
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
		if err := RemoveInterfaceAddress(ifaceName, addr.IP); err != nil {
			return fmt.Errorf("failed to remove address %v from interface %s: %v", addr, ifaceName, err)
		}
	}

	for _, addr := range addrsToAdd {
		klog.V(2).Infof("Adding address %v to interface %s", addr, ifaceName)
		if addr.IP.To4() == nil {
			klog.Warningf("Windows only supports IPv4 addresses, skipping this address %v", addr)
			return nil
		}
		if err := ConfigureInterfaceAddress(ifaceName, addr); err != nil {
			return fmt.Errorf("failed to add address %v to interface %s: %v", addr, ifaceName, err)
		}
	}

	return nil
}

// PrepareHNSNetwork creates HNS Network for containers.
func PrepareHNSNetwork(subnetCIDR *net.IPNet, nodeIPNet *net.IPNet, uplinkAdapter *net.Interface) error {
	hnsNet, err := CreateHNSNetwork(LocalHNSNetwork, subnetCIDR, nodeIPNet, uplinkAdapter)
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
	hypervEnabled, err := WindowsHyperVEnabled()
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

// GetLocalBroadcastIP returns the last IP address in a subnet. This IP is always working as the broadcast address in
// the subnet on Windows, and an active route entry that uses it as the destination is added by default when a new IP is
// configured on the interface.
func GetLocalBroadcastIP(ipNet *net.IPNet) net.IP {
	lastAddr := make(net.IP, len(ipNet.IP.To4()))
	binary.BigEndian.PutUint32(lastAddr, binary.BigEndian.Uint32(ipNet.IP.To4())|^binary.BigEndian.Uint32(net.IP(ipNet.Mask).To4()))
	return lastAddr
}

// GetDefaultGatewayByInterfaceIndex returns the default gateway configured on the speicified interface.
func GetDefaultGatewayByInterfaceIndex(ifIndex int) (string, error) {
	cmd := fmt.Sprintf("$(Get-NetRoute -InterfaceIndex %d -DestinationPrefix 0.0.0.0/0 ).NextHop", ifIndex)
	defaultGW, err := CallPSCommand(cmd)
	if err != nil {
		return "", err
	}
	defaultGW = strings.ReplaceAll(defaultGW, "\r\n", "")
	return defaultGW, nil
}

// GetDNServersByInterfaceIndex returns the DNS servers configured on the specified interface.
func GetDNServersByInterfaceIndex(ifIndex int) (string, error) {
	cmd := fmt.Sprintf("$(Get-DnsClientServerAddress -InterfaceIndex %d -AddressFamily IPv4).ServerAddresses", ifIndex)
	dnsServers, err := CallPSCommand(cmd)
	if err != nil {
		return "", err
	}
	dnsServers = strings.ReplaceAll(dnsServers, "\r\n", ",")
	dnsServers = strings.TrimRight(dnsServers, ",")
	return dnsServers, nil
}

// SetAdapterDNSServers configures DNSServers on network adapter.
func SetAdapterDNSServers(adapterName, dnsServers string) error {
	cmd := fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias %s -ServerAddresses %s", adapterName, dnsServers)
	if err := InvokePSCommand(cmd); err != nil {
		return err
	}
	return nil
}

// ListenLocalSocket creates a listener on a Unix domain socket or a Windows named pipe.
// - If the specified address starts with "\\.\pipe\",  create a listener on the a Windows named pipe path.
// - Else create a listener on a local Unix domain socket.
func ListenLocalSocket(address string) (net.Listener, error) {
	if strings.HasPrefix(address, namedPipePrefix) {
		return winio.ListenPipe(address, nil)
	}
	return listenUnix(address)
}

// DialLocalSocket connects to a Unix domain socket or a Windows named pipe.
// - If the specified address starts with "\\.\pipe\",  connect to a Windows named pipe path.
// - Else connect to a Unix domain socket.
func DialLocalSocket(address string) (net.Conn, error) {
	if strings.HasPrefix(address, namedPipePrefix) {
		return winio.DialPipe(address, nil)
	}
	return dialUnix(address)
}

func HostInterfaceExists(ifaceName string) bool {
	if _, err := net.InterfaceByName(ifaceName); err == nil {
		return true
	}
	// Some kinds of interfaces cannot be retrieved by "net.InterfaceByName" such as
	// container vnic.
	// So if a interface cannot be found by above function, use powershell command
	// "Get-NetAdapter" to check if it exists.
	cmd := fmt.Sprintf(`Get-NetAdapter -InterfaceAlias "%s"`, ifaceName)
	if err := InvokePSCommand(cmd); err != nil {
		return false
	}
	return true
}

// SetInterfaceMTU configures interface MTU on host for Pods. MTU change cannot be realized with HNSEndpoint because
// there's no MTU field in HNSEndpoint:
// https://github.com/Microsoft/hcsshim/blob/4a468a6f7ae547974bc32911395c51fb1862b7df/internal/hns/hnsendpoint.go#L12
func SetInterfaceMTU(ifaceName string, mtu int) error {
	cmd := fmt.Sprintf("Set-NetIPInterface -IncludeAllCompartments -InterfaceAlias \"%s\" -NlMtuBytes %d",
		ifaceName, mtu)
	return InvokePSCommand(cmd)
}
