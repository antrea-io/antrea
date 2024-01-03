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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim"
	"github.com/containernetworking/plugins/pkg/ip"
	"golang.org/x/sys/windows"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	ps "antrea.io/antrea/pkg/agent/util/powershell"
	antreasyscall "antrea.io/antrea/pkg/agent/util/syscall"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	iputil "antrea.io/antrea/pkg/util/ip"
)

const (
	ContainerVNICPrefix  = "vEthernet"
	HNSNetworkType       = "Transparent"
	LocalHNSNetwork      = "antrea-hnsnetwork"
	OVSExtensionID       = "583CC151-73EC-4A6A-8B47-578297AD7623"
	ovsExtensionName     = "Open vSwitch Extension"
	namedPipePrefix      = `\\.\pipe\`
	commandRetryTimeout  = 5 * time.Second
	commandRetryInterval = time.Second

	MetricDefault = 256
	MetricHigh    = 50

	AntreaNatName = "antrea-nat"
	LocalVMSwitch = "antrea-switch"

	// Filter masks are used to indicate the attributes used for route filtering.
	RT_FILTER_IF uint64 = 1 << (1 + iota)
	RT_FILTER_METRIC
	RT_FILTER_DST
	RT_FILTER_GW

	// IP_ADAPTER_DHCP_ENABLED is defined in the Win32 API document.
	// https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
	IP_ADAPTER_DHCP_ENABLED = 0x00000004
)

var (
	// Declared variables which are meant to be overridden for testing.
	antreaNetIO          = antreasyscall.NewNetIO()
	getAdaptersAddresses = windows.GetAdaptersAddresses
	runCommand           = ps.RunCommand
	getHNSNetworkByName  = hcsshim.GetHNSNetworkByName
	hnsNetworkRequest    = hcsshim.HNSNetworkRequest
	hnsNetworkCreate     = (*hcsshim.HNSNetwork).Create
	hnsNetworkDelete     = (*hcsshim.HNSNetwork).Delete
)

type Route struct {
	LinkIndex         int
	DestinationSubnet *net.IPNet
	GatewayAddress    net.IP
	RouteMetric       int
}

func (r *Route) String() string {
	return fmt.Sprintf("LinkIndex: %d, DestinationSubnet: %s, GatewayAddress: %s, RouteMetric: %d",
		r.LinkIndex, r.DestinationSubnet, r.GatewayAddress, r.RouteMetric)
}

func (r *Route) Equal(x Route) bool {
	return x.LinkIndex == r.LinkIndex &&
		x.DestinationSubnet != nil &&
		r.DestinationSubnet != nil &&
		iputil.IPNetEqual(x.DestinationSubnet, r.DestinationSubnet) &&
		x.GatewayAddress.Equal(r.GatewayAddress)
}

func (r *Route) toMibIPForwardRow() *antreasyscall.MibIPForwardRow {
	row := antreasyscall.NewIPForwardRow()
	row.DestinationPrefix = *antreasyscall.NewAddressPrefixFromIPNet(r.DestinationSubnet)
	row.NextHop = *antreasyscall.NewRawSockAddrInetFromIP(r.GatewayAddress)
	row.Metric = uint32(r.RouteMetric)
	row.Index = uint32(r.LinkIndex)
	return row
}

func routeFromIPForwardRow(row *antreasyscall.MibIPForwardRow) *Route {
	destination := row.DestinationPrefix.IPNet()
	gatewayAddr := row.NextHop.IP()
	return &Route{
		DestinationSubnet: destination,
		GatewayAddress:    gatewayAddr,
		LinkIndex:         int(row.Index),
		RouteMetric:       int(row.Metric),
	}
}

type Neighbor struct {
	LinkIndex        int
	IPAddress        net.IP
	LinkLayerAddress net.HardwareAddr
	State            string
}

func (n Neighbor) String() string {
	return fmt.Sprintf("LinkIndex: %d, IPAddress: %s, LinkLayerAddress: %s", n.LinkIndex, n.IPAddress, n.LinkLayerAddress)
}

type NetNatStaticMapping struct {
	Name         string
	ExternalIP   net.IP
	ExternalPort uint16
	InternalIP   net.IP
	InternalPort uint16
	Protocol     binding.Protocol
}

func (n NetNatStaticMapping) String() string {
	return fmt.Sprintf("Name: %s, ExternalIP %s, ExternalPort: %d, InternalIP: %s, InternalPort: %d, Protocol: %s", n.Name, n.ExternalIP, n.ExternalPort, n.InternalIP, n.InternalPort, n.Protocol)
}

func GetNSPath(containerNetNS string) (string, error) {
	return containerNetNS, nil
}

// IsVirtualAdapter checks if the provided adapter is virtual.
func IsVirtualAdapter(name string) (bool, error) {
	cmd := fmt.Sprintf(`Get-NetAdapter -InterfaceAlias "%s" | Select-Object -Property Virtual | Format-Table -HideTableHeaders`, name)
	out, err := runCommand(cmd)
	if err != nil {
		return false, err
	}
	isVirtual, err := strconv.ParseBool(strings.TrimSpace(out))
	if err != nil {
		return false, err
	}
	return isVirtual, nil
}

func GetHostInterfaceStatus(ifaceName string) (string, error) {
	cmd := fmt.Sprintf(`Get-NetAdapter -InterfaceAlias "%s" | Select-Object -Property Status | Format-Table -HideTableHeaders`, ifaceName)
	out, err := runCommand(cmd)
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
	if err := wait.PollUntilContextTimeout(context.TODO(), commandRetryInterval, commandRetryTimeout, true, func(ctx context.Context) (done bool, err error) {
		if _, err := runCommand(cmd); err != nil {
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
	_, err := runCommand(cmd)
	// If the address already exists, ignore the error.
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}

// RemoveInterfaceAddress removes IPAddress from the specified interface.
func RemoveInterfaceAddress(ifaceName string, ipAddr net.IP) error {
	cmd := fmt.Sprintf(`Remove-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -Confirm:$false`, ifaceName, ipAddr.String())
	_, err := runCommand(cmd)
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
	cmd := fmt.Sprintf(`New-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -PrefixLength %s`, ifaceName, ipStr[0], ipStr[1])
	if gateway != "" {
		cmd = fmt.Sprintf("%s -DefaultGateway %s", cmd, gateway)
	}
	_, err := runCommand(cmd)
	// If the address already exists, ignore the error.
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}

// EnableIPForwarding enables the IP interface to forward packets that arrive at this interface to other interfaces.
func EnableIPForwarding(ifaceName string) error {
	adapter, err := getAdapterInAllCompartmentsByName(ifaceName)
	if err != nil {
		return fmt.Errorf("unable to find NetAdapter on host in all compartments with name %s: %v", ifaceName, err)
	}
	return adapter.setForwarding(true, antreasyscall.AF_INET)
}

func RenameVMNetworkAdapter(networkName string, macStr, newName string, renameNetAdapter bool) error {
	cmd := fmt.Sprintf(`Get-VMNetworkAdapter -ManagementOS -ComputerName "$(hostname)" -SwitchName "%s" | ? MacAddress -EQ "%s" | Select-Object -Property Name | Format-Table -HideTableHeaders`, networkName, macStr)
	stdout, err := runCommand(cmd)
	if err != nil {
		return err
	}
	stdout = strings.TrimSpace(stdout)
	if len(stdout) == 0 {
		return fmt.Errorf("unable to find vmnetwork adapter configured with uplink MAC address %s", macStr)
	}
	vmNetworkAdapterName := stdout
	cmd = fmt.Sprintf(`Get-VMNetworkAdapter -ManagementOS -ComputerName "$(hostname)" -Name "%s" | Rename-VMNetworkAdapter -NewName "%s"`, vmNetworkAdapterName, newName)
	if _, err := runCommand(cmd); err != nil {
		return err
	}
	if renameNetAdapter {
		oriNetAdapterName := VirtualAdapterName(newName)
		cmd = fmt.Sprintf(`Get-NetAdapter -Name "%s" | Rename-NetAdapter -NewName "%s"`, oriNetAdapterName, newName)
		if _, err := runCommand(cmd); err != nil {
			return err
		}
	}
	return nil
}

// SetAdapterMACAddress sets specified MAC address on interface.
func SetAdapterMACAddress(adapterName string, macConfig *net.HardwareAddr) error {
	macAddr := strings.Replace(macConfig.String(), ":", "", -1)
	cmd := fmt.Sprintf(`Set-NetAdapterAdvancedProperty -Name "%s" -RegistryKeyword NetworkAddress -RegistryValue "%s"`,
		adapterName, macAddr)
	_, err := runCommand(cmd)
	return err
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
	// Set host gateway interface up.
	if err := EnableHostInterface(name); err != nil {
		klog.Errorf("Failed to set host link for %s up: %v", name, err)
		if strings.Contains(err.Error(), "ObjectNotFound") {
			return nil, 0, newLinkNotFoundError(name)
		}
		return nil, 0, err
	}

	iface, err := netInterfaceByName(name)
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
		adapter, ipFound, checkErr = adapterIPExists(nodeIPNet.IP, uplinkAdapter.HardwareAddr, ContainerVNICPrefix)
		if checkErr != nil {
			return false, checkErr
		}
		return ipFound, nil
	})
	if err != nil {
		if wait.Interrupted(err) {
			dhcpStatus, err := InterfaceIPv4DhcpEnabled(uplinkAdapter.Name)
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
		if err := ConfigureInterfaceAddressWithDefaultGateway(vNicName, nodeIPNet, nodeGateway); err != nil {
			klog.ErrorS(err, "Failed to configure IP and gateway on the management virtual network adapter", "adapter", vNicName, "ip", nodeIPNet.String())
			return err
		}
		if dnsServers != "" {
			if err := SetAdapterDNSServers(vNicName, dnsServers); err != nil {
				klog.ErrorS(err, "Failed to configure DNS servers on the management virtual network adapter", "adapter", vNicName, "dnsServers", dnsServers)
				return err
			}
		}
		for _, route := range routes {
			rt := route.(Route)
			newRt := Route{
				LinkIndex:         index,
				DestinationSubnet: rt.DestinationSubnet,
				GatewayAddress:    rt.GatewayAddress,
				RouteMetric:       rt.RouteMetric,
			}
			if err := NewNetRoute(&newRt); err != nil {
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
		if err = RenameVMNetworkAdapter(LocalHNSNetwork, uplinkMACStr, newName, true); err != nil {
			return err
		}
	}

	// Enable OVS Extension on the HNS Network. If an error occurs, delete the HNS Network and return the error.
	// While the hnsshim API allows for enabling the OVS extension when creating an HNS network, it can cause the adapter being unable
	// to obtain a valid DHCP IP in case of network interruption. Therefore, we have to enable the OVS extension after running adapterIPExists.
	if err = EnableHNSNetworkExtension(hnsNet.Id, OVSExtensionID); err != nil {
		return err
	}

	if err = EnableRSCOnVSwitch(LocalHNSNetwork); err != nil {
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

// EnableRSCOnVSwitch enables RSC in the vSwitch to reduce host CPU utilization and increase throughput for virtual
// workloads by coalescing multiple TCP segments into fewer, but larger segments.
func EnableRSCOnVSwitch(vSwitch string) error {
	cmd := fmt.Sprintf("Get-VMSwitch -ComputerName $(hostname) -Name %s | Select-Object -Property SoftwareRscEnabled | Format-Table -HideTableHeaders", vSwitch)
	stdout, err := runCommand(cmd)
	if err != nil {
		return err
	}
	stdout = strings.TrimSpace(stdout)
	// RSC doc says it applies to Windows Server 2019, which is the only Windows operating system supported so far, so
	// this should not happen. However, this is only an optimization, no need to crash the process even if it's not
	// supported.
	// https://docs.microsoft.com/en-us/windows-server/networking/technologies/hpn/rsc-in-the-vswitch
	if len(stdout) == 0 {
		klog.Warning("Receive Segment Coalescing (RSC) is not supported by this Windows Server version")
		return nil
	}
	if strings.EqualFold(stdout, "True") {
		klog.Infof("Receive Segment Coalescing (RSC) for vSwitch %s is already enabled", vSwitch)
		return nil
	}
	cmd = fmt.Sprintf("Set-VMSwitch -ComputerName $(hostname) -Name %s -EnableSoftwareRsc $True", vSwitch)
	_, err = runCommand(cmd)
	if err != nil {
		return err
	}
	klog.Infof("Enabled Receive Segment Coalescing (RSC) for vSwitch %s", vSwitch)
	return nil
}

// GetDefaultGatewayByInterfaceIndex returns the default gateway configured on the specified interface.
func GetDefaultGatewayByInterfaceIndex(ifIndex int) (string, error) {
	ip, defaultDestination, _ := net.ParseCIDR("0.0.0.0/0")
	family := addressFamilyByIP(ip)
	filter := &Route{
		LinkIndex:         ifIndex,
		DestinationSubnet: defaultDestination,
	}
	routes, err := RouteListFiltered(family, filter, RT_FILTER_IF|RT_FILTER_DST)
	if err != nil {
		return "", err
	}
	if len(routes) == 0 {
		return "", nil
	}
	return routes[0].GatewayAddress.String(), nil
}

// GetDNServersByInterfaceIndex returns the DNS servers configured on the specified interface.
func GetDNServersByInterfaceIndex(ifIndex int) (string, error) {
	cmd := fmt.Sprintf("$(Get-DnsClientServerAddress -InterfaceIndex %d -AddressFamily IPv4).ServerAddresses", ifIndex)
	dnsServers, err := runCommand(cmd)
	if err != nil {
		return "", err
	}
	dnsServers = strings.ReplaceAll(dnsServers, "\r\n", ",")
	dnsServers = strings.TrimRight(dnsServers, ",")
	return dnsServers, nil
}

// SetAdapterDNSServers configures DNSServers on network adapter.
func SetAdapterDNSServers(adapterName, dnsServers string) error {
	cmd := fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias "%s" -ServerAddresses "%s"`, adapterName, dnsServers)
	if _, err := runCommand(cmd); err != nil {
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

func HostInterfaceExists(ifaceName string) bool {
	_, err := getAdapterInAllCompartmentsByName(ifaceName)
	if err != nil {
		return false
	}
	return true
}

// InterfaceIPv4DhcpEnabled returns the IPv4 DHCP status on the specified interface.
func InterfaceIPv4DhcpEnabled(ifaceName string) (bool, error) {
	adapter, err := getAdapterInAllCompartmentsByName(ifaceName)
	if err != nil {
		return false, err
	}
	ipv4Dhcp := (adapter.flags&IP_ADAPTER_DHCP_ENABLED != 0)
	return ipv4Dhcp, nil
}

// SetInterfaceMTU configures interface MTU on host for Pods. MTU change cannot be realized with HNSEndpoint because
// there's no MTU field in HNSEndpoint:
// https://github.com/Microsoft/hcsshim/blob/4a468a6f7ae547974bc32911395c51fb1862b7df/internal/hns/hnsendpoint.go#L12
func SetInterfaceMTU(ifaceName string, mtu int) error {
	adapter, err := getAdapterInAllCompartmentsByName(ifaceName)
	if err != nil {
		return fmt.Errorf("unable to find NetAdapter on host in all compartments with name %s: %v", ifaceName, err)
	}
	return adapter.setMTU(mtu, antreasyscall.AF_INET)
}

func NewNetRoute(route *Route) error {
	if route == nil {
		return nil
	}
	row := route.toMibIPForwardRow()
	if err := antreaNetIO.CreateIPForwardEntry(row); err != nil {
		return fmt.Errorf("failed to create new IPForward row: %v", err)
	}
	return nil
}

func RemoveNetRoute(route *Route) error {
	if route == nil || route.DestinationSubnet == nil {
		return nil
	}
	family := addressFamilyByIP(route.DestinationSubnet.IP)
	rows, err := antreaNetIO.ListIPForwardRows(family)
	if err != nil {
		return fmt.Errorf("unable to list Windows IPForward rows: %v", err)
	}
	for i := range rows {
		row := rows[i]
		if row.DestinationPrefix.EqualsTo(route.DestinationSubnet) && row.Index == uint32(route.LinkIndex) && row.NextHop.IP().Equal(route.GatewayAddress) {
			if err := antreaNetIO.DeleteIPForwardEntry(&row); err != nil {
				return fmt.Errorf("failed to delete existing route %s: %v", route.String(), err)
			}
		}
	}
	return nil
}

func ReplaceNetRoute(route *Route) error {
	if route == nil || route.DestinationSubnet == nil {
		return nil
	}
	family := addressFamilyByIP(route.DestinationSubnet.IP)
	rows, err := antreaNetIO.ListIPForwardRows(family)
	if err != nil {
		return fmt.Errorf("unable to list Windows IPForward rows: %v", err)
	}
	for i := range rows {
		row := rows[i]
		if row.DestinationPrefix.EqualsTo(route.DestinationSubnet) && row.Index == uint32(route.LinkIndex) {
			if row.NextHop.IP().Equal(route.GatewayAddress) {
				return nil
			} else {
				if err := antreaNetIO.DeleteIPForwardEntry(&row); err != nil {
					return fmt.Errorf("failed to delete existing route with nextHop %s: %v", route.GatewayAddress, err)
				}
			}
		}
	}
	return NewNetRoute(route)
}

func RouteListFiltered(family uint16, filter *Route, filterMask uint64) ([]Route, error) {
	rows, err := antreaNetIO.ListIPForwardRows(family)
	if err != nil {
		return nil, fmt.Errorf("unable to list Windows IPForward rows: %v", err)
	}
	rts := make([]Route, 0, len(rows))
	for i := range rows {
		route := routeFromIPForwardRow(&rows[i])
		if filter != nil {
			if filterMask&RT_FILTER_IF != 0 && filter.LinkIndex != route.LinkIndex {
				continue
			}
			if filterMask&RT_FILTER_DST != 0 && !iputil.IPNetEqual(filter.DestinationSubnet, route.DestinationSubnet) {
				continue
			}
			if filterMask&RT_FILTER_GW != 0 && !filter.GatewayAddress.Equal(route.GatewayAddress) {
				continue
			}
			if filterMask&RT_FILTER_METRIC != 0 && filter.RouteMetric != route.RouteMetric {
				continue
			}
		}
		rts = append(rts, *route)
	}
	return rts, nil
}

func addressFamilyByIP(ip net.IP) uint16 {
	if ip.To4() != nil {
		return antreasyscall.AF_INET
	}
	return antreasyscall.AF_INET6
}

func parseGetNetCmdResult(result string, itemNum int) [][]string {
	scanner := bufio.NewScanner(strings.NewReader(result))
	parsed := [][]string{}
	for scanner.Scan() {
		items := strings.Fields(scanner.Text())
		if len(items) < itemNum {
			// Skip if an empty line or something similar
			continue
		}
		parsed = append(parsed, items)
	}
	return parsed
}

func NewNetNat(netNatName string, subnetCIDR *net.IPNet) error {
	cmd := fmt.Sprintf(`Get-NetNat -Name %s | Select-Object InternalIPInterfaceAddressPrefix | Format-Table -HideTableHeaders`, netNatName)
	if internalNet, err := runCommand(cmd); err != nil {
		if !strings.Contains(err.Error(), "No MSFT_NetNat objects found") {
			klog.ErrorS(err, "Failed to check the existing netnat", "name", netNatName)
			return err
		}
	} else {
		if strings.Contains(internalNet, subnetCIDR.String()) {
			klog.V(4).InfoS("The existing netnat matched the subnet CIDR", "name", internalNet, "subnetCIDR", subnetCIDR.String())
			return nil
		}
		klog.InfoS("Removing the existing NetNat", "name", netNatName, "internalIPInterfaceAddressPrefix", internalNet)
		cmd = fmt.Sprintf("Remove-NetNat -Name %s -Confirm:$false", netNatName)
		if _, err := runCommand(cmd); err != nil {
			klog.ErrorS(err, "Failed to remove the existing netnat", "name", netNatName, "internalIPInterfaceAddressPrefix", internalNet)
			return err
		}
	}
	cmd = fmt.Sprintf(`New-NetNat -Name %s -InternalIPInterfaceAddressPrefix %s`, netNatName, subnetCIDR.String())
	_, err := runCommand(cmd)
	if err != nil {
		klog.ErrorS(err, "Failed to add netnat", "name", netNatName, "internalIPInterfaceAddressPrefix", subnetCIDR.String())
		return err
	}
	return nil
}

func ReplaceNetNatStaticMapping(mapping *NetNatStaticMapping) error {
	staticMappingStr, err := GetNetNatStaticMapping(mapping)
	if err != nil {
		return err
	}
	parsed := parseGetNetCmdResult(staticMappingStr, 6)
	if len(parsed) > 0 {
		items := parsed[0]
		if items[4] == mapping.InternalIP.String() && items[5] == strconv.Itoa(int(mapping.InternalPort)) {
			return nil
		}
		firstCol := strings.Split(items[0], ";")
		id, err := strconv.Atoi(firstCol[1])
		if err != nil {
			return err
		}
		if err := RemoveNetNatStaticMappingByID(mapping.Name, id); err != nil {
			return err
		}
	}
	return AddNetNatStaticMapping(mapping)
}

// GetNetNatStaticMapping checks if a NetNatStaticMapping exists.
func GetNetNatStaticMapping(mapping *NetNatStaticMapping) (string, error) {
	cmd := fmt.Sprintf("Get-NetNatStaticMapping -NatName %s", mapping.Name) +
		fmt.Sprintf("|? ExternalIPAddress -EQ %s", mapping.ExternalIP) +
		fmt.Sprintf("|? ExternalPort -EQ %d", mapping.ExternalPort) +
		fmt.Sprintf("|? Protocol -EQ %s", mapping.Protocol) +
		"| Format-Table -HideTableHeaders"
	staticMappingStr, err := runCommand(cmd)
	if err != nil && !strings.Contains(err.Error(), "No MSFT_NetNatStaticMapping objects found") {
		return "", err
	}
	return staticMappingStr, nil
}

// AddNetNatStaticMapping adds a static mapping to a NAT instance.
func AddNetNatStaticMapping(mapping *NetNatStaticMapping) error {
	cmd := fmt.Sprintf("Add-NetNatStaticMapping -NatName %s -ExternalIPAddress %s -ExternalPort %d -InternalIPAddress %s -InternalPort %d -Protocol %s",
		mapping.Name, mapping.ExternalIP, mapping.ExternalPort, mapping.InternalIP, mapping.InternalPort, mapping.Protocol)
	_, err := runCommand(cmd)
	return err
}

func RemoveNetNatStaticMapping(mapping *NetNatStaticMapping) error {
	staticMappingStr, err := GetNetNatStaticMapping(mapping)
	if err != nil {
		return err
	}
	parsed := parseGetNetCmdResult(staticMappingStr, 6)
	if len(parsed) == 0 {
		return nil
	}

	firstCol := strings.Split(parsed[0][0], ";")
	id, err := strconv.Atoi(firstCol[1])
	if err != nil {
		return err
	}
	return RemoveNetNatStaticMappingByID(mapping.Name, id)
}

func RemoveNetNatStaticMappingByNPLTuples(mapping *NetNatStaticMapping) error {
	staticMappingStr, err := GetNetNatStaticMapping(mapping)
	if err != nil {
		return err
	}
	parsed := parseGetNetCmdResult(staticMappingStr, 6)
	if len(parsed) > 0 {
		items := parsed[0]
		if items[4] == mapping.InternalIP.String() && items[5] == strconv.Itoa(int(mapping.InternalPort)) {
			firstCol := strings.Split(items[0], ";")
			id, err := strconv.Atoi(firstCol[1])
			if err != nil {
				return err
			}
			if err := RemoveNetNatStaticMappingByID(mapping.Name, id); err != nil {
				return err
			}
			return nil
		}
	}
	return nil
}

func RemoveNetNatStaticMappingByID(netNatName string, id int) error {
	cmd := fmt.Sprintf("Remove-NetNatStaticMapping -NatName %s -StaticMappingID %d -Confirm:$false", netNatName, id)
	_, err := runCommand(cmd)
	return err
}

func RemoveNetNatStaticMappingByNAME(netNatName string) error {
	cmd := fmt.Sprintf("Remove-NetNatStaticMapping -NatName %s -Confirm:$false", netNatName)
	_, err := runCommand(cmd)
	return err
}

// GetNetNeighbor gets neighbor cache entries with Get-NetNeighbor.
func GetNetNeighbor(neighbor *Neighbor) ([]Neighbor, error) {
	cmd := fmt.Sprintf("Get-NetNeighbor -InterfaceIndex %d -IPAddress %s | Format-Table -HideTableHeaders", neighbor.LinkIndex, neighbor.IPAddress.String())
	neighborsStr, err := runCommand(cmd)
	if err != nil && !strings.Contains(err.Error(), "No matching MSFT_NetNeighbor objects") {
		return nil, err
	}

	parsed := parseGetNetCmdResult(neighborsStr, 5)
	var neighbors []Neighbor
	for _, items := range parsed {
		idx, err := strconv.Atoi(items[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse the LinkIndex '%s': %v", items[0], err)
		}
		dstIP := net.ParseIP(items[1])
		if err != nil {
			return nil, fmt.Errorf("failed to parse the DestinationIP '%s': %v", items[1], err)
		}
		// Get-NetNeighbor returns LinkLayerAddress like "AA-BB-CC-DD-EE-FF".
		mac, err := net.ParseMAC(strings.ReplaceAll(items[2], "-", ":"))
		if err != nil {
			return nil, fmt.Errorf("failed to parse the Gateway MAC '%s': %v", items[2], err)
		}
		neighbor := Neighbor{
			LinkIndex:        idx,
			IPAddress:        dstIP,
			LinkLayerAddress: mac,
			State:            items[3],
		}
		neighbors = append(neighbors, neighbor)
	}
	return neighbors, nil
}

// NewNetNeighbor creates a new neighbor cache entry with New-NetNeighbor.
func NewNetNeighbor(neighbor *Neighbor) error {
	cmd := fmt.Sprintf("New-NetNeighbor -InterfaceIndex %d -IPAddress %s -LinkLayerAddress %s -State Permanent",
		neighbor.LinkIndex, neighbor.IPAddress, neighbor.LinkLayerAddress)
	_, err := runCommand(cmd)
	return err
}

func RemoveNetNeighbor(neighbor *Neighbor) error {
	cmd := fmt.Sprintf("Remove-NetNeighbor -InterfaceIndex %d -IPAddress %s -Confirm:$false",
		neighbor.LinkIndex, neighbor.IPAddress)
	_, err := runCommand(cmd)
	return err
}

func ReplaceNetNeighbor(neighbor *Neighbor) error {
	neighbors, err := GetNetNeighbor(neighbor)
	if err != nil {
		return err
	}

	if len(neighbors) == 0 {
		if err := NewNetNeighbor(neighbor); err != nil {
			return err
		}
		return nil
	}
	for _, n := range neighbors {
		if n.LinkLayerAddress.String() == neighbor.LinkLayerAddress.String() && n.State == neighbor.State {
			return nil
		}
	}
	if err := RemoveNetNeighbor(neighbor); err != nil {
		return err
	}
	return NewNetNeighbor(neighbor)
}

func VirtualAdapterName(name string) string {
	return fmt.Sprintf("%s (%s)", ContainerVNICPrefix, name)
}

func GetInterfaceConfig(ifName string) (*net.Interface, []*net.IPNet, []interface{}, error) {
	iface, err := netInterfaceByName(ifName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get interface %s: %v", ifName, err)
	}
	addrs, err := GetIPNetsByLink(iface)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get address for interface %s: %v", iface.Name, err)
	}
	rts, err := RouteListFiltered(antreasyscall.AF_UNSPEC, &Route{LinkIndex: iface.Index}, RT_FILTER_IF)
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
		renameErr = renameHostInterface(from, to)
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

func GetVMSwitchInterfaceName() (string, error) {
	cmd := fmt.Sprintf(`Get-VMSwitchTeam -Name "%s" | select NetAdapterInterfaceDescription |  Format-Table -HideTableHeaders`, LocalVMSwitch)
	out, err := runCommand(cmd)
	if err != nil {
		return "", err
	}
	out = strings.TrimSpace(out)
	// Remove the leading and trailing {} brackets
	out = out[1 : len(out)-1]
	cmd = fmt.Sprintf(`Get-NetAdapter -InterfaceDescription "%s" | select Name | Format-Table -HideTableHeaders`, out)
	out, err = runCommand(cmd)
	if err != nil {
		return "", err
	}
	out = strings.TrimSpace(out)
	return out, err
}

func VMSwitchExists() (bool, error) {
	cmd := fmt.Sprintf(`Get-VMSwitch -Name "%s" -ComputerName $(hostname)`, LocalVMSwitch)
	_, err := runCommand(cmd)
	if err == nil {
		return true, nil
	}
	if strings.Contains(err.Error(), fmt.Sprintf(`unable to find a virtual switch with name "%s"`, LocalVMSwitch)) {
		return false, nil
	}
	return false, err
}

// CreateVMSwitch creates a virtual switch and enables openvswitch extension.
// If switch exists and extension is enabled, then it will return no error.
// Otherwise, it will throw an error.
// TODO: Handle for multiple interfaces
func CreateVMSwitch(ifName string) error {
	exists, err := VMSwitchExists()
	if err != nil {
		return err
	}
	if !exists {
		if err = createVMSwitchWithTeaming(LocalVMSwitch, ifName); err != nil {
			return err
		}
	}

	enabled, err := isOVSExtensionEnabled()
	if err != nil {
		return err
	}
	if !enabled {
		if err = enableOVSExtension(); err != nil {
			return err
		}
	}
	return nil
}

func RemoveVMSwitch() error {
	exists, err := VMSwitchExists()
	if err != nil {
		return err
	}
	if exists {
		cmd := fmt.Sprintf(`Remove-VMSwitch -Name "%s" -ComputerName $(hostname) -Force`, LocalVMSwitch)
		_, err = runCommand(cmd)
		if err != nil {
			return err
		}
	}
	return nil
}

func GenHostInterfaceName(upLinkIfName string) string {
	return strings.TrimSuffix(upLinkIfName, bridgedUplinkSuffix)
}

type updateIPInterfaceFunc func(entry *antreasyscall.MibIPInterfaceRow) *antreasyscall.MibIPInterfaceRow

type adapter struct {
	net.Interface
	compartmentID uint32
	flags         uint32
}

func (a *adapter) setMTU(mtu int, family uint16) error {
	if err := a.setIPInterfaceEntry(family, func(entry *antreasyscall.MibIPInterfaceRow) *antreasyscall.MibIPInterfaceRow {
		newEntry := *entry
		newEntry.NlMtu = uint32(mtu)
		return &newEntry
	}); err != nil {
		return fmt.Errorf("unable to set IPInterface with MTU %d: %v", mtu, err)
	}
	return nil
}

func (a *adapter) setForwarding(enabledForwarding bool, family uint16) error {
	if err := a.setIPInterfaceEntry(family, func(entry *antreasyscall.MibIPInterfaceRow) *antreasyscall.MibIPInterfaceRow {
		newEntry := *entry
		newEntry.ForwardingEnabled = enabledForwarding
		return &newEntry
	}); err != nil {
		return fmt.Errorf("unable to enable IPForwarding on net adapter: %v", err)
	}
	return nil
}

func (a *adapter) setIPInterfaceEntry(family uint16, updateFunc updateIPInterfaceFunc) error {
	if a.compartmentID > 1 {
		runtime.LockOSThread()
		defer func() {
			hcsshim.SetCurrentThreadCompartmentId(0)
			runtime.UnlockOSThread()
		}()
		if err := hcsshim.SetCurrentThreadCompartmentId(a.compartmentID); err != nil {
			klog.ErrorS(err, "Failed to change current thread's compartment", "compartment", a.compartmentID)
			return err
		}
	}
	ipInterfaceRow := &antreasyscall.MibIPInterfaceRow{Family: family, Index: uint32(a.Index)}
	if err := antreaNetIO.GetIPInterfaceEntry(ipInterfaceRow); err != nil {
		return fmt.Errorf("unable to get IPInterface entry with Index %d: %v", a.Index, err)
	}
	updatedRow := updateFunc(ipInterfaceRow)
	updatedRow.SitePrefixLength = 0
	return antreaNetIO.SetIPInterfaceEntry(updatedRow)
}

var (
	errInvalidInterfaceName = errors.New("invalid network interface name")
	errNoSuchInterface      = errors.New("no such network interface")
)

func getAdapterInAllCompartmentsByName(name string) (*adapter, error) {
	if name == "" {
		return nil, &net.OpError{Op: "route", Net: "ip+net", Source: nil, Addr: nil, Err: errInvalidInterfaceName}
	}
	adapters, err := getAdaptersByName(name)
	if err != nil {
		return nil, &net.OpError{Op: "route", Net: "ip+net", Source: nil, Addr: nil, Err: err}
	}
	if len(adapters) == 0 {
		return nil, &net.OpError{Op: "route", Net: "ip+net", Source: nil, Addr: nil, Err: errNoSuchInterface}
	}
	return &adapters[0], nil
}

// createVMSwitchWithTeaming creates VMSwitch and enables OVS extension.
// Connection to VM is lost for few seconds
func createVMSwitchWithTeaming(switchName, ifName string) error {
	cmd := fmt.Sprintf(`New-VMSwitch -Name "%s" -NetAdapterName "%s" -EnableEmbeddedTeaming $true -AllowManagementOS $true -ComputerName $(hostname)| Enable-VMSwitchExtension "%s"`, switchName, ifName, ovsExtensionName)
	_, err := runCommand(cmd)
	if err != nil {
		return err
	}
	return nil
}

func enableOVSExtension() error {
	cmd := fmt.Sprintf(`Get-VMSwitch -Name "%s" -ComputerName $(hostname)| Enable-VMSwitchExtension "%s"`, LocalVMSwitch, ovsExtensionName)
	_, err := runCommand(cmd)
	if err != nil {
		return err
	}
	return nil
}

// parseOVSExtensionOutput parses the VM extension output
// and returns the value of Enabled field
func parseOVSExtensionOutput(s string) bool {
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		temp := strings.Fields(scanner.Text())
		line := strings.Join(temp, "")
		if strings.Contains(line, "Enabled") {
			if strings.Contains(line, "True") {
				return true
			}
			return false
		}
	}
	return false
}

func isOVSExtensionEnabled() (bool, error) {
	cmd := fmt.Sprintf(`Get-VMSwitchExtension -VMSwitchName "%s" -ComputerName $(hostname) | ? Id -EQ "%s"`, LocalVMSwitch, OVSExtensionID)
	out, err := runCommand(cmd)
	if err != nil {
		return false, err
	}
	if !strings.Contains(out, ovsExtensionName) {
		return false, fmt.Errorf("open vswitch extension driver is not installed")
	}
	return parseOVSExtensionOutput(out), nil
}

func renameHostInterface(oriName string, newName string) error {
	cmd := fmt.Sprintf(`Get-NetAdapter -Name "%s" | Rename-NetAdapter -NewName "%s"`, oriName, newName)
	_, err := runCommand(cmd)
	return err
}

func getAdaptersByName(name string) ([]adapter, error) {
	aas, err := adapterAddresses()
	if err != nil {
		return nil, err
	}
	var adapters []adapter
	for _, aa := range aas {
		ifName := windows.UTF16PtrToString(aa.FriendlyName)
		if ifName != name {
			continue
		}
		index := aa.IfIndex
		if index == 0 { // ipv6IfIndex is a substitute for ifIndex
			index = aa.Ipv6IfIndex
		}
		ifi := net.Interface{
			Index: int(index),
			Name:  ifName,
		}
		if aa.OperStatus == windows.IfOperStatusUp {
			ifi.Flags |= net.FlagUp
		}
		// For now we need to infer link-layer service capabilities from media types.
		// TODO: use MIB_IF_ROW2.AccessType now that we no longer support Windows XP.
		switch aa.IfType {
		case windows.IF_TYPE_ETHERNET_CSMACD, windows.IF_TYPE_ISO88025_TOKENRING, windows.IF_TYPE_IEEE80211, windows.IF_TYPE_IEEE1394:
			ifi.Flags |= net.FlagBroadcast | net.FlagMulticast
		case windows.IF_TYPE_PPP, windows.IF_TYPE_TUNNEL:
			ifi.Flags |= net.FlagPointToPoint | net.FlagMulticast
		case windows.IF_TYPE_SOFTWARE_LOOPBACK:
			ifi.Flags |= net.FlagLoopback | net.FlagMulticast
		case windows.IF_TYPE_ATM:
			ifi.Flags |= net.FlagBroadcast | net.FlagPointToPoint | net.FlagMulticast // assume all services available; LANE, point-to-point and point-to-multipoint
		}
		if aa.Mtu == 0xffffffff {
			ifi.MTU = -1
		} else {
			ifi.MTU = int(aa.Mtu)
		}
		if aa.PhysicalAddressLength > 0 {
			ifi.HardwareAddr = make(net.HardwareAddr, aa.PhysicalAddressLength)
			copy(ifi.HardwareAddr, aa.PhysicalAddress[:])
		}
		adapter := adapter{
			Interface:     ifi,
			compartmentID: aa.CompartmentId,
			flags:         aa.Flags,
		}
		adapters = append(adapters, adapter)
	}
	return adapters, nil
}

// GAA_FLAG_INCLUDE_ALL_COMPARTMENTS is used in windows.GetAdapterAddresses parameter
// flags to return addresses in all routing compartments.
const GAA_FLAG_INCLUDE_ALL_COMPARTMENTS = 0x00000200

// GAA_FLAG_INCLUDE_ALL_INTERFACES is used in windows.GetAdapterAddresses parameter
// flags to return addresses for all NDIS interfaces.
const GAA_FLAG_INCLUDE_ALL_INTERFACES = 0x00000100

// adapterAddresses returns a list of IpAdapterAddresses structures. The structure
// contains an IP adapter and flattened multiple IP addresses including unicast, anycast
// and multicast addresses.
// This function is copied from go/src/net/interface_windows.go, with a change that flag
// GAA_FLAG_INCLUDE_ALL_COMPARTMENTS is introduced to query interfaces in all compartments,
// and GAA_FLAG_INCLUDE_ALL_INTERFACES is introduced to query all NDIS interfaces even they
// are not configured with any IP addresses, e.g., uplink.
func adapterAddresses() ([]*windows.IpAdapterAddresses, error) {
	flags := uint32(windows.GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_ALL_COMPARTMENTS | GAA_FLAG_INCLUDE_ALL_INTERFACES)
	var b []byte
	l := uint32(15000) // recommended initial size
	for {
		b = make([]byte, l)
		err := getAdaptersAddresses(syscall.AF_UNSPEC, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &l)
		if err == nil {
			if l == 0 {
				return nil, nil
			}
			break
		}
		if err.(syscall.Errno) != syscall.ERROR_BUFFER_OVERFLOW {
			return nil, os.NewSyscallError("getadaptersaddresses", err)
		}
		if l <= uint32(len(b)) {
			return nil, os.NewSyscallError("getadaptersaddresses", err)
		}
	}
	var aas []*windows.IpAdapterAddresses
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); aa != nil; aa = aa.Next {
		aas = append(aas, aa)
	}
	return aas, nil
}
