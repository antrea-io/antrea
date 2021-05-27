//go:build windows
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
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim"
	"github.com/containernetworking/plugins/pkg/ip"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	ps "antrea.io/antrea/pkg/agent/util/powershell"
)

const (
	ContainerVNICPrefix  = "vEthernet"
	HNSNetworkType       = "Transparent"
	LocalHNSNetwork      = "antrea-hnsnetwork"
	OVSExtensionID       = "583CC151-73EC-4A6A-8B47-578297AD7623"
	namedPipePrefix      = `\\.\pipe\`
	commandRetryTimeout  = 5 * time.Second
	commandRetryInterval = time.Second

	MetricDefault = 256
	MetricHigh    = 50
)

type Route struct {
	LinkIndex         int
	DestinationSubnet *net.IPNet
	GatewayAddress    net.IP
	RouteMetric       int
}

func (r Route) String() string {
	return fmt.Sprintf("LinkIndex: %d, DestinationSubnet: %s, GatewayAddress: %s, RouteMetric: %d",
		r.LinkIndex, r.DestinationSubnet, r.GatewayAddress, r.RouteMetric)
}

type Neighbor struct {
	LinkIndex        int
	IPAddress        net.IP
	LinkLayerAddress net.HardwareAddr
}

func (n Neighbor) String() string {
	return fmt.Sprintf("LinkIndex: %d, IPAddress: %s, LinkLayerAddress: %s", n.LinkIndex, n.IPAddress, n.LinkLayerAddress)
}

func GetNSPath(containerNetNS string) (string, error) {
	return containerNetNS, nil
}

// IsVirtualAdapter checks if the provided adapter is virtual.
func IsVirtualAdapter(name string) (bool, error) {
	cmd := fmt.Sprintf(`Get-NetAdapter -InterfaceAlias "%s" | Select-Object -Property Virtual | Format-Table -HideTableHeaders`, name)
	out, err := ps.RunCommand(cmd)
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
	out, err := ps.RunCommand(cmd)
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
		if _, err := ps.RunCommand(cmd); err != nil {
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
	_, err := ps.RunCommand(cmd)
	// If the address already exists, ignore the error.
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}

// RemoveInterfaceAddress removes IPAddress from the specified interface.
func RemoveInterfaceAddress(ifaceName string, ipAddr net.IP) error {
	cmd := fmt.Sprintf(`Remove-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -Confirm:$false`, ifaceName, ipAddr.String())
	_, err := ps.RunCommand(cmd)
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
	_, err := ps.RunCommand(cmd)
	// If the address already exists, ignore the error.
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}

// EnableIPForwarding enables the IP interface to forward packets that arrive on this interface to other interfaces.
func EnableIPForwarding(ifaceName string) error {
	cmd := fmt.Sprintf(`Set-NetIPInterface -InterfaceAlias "%s" -Forwarding Enabled`, ifaceName)
	_, err := ps.RunCommand(cmd)
	return err
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
		_, err = ps.RunCommand(cmd)
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
	_, err := ps.RunCommand(cmd)
	return err
}

// WindowsHyperVEnabled checks if the Hyper-V is enabled on the host.
// Hyper-V feature contains multiple components/sub-features. According to the
// test, OVS requires "Microsoft-Hyper-V" feature to be enabled.
func WindowsHyperVEnabled() (bool, error) {
	cmd := "$(Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).State"
	result, err := ps.RunCommand(cmd)
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
		}
		return err
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
	ifaceAddrs, err := iface.Addrs()
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
func PrepareHNSNetwork(subnetCIDR *net.IPNet, nodeIPNet *net.IPNet, uplinkAdapter *net.Interface) error {
	klog.InfoS("Creating HNSNetwork", "name", LocalHNSNetwork, "subnet", subnetCIDR, "nodeIP", nodeIPNet, "adapter", uplinkAdapter)
	hnsNet, err := CreateHNSNetwork(LocalHNSNetwork, subnetCIDR, nodeIPNet, uplinkAdapter)
	if err != nil {
		return fmt.Errorf("error creating HNSNetwork: %v", err)
	}

	// Enable OVS Extension on the HNS Network. If an error occurs, delete the HNS Network and return the error.
	if err = enableHNSOnOVS(hnsNet); err != nil {
		hnsNet.Delete()
		return err
	}

	if err = EnableRSCOnVSwitch(LocalHNSNetwork); err != nil {
		return err
	}

	klog.Infof("Created HNSNetwork with name %s id %s", hnsNet.Name, hnsNet.Id)
	return nil
}

// EnableRSCOnVSwitch enables RSC in the vSwitch to reduce host CPU utilization and increase throughput for virtual
// workloads by coalescing multiple TCP segments into fewer, but larger segments.
func EnableRSCOnVSwitch(vSwitch string) error {
	cmd := fmt.Sprintf("Get-VMSwitch -Name %s | Select-Object -Property SoftwareRscEnabled | Format-Table -HideTableHeaders", vSwitch)
	stdout, err := ps.RunCommand(cmd)
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
	cmd = fmt.Sprintf("Set-VMSwitch -Name %s -EnableSoftwareRsc $True", vSwitch)
	_, err = ps.RunCommand(cmd)
	if err != nil {
		return err
	}
	klog.Infof("Enabled Receive Segment Coalescing (RSC) for vSwitch %s", vSwitch)
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

// GetDefaultGatewayByInterfaceIndex returns the default gateway configured on the specified interface.
func GetDefaultGatewayByInterfaceIndex(ifIndex int) (string, error) {
	cmd := fmt.Sprintf("$(Get-NetRoute -InterfaceIndex %d -DestinationPrefix 0.0.0.0/0 ).NextHop", ifIndex)
	defaultGW, err := ps.RunCommand(cmd)
	if err != nil {
		return "", err
	}
	defaultGW = strings.ReplaceAll(defaultGW, "\r\n", "")
	return defaultGW, nil
}

// GetDNServersByInterfaceIndex returns the DNS servers configured on the specified interface.
func GetDNServersByInterfaceIndex(ifIndex int) (string, error) {
	cmd := fmt.Sprintf("$(Get-DnsClientServerAddress -InterfaceIndex %d -AddressFamily IPv4).ServerAddresses", ifIndex)
	dnsServers, err := ps.RunCommand(cmd)
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
	if _, err := ps.RunCommand(cmd); err != nil {
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
	if _, err := ps.RunCommand(cmd); err != nil {
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
	_, err := ps.RunCommand(cmd)
	return err
}

func NewNetRoute(route *Route) error {
	cmd := fmt.Sprintf("New-NetRoute -InterfaceIndex %v -DestinationPrefix %v -NextHop %v -RouteMetric %d -Verbose",
		route.LinkIndex, route.DestinationSubnet.String(), route.GatewayAddress.String(), route.RouteMetric)
	_, err := ps.RunCommand(cmd)
	return err
}

func RemoveNetRoute(route *Route) error {
	cmd := fmt.Sprintf("Remove-NetRoute -InterfaceIndex %v -DestinationPrefix %v -Verbose -Confirm:$false",
		route.LinkIndex, route.DestinationSubnet.String())
	_, err := ps.RunCommand(cmd)
	return err
}

func ReplaceNetRoute(route *Route) error {
	rs, err := GetNetRoutes(route.LinkIndex, route.DestinationSubnet)
	if err != nil {
		return err
	}

	if len(rs) == 0 {
		if err := NewNetRoute(route); err != nil {
			return err
		}
		return nil
	}
	found := false
	for _, r := range rs {
		if r.GatewayAddress.Equal(route.GatewayAddress) {
			found = true
			break
		}
	}
	if found {
		return nil
	}
	if err := RemoveNetRoute(route); err != nil {
		return err
	}
	if err := NewNetRoute(route); err != nil {
		return err
	}
	return nil
}

func GetNetRoutes(linkIndex int, dstSubnet *net.IPNet) ([]Route, error) {
	cmd := fmt.Sprintf("Get-NetRoute -InterfaceIndex %d -DestinationPrefix %s -ErrorAction Ignore | Format-Table -HideTableHeaders",
		linkIndex, dstSubnet.String())
	return getNetRoutes(cmd)
}

func GetNetRoutesAll() ([]Route, error) {
	cmd := "Get-NetRoute -ErrorAction Ignore | Format-Table -HideTableHeaders"
	return getNetRoutes(cmd)
}

func getNetRoutes(cmd string) ([]Route, error) {
	routesStr, _ := ps.RunCommand(cmd)
	parsed := parseGetNetCmdResult(routesStr, 6)
	var routes []Route
	for _, items := range parsed {
		idx, err := strconv.Atoi(items[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse the LinkIndex '%s': %v", items[0], err)
		}
		_, dstSubnet, err := net.ParseCIDR(items[1])
		if err != nil {
			return nil, fmt.Errorf("failed to parse the DestinationSubnet '%s': %v", items[1], err)
		}
		gw := net.ParseIP(items[2])
		metric, err := strconv.Atoi(items[3])
		if err != nil {
			return nil, fmt.Errorf("failed to parse the RouteMetric '%s': %v", items[3], err)
		}
		route := Route{
			LinkIndex:         idx,
			DestinationSubnet: dstSubnet,
			GatewayAddress:    gw,
			RouteMetric:       metric,
		}
		routes = append(routes, route)
	}
	return routes, nil
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

func CreateNetNatOnHost(subnetCIDR *net.IPNet) error {
	netNatName := "antrea-nat"
	cmd := fmt.Sprintf(`Get-NetNat -Name %s | Select-Object InternalIPInterfaceAddressPrefix | Format-Table -HideTableHeaders`, netNatName)
	if internalNet, err := ps.RunCommand(cmd); err != nil {
		if !strings.Contains(err.Error(), "No MSFT_NetNat objects found") {
			klog.ErrorS(err, "Failed to check the existing netnat", "name", netNatName)
			return err
		}
	} else {
		if strings.Contains(internalNet, subnetCIDR.String()) {
			return nil
		}
		klog.InfoS("Removing the existing netnat", "name", netNatName, "internalIPInterfaceAddressPrefix", internalNet)
		cmd = fmt.Sprintf("Remove-NetNat -Name %s -Confirm:$false", netNatName)
		if _, err := ps.RunCommand(cmd); err != nil {
			klog.ErrorS(err, "Failed to remove the existing netnat", "name", netNatName, "internalIPInterfaceAddressPrefix", internalNet)
			return err
		}
	}
	cmd = fmt.Sprintf(`New-NetNat -Name %s -InternalIPInterfaceAddressPrefix %s`, netNatName, subnetCIDR.String())
	_, err := ps.RunCommand(cmd)
	if err != nil {
		klog.ErrorS(err, "Failed to add netnat", "name", netNatName, "internalIPInterfaceAddressPrefix", subnetCIDR.String())
		return err
	}
	return nil
}

// GetNetNeighbor gets neighbor cache entries with Get-NetNeighbor.
func GetNetNeighbor(neighbor *Neighbor) ([]Neighbor, error) {
	cmd := fmt.Sprintf("Get-NetNeighbor -InterfaceIndex %d -IPAddress %s -ErrorAction Ignore | Format-Table -HideTableHeaders", neighbor.LinkIndex, neighbor.IPAddress.String())
	neighborsStr, err := ps.RunCommand(cmd)
	if err != nil {
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
		// Get-NetRoute returns LinkLayerAddress like "AA-BB-CC-DD-EE-FF".
		mac, err := net.ParseMAC(strings.ReplaceAll(items[2], "-", ":"))
		if err != nil {
			return nil, fmt.Errorf("failed to parse the Gateway MAC '%s': %v", items[2], err)
		}
		neighbor := Neighbor{
			LinkIndex:        idx,
			IPAddress:        dstIP,
			LinkLayerAddress: mac,
		}
		neighbors = append(neighbors, neighbor)
	}
	return neighbors, nil
}

// NewNetNeighbor creates a new neighbor cache entry with New-NetNeighbor.
func NewNetNeighbor(neighbor *Neighbor) error {
	cmd := fmt.Sprintf("New-NetNeighbor -InterfaceIndex %d -IPAddress %s -LinkLayerAddress %s -State Permanent",
		neighbor.LinkIndex, neighbor.IPAddress, neighbor.LinkLayerAddress)
	_, err := ps.RunCommand(cmd)
	return err
}

// SetNetNeighbor modifies a neighbor cache entry with Set-NetNeighbor.
func SetNetNeighbor(neighbor *Neighbor) error {
	cmd := fmt.Sprintf("Set-NetNeighbor -InterfaceIndex %d -IPAddress %s -LinkLayerAddress %s -State Permanent",
		neighbor.LinkIndex, neighbor.IPAddress, neighbor.LinkLayerAddress)
	_, err := ps.RunCommand(cmd)
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
	found := false
	for _, n := range neighbors {
		if n.LinkLayerAddress.String() == neighbor.LinkLayerAddress.String() {
			found = true
			break
		}
	}
	if found {
		return nil
	}
	if err := SetNetNeighbor(neighbor); err != nil {
		return err
	}
	return nil
}
