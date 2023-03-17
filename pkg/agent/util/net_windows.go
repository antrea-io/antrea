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
	"bytes"
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
	ovsExtensionName     = "Open vSwitch Extension"
	namedPipePrefix      = `\\.\pipe\`
	commandRetryTimeout  = 5 * time.Second
	commandRetryInterval = time.Second

	MetricDefault = 256
	MetricHigh    = 50

	AntreaNatName = "antrea-nat"
	LocalVMSwitch = "antrea-switch"
)

var (
	// Declared variables which are meant to be overridden for testing.
	runCommand          = ps.RunCommand
	getHNSNetworkByName = hcsshim.GetHNSNetworkByName
	hnsNetworkRequest   = hcsshim.HNSNetworkRequest
	hnsNetworkCreate    = (*hcsshim.HNSNetwork).Create
	hnsNetworkDelete    = (*hcsshim.HNSNetwork).Delete
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
	State            string
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
	if err := wait.PollImmediate(commandRetryInterval, commandRetryTimeout, func() (done bool, err error) {
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
	cmd := fmt.Sprintf(`Set-NetIPInterface -InterfaceAlias "%s" -Forwarding Enabled`, ifaceName)
	_, err := runCommand(cmd)
	return err
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

	adapter, ipFound, err := adapterIPExists(nodeIPNet.IP, uplinkAdapter.HardwareAddr, ContainerVNICPrefix)
	if err != nil {
		return err
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
	cmd := fmt.Sprintf("$(Get-NetRoute -InterfaceIndex %d -DestinationPrefix 0.0.0.0/0 ).NextHop", ifIndex)
	defaultGW, err := runCommand(cmd)
	if err != nil {
		return "", err
	}
	defaultGW = strings.ReplaceAll(defaultGW, "\r\n", "")
	return defaultGW, nil
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
	if _, err := netInterfaceByName(ifaceName); err == nil {
		return true
	}
	// Some kinds of interfaces cannot be retrieved by "net.InterfaceByName" such as
	// container vnic.
	// So if an interface cannot be found by above function, use powershell command
	// "Get-NetAdapter" to check if it exists.
	cmd := fmt.Sprintf(`Get-NetAdapter -InterfaceAlias "%s"`, ifaceName)
	if _, err := runCommand(cmd); err != nil {
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
	_, err := runCommand(cmd)
	return err
}

func NewNetRoute(route *Route) error {
	cmd := fmt.Sprintf("New-NetRoute -InterfaceIndex %v -DestinationPrefix %v -NextHop %v -RouteMetric %d -Verbose",
		route.LinkIndex, route.DestinationSubnet.String(), route.GatewayAddress.String(), route.RouteMetric)
	_, err := runCommand(cmd)
	return err
}

func RemoveNetRoute(route *Route) error {
	cmd := fmt.Sprintf("Remove-NetRoute -InterfaceIndex %v -DestinationPrefix %v -Verbose -Confirm:$false",
		route.LinkIndex, route.DestinationSubnet.String())
	_, err := runCommand(cmd)
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

	for _, r := range rs {
		if r.GatewayAddress.Equal(route.GatewayAddress) {
			return nil
		}
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
	routesStr, _ := runCommand(cmd)
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

func NewNetNat(netNatName string, subnetCIDR *net.IPNet) error {
	cmd := fmt.Sprintf(`Get-NetNat -Name %s | Select-Object InternalIPInterfaceAddressPrefix | Format-Table -HideTableHeaders`, netNatName)
	if internalNet, err := runCommand(cmd); err != nil {
		if !strings.Contains(err.Error(), "No MSFT_NetNat objects found") {
			klog.ErrorS(err, "Failed to check the existing netnat", "name", netNatName)
			return err
		}
	} else {
		if strings.Contains(internalNet, subnetCIDR.String()) {
			klog.InfoS("existing netnat in CIDR", "name", internalNet, "subnetCIDR", subnetCIDR.String())
			return nil
		}
		klog.InfoS("Removing the existing netnat", "name", netNatName, "internalIPInterfaceAddressPrefix", internalNet)
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

func ReplaceNetNatStaticMapping(netNatName string, externalIPAddr string, externalPort uint16, internalIPAddr string, internalPort uint16, proto string) error {
	staticMappingStr, err := GetNetNatStaticMapping(netNatName, externalIPAddr, externalPort, proto)
	if err != nil {
		return err
	}
	parsed := parseGetNetCmdResult(staticMappingStr, 6)
	if len(parsed) > 0 {
		items := parsed[0]
		if items[4] == internalIPAddr && items[5] == strconv.Itoa(int(internalPort)) {
			return nil
		}
		firstCol := strings.Split(items[0], ";")
		id, err := strconv.Atoi(firstCol[1])
		if err != nil {
			return err
		}
		if err := RemoveNetNatStaticMappingByID(netNatName, id); err != nil {
			return err
		}
	}
	return AddNetNatStaticMapping(netNatName, externalIPAddr, externalPort, internalIPAddr, internalPort, proto)
}

// GetNetNatStaticMapping checks if a NetNatStaticMapping exists.
func GetNetNatStaticMapping(netNatName string, externalIPAddr string, externalPort uint16, proto string) (string, error) {
	cmd := fmt.Sprintf("Get-NetNatStaticMapping -NatName %s", netNatName) +
		fmt.Sprintf("|? ExternalIPAddress -EQ %s", externalIPAddr) +
		fmt.Sprintf("|? ExternalPort -EQ %d", externalPort) +
		fmt.Sprintf("|? Protocol -EQ %s", proto) +
		"| Format-Table -HideTableHeaders"
	staticMappingStr, err := runCommand(cmd)
	if err != nil && !strings.Contains(err.Error(), "No MSFT_NetNatStaticMapping objects found") {
		return "", err
	}
	return staticMappingStr, nil
}

// AddNetNatStaticMapping adds a static mapping to a NAT instance.
func AddNetNatStaticMapping(netNatName string, externalIPAddr string, externalPort uint16, internalIPAddr string, internalPort uint16, proto string) error {
	cmd := fmt.Sprintf("Add-NetNatStaticMapping -NatName %s -ExternalIPAddress %s -ExternalPort %d -InternalIPAddress %s -InternalPort %d -Protocol %s",
		netNatName, externalIPAddr, externalPort, internalIPAddr, internalPort, proto)
	_, err := runCommand(cmd)
	return err
}

func RemoveNetNatStaticMapping(netNatName string, externalIPAddr string, externalPort uint16, proto string) error {
	staticMappingStr, err := GetNetNatStaticMapping(netNatName, externalIPAddr, externalPort, proto)
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
	return RemoveNetNatStaticMappingByID(netNatName, id)
}

func RemoveNetNatStaticMappingByNPLTuples(netNatName string, externalIPAddr string, externalPort uint16, internalIPAddr string, internalPort uint16, proto string) error {
	staticMappingStr, err := GetNetNatStaticMapping(netNatName, externalIPAddr, externalPort, proto)
	if err != nil {
		return err
	}
	parsed := parseGetNetCmdResult(staticMappingStr, 6)
	if len(parsed) > 0 {
		items := parsed[0]
		if items[4] == internalIPAddr && items[5] == strconv.Itoa(int(internalPort)) {
			firstCol := strings.Split(items[0], ";")
			id, err := strconv.Atoi(firstCol[1])
			if err != nil {
				return err
			}
			if err := RemoveNetNatStaticMappingByID(netNatName, id); err != nil {
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
		// Get-NetRoute returns LinkLayerAddress like "AA-BB-CC-DD-EE-FF".
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
	routes, err := getRoutesOnInterface(iface.Index)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get routes for interface index %d: %v", iface.Index, err)
	}
	return iface, addrs, routes, nil
}

func RenameInterface(from, to string) error {
	var renameErr error
	pollErr := wait.Poll(time.Millisecond*100, time.Second, func() (done bool, err error) {
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

func getRoutesOnInterface(linkIndex int) ([]interface{}, error) {
	cmd := fmt.Sprintf("Get-NetRoute -InterfaceIndex %d -ErrorAction Ignore | Format-Table -HideTableHeaders", linkIndex)
	rs, err := getNetRoutes(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get routes: %v", err)
	}
	var routes []interface{}
	for _, r := range rs {
		// Skip the routes automatically generated by Windows host when adding IP address on the network adapter.
		if r.GatewayAddress != nil && r.GatewayAddress.IsUnspecified() {
			continue
		}
		routes = append(routes, r)
	}
	return routes, nil
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
