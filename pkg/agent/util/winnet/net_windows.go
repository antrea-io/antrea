//go:build windows
// +build windows

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
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Microsoft/hcsshim"
	"golang.org/x/sys/windows"
	"k8s.io/klog/v2"

	ps "antrea.io/antrea/pkg/agent/util/powershell"
	antreasyscall "antrea.io/antrea/pkg/agent/util/syscall"
	iputil "antrea.io/antrea/pkg/util/ip"
)

const (
	ContainerVNICPrefix = "vEthernet"
	OVSExtensionID      = "583CC151-73EC-4A6A-8B47-578297AD7623"
	ovsExtensionName    = "Open vSwitch Extension"

	MetricDefault = 256
	MetricHigh    = 50

	// Filter masks are used to indicate the attributes used for route filtering.
	RT_FILTER_IF uint64 = 1 << (1 + iota)
	RT_FILTER_METRIC
	RT_FILTER_DST
	RT_FILTER_GW

	// IP_ADAPTER_DHCP_ENABLED is defined in the Win32 API document.
	// https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
	IP_ADAPTER_DHCP_ENABLED = 0x00000004

	// GAA_FLAG_INCLUDE_ALL_COMPARTMENTS is used in windows.GetAdapterAddresses parameter
	// flags to return addresses in all routing compartments.
	GAA_FLAG_INCLUDE_ALL_COMPARTMENTS = 0x00000200

	// GAA_FLAG_INCLUDE_ALL_INTERFACES is used in windows.GetAdapterAddresses parameter
	// flags to return addresses for all NDIS interfaces.
	GAA_FLAG_INCLUDE_ALL_INTERFACES = 0x00000100
)

type Handle struct{}

var (
	// Declared variables which are meant to be overridden for testing.
	antreaNetIO          = antreasyscall.NewNetIO()
	getAdaptersAddresses = windows.GetAdaptersAddresses
	runCommand           = ps.RunCommand
)

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

// IsVirtualNetAdapter checks if the provided network adapter is virtual.
func (h *Handle) IsVirtualNetAdapter(adapterName string) (bool, error) {
	cmd := fmt.Sprintf(`Get-NetAdapter -InterfaceAlias "%s" | Select-Object -Property Virtual | Format-Table -HideTableHeaders`, adapterName)
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

// IsNetAdapterStatusUp checks if the status of the provided network adapter is UP.
func (h *Handle) IsNetAdapterStatusUp(adapterName string) (bool, error) {
	cmd := fmt.Sprintf(`Get-NetAdapter -InterfaceAlias "%s" | Select-Object -Property Status | Format-Table -HideTableHeaders`, adapterName)
	out, err := runCommand(cmd)
	if err != nil {
		return false, err
	}
	status := strings.TrimSpace(out)
	if !strings.EqualFold(status, "Up") {
		return false, nil
	}
	return true, nil
}

// EnableNetAdapter sets the specified network adapter status as UP.
func (h *Handle) EnableNetAdapter(adapterName string) error {
	cmd := fmt.Sprintf(`Enable-NetAdapter -InterfaceAlias "%s"`, adapterName)
	if _, err := runCommand(cmd); err != nil {
		return err
	}
	return nil
}

// AddNetAdapterIPAddress adds the specified IP address on the specified network adapter.
func (h *Handle) AddNetAdapterIPAddress(adapterName string, ipConfig *net.IPNet, gateway string) error {
	ipStr := strings.Split(ipConfig.String(), "/")
	cmd := fmt.Sprintf(`New-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -PrefixLength %s`, adapterName, ipStr[0], ipStr[1])
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

// RemoveNetAdapterIPAddress removes the specified IP address from the specified network adapter.
func (h *Handle) RemoveNetAdapterIPAddress(adapterName string, ipAddr net.IP) error {
	cmd := fmt.Sprintf(`Remove-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -Confirm:$false`, adapterName, ipAddr.String())
	_, err := runCommand(cmd)
	// If the address does not exist, ignore the error.
	if err != nil && !strings.Contains(err.Error(), "No matching") {
		return err
	}
	return nil
}

// EnableIPForwarding enables the network adapter to forward IP packets that arrive at this network adapter to other ones.
func (h *Handle) EnableIPForwarding(adapterName string) error {
	adapter, err := getAdapterInAllCompartmentsByName(adapterName)
	if err != nil {
		return fmt.Errorf("unable to find NetAdapter on host in all compartments with name %s: %w", adapterName, err)
	}
	return adapter.setForwarding(true, antreasyscall.AF_INET)
}

func (h *Handle) RenameVMNetworkAdapter(networkName, macStr, newName string, renameNetAdapter bool) error {
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
		if err := h.RenameNetAdapter(oriNetAdapterName, newName); err != nil {
			return err
		}
	}
	return nil
}

// EnableRSCOnVSwitch enables RSC in the vSwitch to reduce host CPU utilization and increase throughput for virtual
// workloads by coalescing multiple TCP segments into fewer, but larger segments.
func (h *Handle) EnableRSCOnVSwitch(vSwitch string) error {
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

// GetDefaultGatewayByNetAdapterIndex returns the default gateway configured on the specified network adapter.
func (h *Handle) GetDefaultGatewayByNetAdapterIndex(adapterIndex int) (string, error) {
	ip, defaultDestination, _ := net.ParseCIDR("0.0.0.0/0")
	family := AddressFamilyByIP(ip)
	filter := &Route{
		LinkIndex:         adapterIndex,
		DestinationSubnet: defaultDestination,
	}
	routes, err := h.RouteListFiltered(family, filter, RT_FILTER_IF|RT_FILTER_DST)
	if err != nil {
		return "", err
	}
	if len(routes) == 0 {
		return "", nil
	}
	return routes[0].GatewayAddress.String(), nil
}

// GetDNServersByNetAdapterIndex returns the DNS servers configured on the specified network adapter.
func (h *Handle) GetDNServersByNetAdapterIndex(adapterIndex int) (string, error) {
	cmd := fmt.Sprintf("$(Get-DnsClientServerAddress -InterfaceIndex %d -AddressFamily IPv4).ServerAddresses", adapterIndex)
	dnsServers, err := runCommand(cmd)
	if err != nil {
		return "", err
	}
	dnsServers = strings.ReplaceAll(dnsServers, "\r\n", ",")
	dnsServers = strings.TrimRight(dnsServers, ",")
	return dnsServers, nil
}

// SetNetAdapterDNSServers configures DNS servers on network adapter.
func (h *Handle) SetNetAdapterDNSServers(adapterName, dnsServers string) error {
	cmd := fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias "%s" -ServerAddresses "%s"`, adapterName, dnsServers)
	if _, err := runCommand(cmd); err != nil {
		return err
	}
	return nil
}

func (h *Handle) NetAdapterExists(adapterName string) bool {
	_, err := getAdapterInAllCompartmentsByName(adapterName)
	if err != nil {
		return false
	}
	return true
}

// IsNetAdapterIPv4DHCPEnabled returns the IPv4 DHCP status on the specified network adapter.
func (h *Handle) IsNetAdapterIPv4DHCPEnabled(adapterName string) (bool, error) {
	adapter, err := getAdapterInAllCompartmentsByName(adapterName)
	if err != nil {
		return false, err
	}
	ipv4DHCP := adapter.flags&IP_ADAPTER_DHCP_ENABLED != 0
	return ipv4DHCP, nil
}

// SetNetAdapterMTU configures network adapter MTU on host for Pods. MTU change cannot be realized with HNSEndpoint because
// there's no MTU field in HNSEndpoint:
// https://github.com/Microsoft/hcsshim/blob/4a468a6f7ae547974bc32911395c51fb1862b7df/internal/hns/hnsendpoint.go#L12
func (h *Handle) SetNetAdapterMTU(adapterName string, mtu int) error {
	adapter, err := getAdapterInAllCompartmentsByName(adapterName)
	if err != nil {
		return fmt.Errorf("unable to find NetAdapter on host in all compartments with name %s: %w", adapterName, err)
	}
	return adapter.setMTU(mtu, antreasyscall.AF_INET)
}

func AddressFamilyByIP(ip net.IP) uint16 {
	if ip.To4() != nil {
		return antreasyscall.AF_INET
	}
	return antreasyscall.AF_INET6
}

func VirtualAdapterName(name string) string {
	return fmt.Sprintf("%s (%s)", ContainerVNICPrefix, name)
}

func toMibIPForwardRow(r *Route) *antreasyscall.MibIPForwardRow {
	row := antreasyscall.NewIPForwardRow()
	row.DestinationPrefix = *antreasyscall.NewAddressPrefixFromIPNet(r.DestinationSubnet)
	row.NextHop = *antreasyscall.NewRawSockAddrInetFromIP(r.GatewayAddress)
	row.Metric = uint32(r.RouteMetric)
	row.Index = uint32(r.LinkIndex)
	return row
}

func (h *Handle) AddNetRoute(route *Route) error {
	if route == nil {
		return nil
	}
	row := toMibIPForwardRow(route)
	if err := antreaNetIO.CreateIPForwardEntry(row); err != nil {
		return fmt.Errorf("failed to create new IPForward row: %w", err)
	}
	return nil
}

func (h *Handle) RemoveNetRoute(route *Route) error {
	if route == nil || route.DestinationSubnet == nil {
		return nil
	}
	family := AddressFamilyByIP(route.DestinationSubnet.IP)
	rows, err := antreaNetIO.ListIPForwardRows(family)
	if err != nil {
		return fmt.Errorf("unable to list Windows IPForward rows: %w", err)
	}
	for i := range rows {
		row := rows[i]
		if row.DestinationPrefix.EqualsTo(route.DestinationSubnet) && row.Index == uint32(route.LinkIndex) && row.NextHop.IP().Equal(route.GatewayAddress) {
			if err := antreaNetIO.DeleteIPForwardEntry(&row); err != nil {
				return fmt.Errorf("failed to delete existing route with nextHop %s: %w", route.GatewayAddress, err)
			}
		}
	}
	return nil
}

func (h *Handle) ReplaceNetRoute(route *Route) error {
	if route == nil || route.DestinationSubnet == nil {
		return nil
	}
	family := AddressFamilyByIP(route.DestinationSubnet.IP)
	rows, err := antreaNetIO.ListIPForwardRows(family)
	if err != nil {
		return fmt.Errorf("unable to list Windows IPForward rows: %w", err)
	}
	for i := range rows {
		row := rows[i]
		if row.DestinationPrefix.EqualsTo(route.DestinationSubnet) && row.Index == uint32(route.LinkIndex) {
			if row.NextHop.IP().Equal(route.GatewayAddress) {
				return nil
			} else {
				if err := antreaNetIO.DeleteIPForwardEntry(&row); err != nil {
					return fmt.Errorf("failed to delete existing route with nextHop %s: %w", route.GatewayAddress, err)
				}
			}
		}
	}
	return h.AddNetRoute(route)
}

func (h *Handle) RouteListFiltered(family uint16, filter *Route, filterMask uint64) ([]Route, error) {
	rows, err := antreaNetIO.ListIPForwardRows(family)
	if err != nil {
		return nil, fmt.Errorf("unable to list Windows IPForward rows: %w", err)
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

func parseCmdResult(result string, columns int) [][]string {
	scanner := bufio.NewScanner(strings.NewReader(result))
	parsed := [][]string{}
	for scanner.Scan() {
		items := strings.Fields(scanner.Text())
		if len(items) < columns {
			// Skip if an empty line or something similar
			continue
		}
		parsed = append(parsed, items)
	}
	return parsed
}

func (h *Handle) AddNetNat(netNatName string, subnetCIDR *net.IPNet) error {
	cmd := fmt.Sprintf("Get-NetNat -Name %s | Select-Object InternalIPInterfaceAddressPrefix | Format-Table -HideTableHeaders", netNatName)
	if internalNet, err := runCommand(cmd); err != nil {
		if !strings.Contains(err.Error(), "No MSFT_NetNat objects found") {
			return fmt.Errorf("failed to check the existing netnat '%s': %w", netNatName, err)
		}
	} else {
		if strings.Contains(internalNet, subnetCIDR.String()) {
			klog.V(4).InfoS("The existing netnat matched the subnet CIDR", "name", internalNet, "subnetCIDR", subnetCIDR.String())
			return nil
		}
		klog.InfoS("Removing the existing NetNat", "name", netNatName, "internalIPInterfaceAddressPrefix", internalNet)
		cmd = fmt.Sprintf("Remove-NetNat -Name %s -Confirm:$false", netNatName)
		if _, err := runCommand(cmd); err != nil {
			return fmt.Errorf("failed to remove the existing netnat '%s' with internalIPInterfaceAddressPrefix '%s': %w", netNatName, internalNet, err)
		}
	}
	cmd = fmt.Sprintf("New-NetNat -Name %s -InternalIPInterfaceAddressPrefix %s", netNatName, subnetCIDR.String())
	_, err := runCommand(cmd)
	if err != nil {
		return fmt.Errorf("failed to add netnat '%s' with internalIPInterfaceAddressPrefix '%s': %w", netNatName, subnetCIDR.String(), err)
	}
	return nil
}

func (h *Handle) ReplaceNetNatStaticMapping(mapping *NetNatStaticMapping) error {
	staticMappingStr, err := getNetNatStaticMapping(mapping)
	if err != nil {
		return err
	}
	parsed := parseCmdResult(staticMappingStr, 6)
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
		if err := removeNetNatStaticMappingByID(mapping.Name, id); err != nil {
			return err
		}
	}
	return h.AddNetNatStaticMapping(mapping)
}

// getNetNatStaticMapping checks if a NetNatStaticMapping exists.
func getNetNatStaticMapping(mapping *NetNatStaticMapping) (string, error) {
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
func (h *Handle) AddNetNatStaticMapping(mapping *NetNatStaticMapping) error {
	cmd := fmt.Sprintf("Add-NetNatStaticMapping -NatName %s -ExternalIPAddress %s -ExternalPort %d -InternalIPAddress %s -InternalPort %d -Protocol %s",
		mapping.Name, mapping.ExternalIP, mapping.ExternalPort, mapping.InternalIP, mapping.InternalPort, mapping.Protocol)
	_, err := runCommand(cmd)
	return err
}

// RemoveNetNatStaticMapping removes a static mapping from a NetNat instance.
func (h *Handle) RemoveNetNatStaticMapping(mapping *NetNatStaticMapping) error {
	staticMappingStr, err := getNetNatStaticMapping(mapping)
	if err != nil {
		return err
	}
	parsed := parseCmdResult(staticMappingStr, 6)
	if len(parsed) == 0 {
		return nil
	}

	firstCol := strings.Split(parsed[0][0], ";")
	id, err := strconv.Atoi(firstCol[1])
	if err != nil {
		return err
	}
	return removeNetNatStaticMappingByID(mapping.Name, id)
}

func removeNetNatStaticMappingByID(netNatName string, id int) error {
	cmd := fmt.Sprintf("Remove-NetNatStaticMapping -NatName %s -StaticMappingID %d -Confirm:$false", netNatName, id)
	_, err := runCommand(cmd)
	return err
}

// RemoveNetNatStaticMappingsByNetNat removes all static mappings from a NetNat instance.
func (h *Handle) RemoveNetNatStaticMappingsByNetNat(netNatName string) error {
	cmd := fmt.Sprintf("Remove-NetNatStaticMapping -NatName %s -Confirm:$false", netNatName)
	_, err := runCommand(cmd)
	return err
}

// getNetNeighbor gets neighbor cache entries with Get-NetNeighbor.
func getNetNeighbor(neighbor *Neighbor) ([]Neighbor, error) {
	cmd := fmt.Sprintf("Get-NetNeighbor -InterfaceIndex %d -IPAddress %s | Format-Table -HideTableHeaders", neighbor.LinkIndex, neighbor.IPAddress.String())
	neighborsStr, err := runCommand(cmd)
	if err != nil && !strings.Contains(err.Error(), "No matching MSFT_NetNeighbor objects") {
		return nil, err
	}

	parsed := parseCmdResult(neighborsStr, 5)
	var neighbors []Neighbor
	for _, items := range parsed {
		idx, err := strconv.Atoi(items[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse the LinkIndex '%s': %w", items[0], err)
		}
		dstIP := net.ParseIP(items[1])
		if err != nil {
			return nil, fmt.Errorf("failed to parse the DestinationIP '%s': %w", items[1], err)
		}
		// Get-NetNeighbor returns LinkLayerAddress like "AA-BB-CC-DD-EE-FF".
		mac, err := net.ParseMAC(strings.ReplaceAll(items[2], "-", ":"))
		if err != nil {
			return nil, fmt.Errorf("failed to parse the Gateway MAC '%s': %w", items[2], err)
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

// newNetNeighbor creates a new neighbor cache entry with New-NetNeighbor.
func newNetNeighbor(neighbor *Neighbor) error {
	cmd := fmt.Sprintf("New-NetNeighbor -InterfaceIndex %d -IPAddress %s -LinkLayerAddress %s -State Permanent",
		neighbor.LinkIndex, neighbor.IPAddress, neighbor.LinkLayerAddress)
	_, err := runCommand(cmd)
	return err
}

func removeNetNeighbor(neighbor *Neighbor) error {
	cmd := fmt.Sprintf("Remove-NetNeighbor -InterfaceIndex %d -IPAddress %s -Confirm:$false",
		neighbor.LinkIndex, neighbor.IPAddress)
	_, err := runCommand(cmd)
	return err
}

func (h *Handle) ReplaceNetNeighbor(neighbor *Neighbor) error {
	neighbors, err := getNetNeighbor(neighbor)
	if err != nil {
		return err
	}

	if len(neighbors) == 0 {
		if err := newNetNeighbor(neighbor); err != nil {
			return err
		}
		return nil
	}
	for _, n := range neighbors {
		if n.LinkLayerAddress.String() == neighbor.LinkLayerAddress.String() && n.State == neighbor.State {
			return nil
		}
	}
	if err := removeNetNeighbor(neighbor); err != nil {
		return err
	}
	return newNetNeighbor(neighbor)
}

func (h *Handle) GetVMSwitchNetAdapterName(vmSwitch string) (string, error) {
	cmd := fmt.Sprintf(`Get-VMSwitchTeam -Name "%s" | select NetAdapterInterfaceDescription |  Format-Table -HideTableHeaders`, vmSwitch)
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

func (h *Handle) VMSwitchExists(vmSwitch string) (bool, error) {
	cmd := fmt.Sprintf(`Get-VMSwitch -Name "%s" -ComputerName $(hostname)`, vmSwitch)
	_, err := runCommand(cmd)
	if err == nil {
		return true, nil
	}
	if strings.Contains(err.Error(), fmt.Sprintf(`unable to find a virtual switch with name "%s"`, vmSwitch)) {
		return false, nil
	}
	return false, err
}

// AddVMSwitch creates a VMSwitch and enables OVS extension. Connection to VMSwitch is lost for few seconds.
// TODO: Handle for multiple interfaces
func (h *Handle) AddVMSwitch(adapterName, vmSwitch string) error {
	cmd := fmt.Sprintf(`New-VMSwitch -Name "%s" -NetAdapterName "%s" -EnableEmbeddedTeaming $true -AllowManagementOS $true -ComputerName $(hostname)| Enable-VMSwitchExtension "%s"`, vmSwitch, adapterName, ovsExtensionName)
	_, err := runCommand(cmd)
	if err != nil {
		return err
	}
	return nil
}

func (h *Handle) RemoveVMSwitch(vmSwitch string) error {
	exists, err := h.VMSwitchExists(vmSwitch)
	if err != nil {
		return err
	}
	if exists {
		cmd := fmt.Sprintf(`Remove-VMSwitch -Name "%s" -ComputerName $(hostname) -Force`, vmSwitch)
		_, err = runCommand(cmd)
		if err != nil {
			return err
		}
	}
	return nil
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
		return fmt.Errorf("unable to set IPInterface with MTU %d: %w", mtu, err)
	}
	return nil
}

func (a *adapter) setForwarding(enabledForwarding bool, family uint16) error {
	if err := a.setIPInterfaceEntry(family, func(entry *antreasyscall.MibIPInterfaceRow) *antreasyscall.MibIPInterfaceRow {
		newEntry := *entry
		newEntry.ForwardingEnabled = enabledForwarding
		return &newEntry
	}); err != nil {
		return fmt.Errorf("unable to enable IPForwarding on network adapter: %w", err)
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
			return fmt.Errorf("failed to change current thread's compartment '%d': %w", a.compartmentID, err)
		}
	}
	ipInterfaceRow := &antreasyscall.MibIPInterfaceRow{Family: family, Index: uint32(a.Index)}
	if err := antreaNetIO.GetIPInterfaceEntry(ipInterfaceRow); err != nil {
		return fmt.Errorf("unable to get IPInterface entry with Index %d: %w", a.Index, err)
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

func (h *Handle) EnableVMSwitchOVSExtension(vmSwitch string) error {
	cmd := fmt.Sprintf(`Get-VMSwitch -Name "%s" -ComputerName $(hostname)| Enable-VMSwitchExtension "%s"`, vmSwitch, ovsExtensionName)
	_, err := runCommand(cmd)
	if err != nil {
		return err
	}
	return nil
}

// parseOVSExtensionOutput parses the VM extension output and returns the value of Enabled field.
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

func (h *Handle) IsVMSwitchOVSExtensionEnabled(vmSwitch string) (bool, error) {
	cmd := fmt.Sprintf(`Get-VMSwitchExtension -VMSwitchName "%s" -ComputerName $(hostname) | ? Id -EQ "%s"`, vmSwitch, OVSExtensionID)
	out, err := runCommand(cmd)
	if err != nil {
		return false, err
	}
	if !strings.Contains(out, ovsExtensionName) {
		return false, fmt.Errorf("open vswitch extension driver is not installed")
	}
	return parseOVSExtensionOutput(out), nil
}

func (h *Handle) RenameNetAdapter(oriName string, newName string) error {
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
