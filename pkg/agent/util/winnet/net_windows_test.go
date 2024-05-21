//go:build windows
// +build windows

// Copyright 2023 Antrea Authors
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
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	antreasyscall "antrea.io/antrea/pkg/agent/util/syscall"
	antreasyscalltest "antrea.io/antrea/pkg/agent/util/syscall/testing"
	"antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/ip"
)

var (
	testMACAddr, _  = net.ParseMAC("aa:bb:cc:dd:ee:ff")
	ipv4Public      = net.ParseIP("8.8.8.8")
	ipv4PublicIPNet = ip.MustParseCIDR("8.8.8.8/32")

	testInvalidErr = fmt.Errorf("invalid")

	h = &Handle{}
)

const (
	testVMSwitchName = "antrea-switch"
	testAdapterName  = "test-en0"
)

func TestNetRouteString(t *testing.T) {
	gw, subnet, _ := net.ParseCIDR("192.168.2.0/24")
	testRoute := Route{
		LinkIndex:         1,
		DestinationSubnet: subnet,
		GatewayAddress:    gw,
		RouteMetric:       MetricDefault,
	}
	gotRoute := testRoute.String()
	assert.Equal(t, "LinkIndex: 1, DestinationSubnet: 192.168.2.0/24, GatewayAddress: 192.168.2.0, RouteMetric: 256", gotRoute)
}

func TestNetRouteTranslation(t *testing.T) {
	subnet := ip.MustParseCIDR("1.1.1.0/28")
	oriRoute := &Route{
		LinkIndex:         27,
		RouteMetric:       35,
		DestinationSubnet: subnet,
		GatewayAddress:    net.ParseIP("1.1.1.254"),
	}
	row := toMibIPForwardRow(oriRoute)
	newRoute := routeFromIPForwardRow(row)
	assert.Equal(t, oriRoute, newRoute)
}

func TestNetNeighborString(t *testing.T) {
	testNeighbor := Neighbor{
		LinkIndex:        1,
		IPAddress:        net.ParseIP("169.254.0.253"),
		LinkLayerAddress: testMACAddr,
		State:            "Permanent",
	}
	gotNeighbor := testNeighbor.String()
	assert.Equal(t, "LinkIndex: 1, IPAddress: 169.254.0.253, LinkLayerAddress: aa:bb:cc:dd:ee:ff", gotNeighbor)
}

func TestIsVirtualNetAdapter(t *testing.T) {
	adapter := "test-adapter"
	tests := []struct {
		name          string
		commandOut    string
		commandErr    error
		adapter       string
		wantIsVirtual bool
	}{
		{
			name:          "Virtual adapter",
			commandOut:    " true ",
			wantIsVirtual: true,
		},
		{
			name:          "Virtual adapter Err",
			commandErr:    testInvalidErr,
			wantIsVirtual: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockRunCommand(t, []string{
				fmt.Sprintf(`Get-NetAdapter -InterfaceAlias "%s" | Select-Object -Property Virtual | Format-Table -HideTableHeaders`, adapter),
			}, tc.commandOut, tc.commandErr, true)
			gotIsVirtual, err := h.IsVirtualNetAdapter(adapter)
			assert.Equal(t, tc.wantIsVirtual, gotIsVirtual)
			assert.Equal(t, tc.commandErr, err)
		})
	}
}

func TestGetDNServersByNetAdapterIndex(t *testing.T) {
	testIndex := 1
	tests := []struct {
		name          string
		commandOut    string
		commandErr    error
		wantDNSServer string
	}{
		{
			name:          "Index Success",
			commandOut:    "hello\r\nworld\r\n\r\n",
			wantDNSServer: "hello,world",
		},
		{
			name:       "Index Error",
			commandOut: "fail",
			commandErr: testInvalidErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockRunCommand(t, []string{
				fmt.Sprintf("$(Get-DnsClientServerAddress -InterfaceIndex %d -AddressFamily IPv4).ServerAddresses", testIndex),
			}, tc.commandOut, tc.commandErr, true)
			gotDNSServer, err := h.GetDNServersByNetAdapterIndex(testIndex)
			assert.Equal(t, tc.wantDNSServer, gotDNSServer)
			assert.Equal(t, tc.commandErr, err)
		})
	}
}

func TestNetAdapterExists(t *testing.T) {
	tests := []struct {
		name                 string
		testNetInterfaceName string
		testAdapterAddresses *windows.IpAdapterAddresses
	}{
		{
			name:                 "Normal Exist",
			testNetInterfaceName: "host",
			testAdapterAddresses: createTestAdapterAddresses("host"),
		},
		{
			name: "Interface not exist",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockGetAdaptersAddresses(t, tc.testAdapterAddresses, nil)
			gotExists := h.NetAdapterExists(tc.testNetInterfaceName)
			assert.Equal(t, tc.testNetInterfaceName != "", gotExists)
		})
	}
}

func TestSetNetAdapterMTU(t *testing.T) {
	testName := "host"
	testAdapterAddresses := createTestAdapterAddresses(testName)
	testMTU := 2
	tests := []struct {
		name                 string
		testNetInterfaceName string
		testAdapterAddresses *windows.IpAdapterAddresses
		getIPInterfaceErr    error
		setIPInterfaceErr    error
		wantErr              error
	}{
		{
			name:                 "Set Success",
			testNetInterfaceName: testName,
			testAdapterAddresses: testAdapterAddresses,
		},
		{
			name: "Interface name invalid",
			wantErr: fmt.Errorf("unable to find NetAdapter on host in all compartments with name %s: %w", "",
				&net.OpError{Op: "route", Net: "ip+net", Source: nil, Addr: nil, Err: errInvalidInterfaceName}),
		},
		{
			name:                 "Get Interface Err",
			testNetInterfaceName: testName,
			testAdapterAddresses: testAdapterAddresses,
			getIPInterfaceErr:    fmt.Errorf("IP interface not found"),
			wantErr: fmt.Errorf("unable to set IPInterface with MTU %d: %w", testMTU,
				fmt.Errorf("unable to get IPInterface entry with Index %d: %w", (int)(testAdapterAddresses.IfIndex), fmt.Errorf("IP interface not found"))),
		},
		{
			name:                 "Set Interface Err",
			testNetInterfaceName: testName,
			testAdapterAddresses: testAdapterAddresses,
			setIPInterfaceErr:    fmt.Errorf("IP interface set error"),
			wantErr:              fmt.Errorf("unable to set IPInterface with MTU %d: %w", testMTU, fmt.Errorf("IP interface set error")),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockGetAdaptersAddresses(t, tc.testAdapterAddresses, nil)
			mockAntreaNetIO(t,
				&antreasyscalltest.MockNetIO{
					GetIPInterfaceEntryErr: tc.getIPInterfaceErr,
					SetIPInterfaceEntryErr: tc.setIPInterfaceErr})
			gotErr := h.SetNetAdapterMTU(tc.testNetInterfaceName, testMTU)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestReplaceNetRoute(t *testing.T) {
	subnet := ip.MustParseCIDR("1.1.1.0/28")
	testGateway := net.ParseIP("1.1.1.254")
	testIndex := uint32(27)
	testIPForwardRow := createTestMibIPForwardRow(testIndex, subnet, testGateway)
	testRoute := Route{
		LinkIndex:         (int)(testIPForwardRow.Index),
		DestinationSubnet: subnet,
		GatewayAddress:    net.ParseIP("1.1.1.254"),
		RouteMetric:       MetricDefault,
	}
	listIPForwardRowsErr := fmt.Errorf("unable to list Windows IPForward rows: %w", fmt.Errorf("unable to list IP forward entry"))
	deleteIPForwardEntryErr := fmt.Errorf("failed to delete existing route with nextHop %s: %w", testRoute.GatewayAddress, fmt.Errorf("unable to delete IP forward entry"))
	createIPForwardEntryErr := fmt.Errorf("failed to create new IPForward row: %w", fmt.Errorf("unable to create IP forward entry"))
	tests := []struct {
		name               string
		listRows           []antreasyscall.MibIPForwardRow
		listRowsErr        error
		createIPForwardErr error
		deleteIPForwardErr error
		wantErr            error
	}{
		{
			name:     "Replace Success",
			listRows: []antreasyscall.MibIPForwardRow{createTestMibIPForwardRow(testIndex, subnet, net.ParseIP("1.1.1.1"))},
		},
		{
			name:     "Same GatewayAddress",
			listRows: []antreasyscall.MibIPForwardRow{createTestMibIPForwardRow(testIndex, subnet, testGateway)},
		},
		{
			name:        "List Rows Err",
			listRowsErr: fmt.Errorf("unable to list IP forward entry"),
			wantErr:     listIPForwardRowsErr,
		},
		{
			name:               "Delete Ip Forward Entry Err",
			listRows:           []antreasyscall.MibIPForwardRow{createTestMibIPForwardRow(testIndex, subnet, net.ParseIP("1.1.1.1"))},
			deleteIPForwardErr: fmt.Errorf("unable to delete IP forward entry"),
			wantErr:            deleteIPForwardEntryErr,
		},
		{
			name:               "Add Route Err",
			listRows:           []antreasyscall.MibIPForwardRow{createTestMibIPForwardRow(testIndex, subnet, net.ParseIP("1.1.1.1"))},
			createIPForwardErr: fmt.Errorf("unable to create IP forward entry"),
			wantErr:            createIPForwardEntryErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockAntreaNetIO(t,
				&antreasyscalltest.MockNetIO{
					CreateIPForwardEntryErr: tc.createIPForwardErr,
					DeleteIPForwardEntryErr: tc.deleteIPForwardErr,
					ListIPForwardRowsErr:    tc.listRowsErr,
					IPForwardRows:           tc.listRows})
			gotErr := h.ReplaceNetRoute(&testRoute)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestRemoveNetRoute(t *testing.T) {
	subnet := ip.MustParseCIDR("1.1.1.0/28")
	testGateway := net.ParseIP("1.1.1.254")
	testIndex := uint32(27)
	testIPForwardRow := createTestMibIPForwardRow(testIndex, subnet, testGateway)
	testRoute := Route{
		LinkIndex:         (int)(testIPForwardRow.Index),
		DestinationSubnet: subnet,
		GatewayAddress:    testGateway,
		RouteMetric:       MetricDefault,
	}
	listIPForwardRowsErr := fmt.Errorf("unable to list Windows IPForward rows: %w", fmt.Errorf("unable to list IP forward entry"))
	deleteIPForwardEntryErr := fmt.Errorf("failed to delete existing route with nextHop %s: %w", testRoute.GatewayAddress, fmt.Errorf("unable to delete IP forward entry"))
	tests := []struct {
		name               string
		listRows           []antreasyscall.MibIPForwardRow
		listRowsErr        error
		deleteIPForwardErr error
		wantErr            error
	}{
		{
			name:     "Remove Success",
			listRows: []antreasyscall.MibIPForwardRow{createTestMibIPForwardRow(testIndex, subnet, testGateway)},
		},
		{
			name:        "List Rows Err",
			listRowsErr: fmt.Errorf("unable to list IP forward entry"),
			wantErr:     listIPForwardRowsErr,
		},
		{
			name:               "Remove Failed",
			listRows:           []antreasyscall.MibIPForwardRow{createTestMibIPForwardRow(testIndex, subnet, testGateway)},
			deleteIPForwardErr: fmt.Errorf("unable to delete IP forward entry"),
			wantErr:            deleteIPForwardEntryErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockAntreaNetIO(t,
				&antreasyscalltest.MockNetIO{
					DeleteIPForwardEntryErr: tc.deleteIPForwardErr,
					ListIPForwardRowsErr:    tc.listRowsErr,
					IPForwardRows:           tc.listRows})
			gotErr := h.RemoveNetRoute(&testRoute)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestRouteListFiltered(t *testing.T) {
	subnet1 := ip.MustParseCIDR("1.1.1.0/28")
	subnet2 := ip.MustParseCIDR("1.1.1.128/28")
	testGateway1 := net.ParseIP("1.1.1.254")
	testGateway2 := net.ParseIP("1.1.1.254")
	testIndex1 := uint32(27)
	testIndex2 := uint32(28)
	testIPForwardRow1 := createTestMibIPForwardRow(testIndex1, subnet1, testGateway1)
	testIPForwardRow2 := createTestMibIPForwardRow(testIndex2, subnet2, testGateway2)
	testRoute1 := Route{
		LinkIndex:         (int)(testIPForwardRow1.Index),
		DestinationSubnet: subnet1,
		GatewayAddress:    testGateway1,
		RouteMetric:       MetricDefault,
	}
	testRoute2 := Route{
		LinkIndex:         (int)(testIPForwardRow2.Index),
		DestinationSubnet: subnet2,
		GatewayAddress:    testGateway2,
		RouteMetric:       MetricDefault,
	}
	listRows := []antreasyscall.MibIPForwardRow{
		createTestMibIPForwardRow(testIndex1, subnet1, testGateway1),
		createTestMibIPForwardRow(testIndex2, subnet2, testGateway2),
	}

	listIPForwardRowsErr := fmt.Errorf("unable to list Windows IPForward rows: %w", fmt.Errorf("unable to list IP forward entry"))
	tests := []struct {
		name        string
		listRows    []antreasyscall.MibIPForwardRow
		listRowsErr error
		filterRoute *Route
		filterMasks uint64
		wantRoutes  []Route
		wantErr     error
	}{
		{
			name:        "List Rows Err",
			listRowsErr: fmt.Errorf("unable to list IP forward entry"),
			wantErr:     listIPForwardRowsErr,
		},
		{
			name:     "Filter Link Index",
			listRows: listRows,
			filterRoute: &Route{
				LinkIndex: (int)(testIPForwardRow1.Index),
			},
			filterMasks: RT_FILTER_IF,
			wantRoutes:  []Route{testRoute1},
		},
		{
			name:     "Filter Destination",
			listRows: listRows,
			filterRoute: &Route{
				DestinationSubnet: subnet1,
			},
			filterMasks: RT_FILTER_DST,
			wantRoutes:  []Route{testRoute1},
		},
		{
			name:     "Filter Gateway",
			listRows: listRows,
			filterRoute: &Route{
				GatewayAddress: testGateway1,
			},
			filterMasks: RT_FILTER_GW,
			wantRoutes:  []Route{testRoute1, testRoute2},
		},
		{
			name:     "Filter Metric",
			listRows: listRows,
			filterRoute: &Route{
				RouteMetric: MetricDefault,
			},
			filterMasks: RT_FILTER_METRIC,
			wantRoutes:  []Route{testRoute1, testRoute2},
		},
		{
			name:     "Multiple Filters",
			listRows: listRows,
			filterRoute: &Route{
				LinkIndex:         (int)(testIPForwardRow1.Index),
				DestinationSubnet: subnet1,
				GatewayAddress:    testGateway1,
				RouteMetric:       MetricDefault,
			},
			filterMasks: RT_FILTER_IF | RT_FILTER_DST | RT_FILTER_GW | RT_FILTER_METRIC,
			wantRoutes:  []Route{testRoute1},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockAntreaNetIO(t,
				&antreasyscalltest.MockNetIO{
					ListIPForwardRowsErr: tc.listRowsErr,
					IPForwardRows:        tc.listRows})
			routes, gotErr := h.RouteListFiltered(antreasyscall.AF_INET, tc.filterRoute, tc.filterMasks)
			assert.Equal(t, tc.wantErr, gotErr)
			assert.ElementsMatch(t, tc.wantRoutes, routes)
		})
	}
}

func TestAddNetNat(t *testing.T) {
	notFoundErr := fmt.Errorf("received error No MSFT_NetNat objects found")
	testNetNat := "test-nat"
	testSubnetCIDR := &net.IPNet{
		IP:   net.ParseIP("192.168.1.21"),
		Mask: net.CIDRMask(32, 32),
	}
	getCmd := fmt.Sprintf(`Get-NetNat -Name %s | Select-Object InternalIPInterfaceAddressPrefix | Format-Table -HideTableHeaders`, testNetNat)
	removeCmd := fmt.Sprintf("Remove-NetNat -Name %s -Confirm:$false", testNetNat)
	newCmd := fmt.Sprintf(`New-NetNat -Name %s -InternalIPInterfaceAddressPrefix %s`, testNetNat, testSubnetCIDR.String())
	tests := []struct {
		name       string
		commandOut string
		commandErr error
		wantCmds   []string
		wantErr    error
	}{
		{
			name:       "New Net Nat",
			commandOut: "0.0.0.0/32",
			wantCmds:   []string{getCmd, removeCmd, newCmd},
		},
		{
			name:       "Net Nat Not Found",
			commandErr: testInvalidErr,
			wantCmds:   []string{getCmd},
			wantErr:    fmt.Errorf("failed to check the existing netnat '%s': %w", testNetNat, testInvalidErr),
		},
		{
			name:       "Net Nat Exist",
			commandOut: "192.168.1.21/32",
			wantCmds:   []string{getCmd},
		},
		{
			name:       "Net Nat Add Fail",
			commandErr: notFoundErr,
			wantCmds:   []string{getCmd, newCmd},
			wantErr:    fmt.Errorf("failed to add netnat '%s' with internalIPInterfaceAddressPrefix '%s': %w", testNetNat, testSubnetCIDR.String(), notFoundErr),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, true)
			gotErr := h.AddNetNat(testNetNat, testSubnetCIDR)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestReplaceNetNatStaticMapping(t *testing.T) {
	notFoundErr := fmt.Errorf("received error No MSFT_NetNatStaticMapping objects found")
	testNetNatName := "test-nat"
	testExternalPort, testInternalPort := (uint16)(80), (uint16)(8080)
	testExternalIPAddr, testInternalIPAddr := "10.10.0.1", "192.0.2.179"
	testProto := openflow.ProtocolTCP
	testNetNat := &NetNatStaticMapping{
		Name:         testNetNatName,
		ExternalIP:   net.ParseIP(testExternalIPAddr),
		ExternalPort: testExternalPort,
		InternalIP:   net.ParseIP(testInternalIPAddr),
		InternalPort: testInternalPort,
		Protocol:     testProto,
	}

	getCmd := fmt.Sprintf("Get-NetNatStaticMapping -NatName %s", testNetNatName) +
		fmt.Sprintf("|? ExternalIPAddress -EQ %s", testExternalIPAddr) +
		fmt.Sprintf("|? ExternalPort -EQ %d", testExternalPort) +
		fmt.Sprintf("|? Protocol -EQ %s", testProto) +
		"| Format-Table -HideTableHeaders"
	removeCmd := fmt.Sprintf("Remove-NetNatStaticMapping -NatName %s -StaticMappingID %d -Confirm:$false", testNetNatName, 1)
	addCmd := fmt.Sprintf("Add-NetNatStaticMapping -NatName %s -ExternalIPAddress %s -ExternalPort %d -InternalIPAddress %s -InternalPort %d -Protocol %s",
		testNetNatName, testExternalIPAddr, testExternalPort, testInternalIPAddr, testInternalPort, testProto)
	type testFormat struct {
		name       string
		commandOut string
		commandErr error
		wantCmds   []string
		wantErr    error
	}
	tests := []testFormat{
		{
			name:       "Replace Net Nat",
			commandOut: "0;1 nil nil nil 192.168.1.21 80",
			wantCmds:   []string{getCmd, removeCmd, addCmd},
		},
		{
			name:       "Get Net Nat Err",
			commandErr: testInvalidErr,
			wantCmds:   []string{getCmd},
			wantErr:    testInvalidErr,
		},
		{
			name:       "Remove Net Nat Err",
			commandOut: "0;1 nil nil nil 192.168.1.21 80",
			commandErr: notFoundErr,
			wantCmds:   []string{getCmd, removeCmd},
			wantErr:    notFoundErr,
		},
		{
			name:       "Add Net Nat Err",
			commandOut: "empty",
			commandErr: notFoundErr,
			wantCmds:   []string{getCmd, addCmd},
			wantErr:    notFoundErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, true)
			gotErr := h.ReplaceNetNatStaticMapping(testNetNat)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestRemoveNetNatStaticMapping(t *testing.T) {
	testNetNatName := "test-nat"
	testExternalPort, testInternalPort := (uint16)(80), (uint16)(8080)
	testExternalIPAddr, testInternalIPAddr := "10.10.0.1", "192.0.2.179"
	testProto := openflow.ProtocolTCP
	testNetNat := &NetNatStaticMapping{
		Name:         testNetNatName,
		ExternalIP:   net.ParseIP(testExternalIPAddr),
		ExternalPort: testExternalPort,
		InternalIP:   net.ParseIP(testInternalIPAddr),
		InternalPort: testInternalPort,
		Protocol:     testProto,
	}
	getCmd := fmt.Sprintf("Get-NetNatStaticMapping -NatName %s", testNetNatName) +
		fmt.Sprintf("|? ExternalIPAddress -EQ %s", testExternalIPAddr) +
		fmt.Sprintf("|? ExternalPort -EQ %d", testExternalPort) +
		fmt.Sprintf("|? Protocol -EQ %s", testProto) +
		"| Format-Table -HideTableHeaders"
	removeIDCmd := fmt.Sprintf("Remove-NetNatStaticMapping -NatName %s -StaticMappingID %d -Confirm:$false", testNetNatName, 1)
	removeCmd := fmt.Sprintf("Remove-NetNatStaticMapping -NatName %s -Confirm:$false", testNetNatName)
	tests := []struct {
		name       string
		commandOut string
		commandErr error
		wantCmds   []string
		wantErr    error
	}{
		{
			name:       "Remove Net Nat Static Mapping",
			commandOut: "0;1 nil nil nil 192.0.02.179 8080",
			wantCmds:   []string{getCmd, removeIDCmd, removeCmd},
		},
		{
			name:       "Remove Err",
			commandErr: testInvalidErr,
			wantCmds:   []string{getCmd, removeCmd},
			wantErr:    testInvalidErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, false)
			gotErr := h.RemoveNetNatStaticMapping(testNetNat)
			assert.Equal(t, tc.wantErr, gotErr)
			assert.Equal(t, tc.wantErr, gotErr)
			gotErr = h.RemoveNetNatStaticMappingsByNetNat(testNetNat.Name)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestReplaceNetNeighbor(t *testing.T) {
	netNeighborNotFoundErr := fmt.Errorf("received error No matching MSFT_NetNeighbor objects")
	testNeighbor := &Neighbor{
		LinkIndex:        1,
		IPAddress:        net.ParseIP("169.254.0.253"),
		LinkLayerAddress: testMACAddr,
		State:            "Permanent",
	}
	getCmd := fmt.Sprintf("Get-NetNeighbor -InterfaceIndex %d -IPAddress %s | Format-Table -HideTableHeaders", testNeighbor.LinkIndex, testNeighbor.IPAddress.String())
	newCmd := fmt.Sprintf("New-NetNeighbor -InterfaceIndex %d -IPAddress %s -LinkLayerAddress %s -State Permanent",
		testNeighbor.LinkIndex, testNeighbor.IPAddress, testNeighbor.LinkLayerAddress)
	removeCmd := fmt.Sprintf("Remove-NetNeighbor -InterfaceIndex %d -IPAddress %s -Confirm:$false",
		testNeighbor.LinkIndex, testNeighbor.IPAddress)
	type testFormat struct {
		name       string
		commandOut string
		commandErr error
		wantCmds   []string
		wantErr    error
	}
	tests := []testFormat{
		{
			name:       "Replace Neighbor",
			commandOut: "1 169.254.1.253 aa:bb:cc:dd:ff:ff Permanent nil",
			wantCmds:   []string{getCmd, removeCmd, newCmd},
		},
		{
			name:       "Get Net Neighbor Err",
			commandErr: testInvalidErr,
			wantCmds:   []string{getCmd},
			wantErr:    testInvalidErr,
		},
		{
			name:       "Remove Net Neighbor Err",
			commandOut: "1 169.254.1.253 aa:bb:cc:dd:ff:ff Permanent nil",
			commandErr: netNeighborNotFoundErr,
			wantCmds:   []string{getCmd, removeCmd},
			wantErr:    netNeighborNotFoundErr,
		},
		{
			name:       "New Net Neighbor Err",
			commandErr: netNeighborNotFoundErr,
			wantCmds:   []string{getCmd, newCmd},
			wantErr:    netNeighborNotFoundErr,
		},
		{
			name:       "Duplicate Neighbor",
			commandOut: "1 169.254.0.253 aa:bb:cc:dd:ee:ff Permanent nil",
			wantCmds:   []string{getCmd},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, true)
			gotErr := h.ReplaceNetNeighbor(testNeighbor)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestVirtualAdapterName(t *testing.T) {
	gotName := VirtualAdapterName("0")
	assert.Equal(t, "vEthernet (0)", gotName)
}

func TestRenameNetAdapter(t *testing.T) {
	tests := []struct {
		name       string
		commandOut string
		commandErr error
		wantErr    error
	}{
		{
			name:       "Rename Interface",
			commandOut: "success",
		},
		{
			name:       "Rename Err",
			commandErr: testInvalidErr,
			wantErr:    fmt.Errorf("invalid"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockRunCommand(t, []string{
				fmt.Sprintf(`Get-NetAdapter -Name "%s" | Rename-NetAdapter -NewName "%s"`, "test1", "test2"),
			}, tc.commandOut, tc.commandErr, false)
			gotErr := h.RenameNetAdapter("test1", "test2")
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestAddVMSwitch(t *testing.T) {
	testSwitchName := "test-switch"
	tests := []struct {
		name       string
		commandErr error
		wantErr    error
	}{
		{
			name: "Success",
		},
		{
			name:       "Error",
			commandErr: testInvalidErr,
			wantErr:    fmt.Errorf("invalid"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockRunCommand(t, []string{fmt.Sprintf(`New-VMSwitch -Name "%s" -NetAdapterName "%s" -EnableEmbeddedTeaming $true -AllowManagementOS $true -ComputerName $(hostname)| Enable-VMSwitchExtension "%s"`, testVMSwitchName, testSwitchName, ovsExtensionName)}, "", tc.commandErr, false)
			gotErr := h.AddVMSwitch(testSwitchName, testVMSwitchName)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestEnableVMSwitchOVSExtension(t *testing.T) {
	tests := []struct {
		name       string
		commandErr error
		wantErr    error
	}{
		{
			name: "Enable",
		},
		{
			name:       "Error",
			commandErr: testInvalidErr,
			wantErr:    fmt.Errorf("invalid"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockRunCommand(t, []string{fmt.Sprintf(`Get-VMSwitch -Name "%s" -ComputerName $(hostname)| Enable-VMSwitchExtension "%s"`, testVMSwitchName, ovsExtensionName)}, "", tc.commandErr, false)
			gotErr := h.EnableVMSwitchOVSExtension(testVMSwitchName)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestIsVMSwitchOVSExtensionEnabled(t *testing.T) {
	tests := []struct {
		name       string
		commandOut string
		commandErr error
		wantErr    error
		wantRes    bool
	}{
		{
			name:       "Enabled",
			commandOut: "Open vSwitch Extension Enabled True",
			wantRes:    true,
		},
		{
			name:       "Not enabled",
			commandOut: "Open vSwitch Extension False",
			wantRes:    false,
		},
		{
			name:       "Error",
			commandErr: testInvalidErr,
			wantErr:    fmt.Errorf("invalid"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockRunCommand(t, []string{fmt.Sprintf(`Get-VMSwitchExtension -VMSwitchName "%s" -ComputerName $(hostname) | ? Id -EQ "%s"`, testVMSwitchName, OVSExtensionID)}, tc.commandOut, tc.commandErr, false)
			res, gotErr := h.IsVMSwitchOVSExtensionEnabled(testVMSwitchName)
			assert.Equal(t, tc.wantRes, res)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestGetVMSwitchInterfaceName(t *testing.T) {
	getVMCmd := fmt.Sprintf(`Get-VMSwitchTeam -Name "%s" | select NetAdapterInterfaceDescription |  Format-Table -HideTableHeaders`, testVMSwitchName)
	getAdapterCmd := fmt.Sprintf(`Get-NetAdapter -InterfaceDescription "%s" | select Name | Format-Table -HideTableHeaders`, "test")
	tests := []struct {
		name       string
		commandOut string
		commandErr error
		wantCmds   []string
		wantName   string
		wantErr    error
	}{
		{
			name:       "Get Interface Name",
			commandOut: " {test} ",
			wantCmds:   []string{getVMCmd, getAdapterCmd},
			wantName:   "{test}",
		},
		{
			name:       "Get Err",
			commandErr: testInvalidErr,
			wantCmds:   []string{getVMCmd},
			wantErr:    testInvalidErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, true)
			gotName, gotErr := h.GetVMSwitchNetAdapterName(testVMSwitchName)
			assert.Equal(t, tc.wantName, gotName)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestRemoveVMSwitch(t *testing.T) {
	getCmd := fmt.Sprintf(`Get-VMSwitch -Name "%s" -ComputerName $(hostname)`, testVMSwitchName)
	removeCmd := fmt.Sprintf(`Remove-VMSwitch -Name "%s" -ComputerName $(hostname) -Force`, testVMSwitchName)
	tests := []struct {
		name       string
		commandOut string
		commandErr error
		wantCmds   []string
		wantErr    error
	}{
		{
			name:       "Remove VMSwitch",
			commandOut: "true",
			wantCmds:   []string{getCmd, removeCmd},
		},
		{
			name:       "Get Err",
			commandErr: testInvalidErr,
			wantCmds:   []string{getCmd},
			wantErr:    testInvalidErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, true)
			gotErr := h.RemoveVMSwitch(testVMSwitchName)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestGetAdapterInAllCompartmentsByName(t *testing.T) {
	testName := "host"
	testFlags := net.FlagUp | net.FlagBroadcast | net.FlagPointToPoint | net.FlagMulticast
	testAdapter := adapter{
		Interface: net.Interface{
			Index:        1,
			Name:         testName,
			Flags:        testFlags,
			MTU:          1,
			HardwareAddr: testMACAddr,
		},
		compartmentID: 1,
		flags:         IP_ADAPTER_DHCP_ENABLED,
	}
	tests := []struct {
		name            string
		testName        string
		testAdapters    *windows.IpAdapterAddresses
		testAdaptersErr error
		wantAdapters    *adapter
		wantErr         error
	}{
		{
			name:         "Normal",
			testName:     testName,
			testAdapters: createTestAdapterAddresses(testName),
			wantAdapters: &testAdapter,
		},
		{
			name:    "Invalid name",
			wantErr: &net.OpError{Op: "route", Net: "ip+net", Source: nil, Addr: nil, Err: errInvalidInterfaceName},
		},
		{
			name:            "adapter Err",
			testName:        testName,
			testAdaptersErr: windows.ERROR_FILE_NOT_FOUND,
			wantErr:         &net.OpError{Op: "route", Net: "ip+net", Source: nil, Addr: nil, Err: os.NewSyscallError("getadaptersaddresses", windows.ERROR_FILE_NOT_FOUND)},
		},
		{
			name:     "adapter not found",
			testName: testName,
			wantErr:  &net.OpError{Op: "route", Net: "ip+net", Source: nil, Addr: nil, Err: errNoSuchInterface},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockGetAdaptersAddresses(t, tc.testAdapters, tc.testAdaptersErr)
			gotAdapters, gotErr := getAdapterInAllCompartmentsByName(tc.testName)
			assert.EqualValues(t, tc.wantAdapters, gotAdapters)
			assert.EqualValues(t, tc.wantErr, gotErr)
		})
	}
}

func TestEnableNetAdapter(t *testing.T) {
	enableCmd := fmt.Sprintf(`Enable-NetAdapter -InterfaceAlias "%s"`, testAdapterName)
	tests := []struct {
		name           string
		commandErr     error
		gwInterfaceErr error
		wantCmds       []string
	}{
		{
			name:     "Set Link Up Normal",
			wantCmds: []string{enableCmd},
		},
		{
			name:           "Enable Interface Err",
			commandErr:     fmt.Errorf("failed to enable interface test-en0: fail"),
			gwInterfaceErr: fmt.Errorf("failed to enable interface %s", testAdapterName),
			wantCmds:       []string{enableCmd},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockRunCommand(t, tc.wantCmds, "", tc.commandErr, false)
			err := h.EnableNetAdapter(testAdapterName)
			if tc.gwInterfaceErr == nil {
				require.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.gwInterfaceErr.Error())
			}
		})
	}
}

func TestRemoveNetAdapterIPAddress(t *testing.T) {
	removeCmd := fmt.Sprintf(`Remove-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -Confirm:$false`, testAdapterName, ipv4Public.String())
	tests := []struct {
		name       string
		ip         net.IP
		commandOut string
		commandErr error
		wantCmds   []string
		wantErr    error
	}{
		{
			name:     "Link Addr Remove Success",
			ip:       ipv4Public,
			wantCmds: []string{removeCmd},
		},
		{
			name:       "Link Addr Remove Failure",
			ip:         ipv4Public,
			commandErr: fmt.Errorf("fail"),
			wantCmds:   []string{removeCmd},
			wantErr:    fmt.Errorf("fail"),
		},
		{
			name:       "Link Addr Remove Failure with Error 'No Matching'",
			ip:         ipv4Public,
			commandErr: fmt.Errorf("No matching"),
			wantCmds:   []string{removeCmd},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, true)
			gotErr := h.RemoveNetAdapterIPAddress(testAdapterName, tc.ip)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestAddNetAdapterIPAddress(t *testing.T) {
	ipStr := strings.Split(ipv4PublicIPNet.String(), "/")
	configCmd := fmt.Sprintf(`New-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -PrefixLength %s`, testAdapterName, ipStr[0], ipStr[1])
	gateway := "8.8.8.1"
	tests := []struct {
		name       string
		ipNet      *net.IPNet
		gateway    string
		commandOut string
		commandErr error
		wantCmds   []string
		wantErr    error
	}{
		{
			name:       "Configure Link IP Address Success",
			ipNet:      ipv4PublicIPNet,
			commandOut: "success",
			wantCmds:   []string{configCmd},
		},
		{
			name:       "Configure Link IP Address and Gateway Success",
			ipNet:      ipv4PublicIPNet,
			gateway:    gateway,
			commandOut: "success",
			wantCmds:   []string{fmt.Sprintf(`%s -DefaultGateway %s`, configCmd, gateway)},
		},
		{
			name:       "Configure Link IP Failure",
			ipNet:      ipv4PublicIPNet,
			commandErr: fmt.Errorf("failed"),
			wantErr:    fmt.Errorf("failed"),
			wantCmds:   []string{configCmd},
		},
		{
			name:       "Configure Link IP Failure with Error 'already exists'",
			ipNet:      ipv4PublicIPNet,
			commandErr: fmt.Errorf("already exists"),
			wantCmds:   []string{configCmd},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, true)
			gotErr := h.AddNetAdapterIPAddress(testAdapterName, tc.ipNet, tc.gateway)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}

}

func createTestAdapterAddresses(name string) *windows.IpAdapterAddresses {
	testPhysicalAddress := [8]byte{}
	copy(testPhysicalAddress[:6], testMACAddr)
	testName, _ := windows.UTF16FromString(name)
	return &windows.IpAdapterAddresses{
		FriendlyName:          &testName[0],
		IfIndex:               1,
		OperStatus:            windows.IfOperStatusUp,
		IfType:                windows.IF_TYPE_ATM,
		Mtu:                   1,
		PhysicalAddressLength: 6,
		PhysicalAddress:       testPhysicalAddress,
		CompartmentId:         1,
		Flags:                 IP_ADAPTER_DHCP_ENABLED,
	}
}

func createTestMibIPForwardRow(index uint32, subnet *net.IPNet, ip net.IP) antreasyscall.MibIPForwardRow {
	return antreasyscall.MibIPForwardRow{
		Index:             index,
		Metric:            MetricDefault,
		DestinationPrefix: *antreasyscall.NewAddressPrefixFromIPNet(subnet),
		NextHop:           *antreasyscall.NewRawSockAddrInetFromIP(ip),
	}
}

func mockAntreaNetIO(t *testing.T, mockNetIO *antreasyscalltest.MockNetIO) {
	originalNetIO := antreaNetIO
	antreaNetIO = mockNetIO
	t.Cleanup(func() {
		antreaNetIO = originalNetIO
	})
}

func mockGetAdaptersAddresses(t *testing.T, testAdaptersAddresses *windows.IpAdapterAddresses, err error) {
	originalGetAdaptersAddresses := getAdaptersAddresses
	getAdaptersAddresses = func(family uint32, flags uint32, reserved uintptr, adapterAddresses *windows.IpAdapterAddresses, sizePointer *uint32) (errcode error) {
		if adapterAddresses != nil && testAdaptersAddresses != nil {
			adapterAddresses.IfIndex = testAdaptersAddresses.IfIndex
			adapterAddresses.FriendlyName = testAdaptersAddresses.FriendlyName
			adapterAddresses.OperStatus = testAdaptersAddresses.OperStatus
			adapterAddresses.IfType = testAdaptersAddresses.IfType
			adapterAddresses.Mtu = testAdaptersAddresses.Mtu
			adapterAddresses.PhysicalAddressLength = testAdaptersAddresses.PhysicalAddressLength
			adapterAddresses.PhysicalAddress = testAdaptersAddresses.PhysicalAddress
			adapterAddresses.CompartmentId = testAdaptersAddresses.CompartmentId
			adapterAddresses.Flags = testAdaptersAddresses.Flags
		}
		return err
	}
	t.Cleanup(func() {
		getAdaptersAddresses = originalGetAdaptersAddresses
	})
}

// mockRunCommand mocks runCommand with a custom command output and error message.
// If exactMatch is enabled, this function asserts that the executed commands are
// exactly the same as wantCmds in terms of order and value. Otherwise, for tests
// with retry functions, the commands will be executed multiple times. This function
// asserts that wantCmds is strictly a subset of these executed commands.
func mockRunCommand(t *testing.T, wantCmds []string, commandOut string, err error, exactMatch bool) {
	originalRunCommand := runCommand
	actCmds := make([]string, 0)
	runCommand = func(cmd string) (string, error) {
		actCmds = append(actCmds, cmd)
		return commandOut, err
	}
	t.Cleanup(func() {
		runCommand = originalRunCommand
		if wantCmds == nil {
			assert.Empty(t, actCmds)
		} else if exactMatch {
			assert.Equal(t, wantCmds, actCmds)
		} else {
			assert.Subset(t, actCmds, wantCmds)
		}
	})
}
