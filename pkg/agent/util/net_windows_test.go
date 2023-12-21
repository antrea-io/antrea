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

package util

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	antreasyscalltest "antrea.io/antrea/pkg/agent/util/syscall/testing"

	"github.com/Microsoft/hcsshim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	antreasyscall "antrea.io/antrea/pkg/agent/util/syscall"
	"antrea.io/antrea/pkg/ovs/openflow"
)

func TestRouteString(t *testing.T) {
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

func TestRouteTranslation(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("1.1.1.0/28")
	oriRoute := &Route{
		LinkIndex:         27,
		RouteMetric:       35,
		DestinationSubnet: subnet,
		GatewayAddress:    net.ParseIP("1.1.1.254"),
	}
	row := oriRoute.toMibIPForwardRow()
	newRoute := routeFromIPForwardRow(row)
	assert.Equal(t, oriRoute, newRoute)
}

func TestNeighborString(t *testing.T) {
	testNeighbor := Neighbor{
		LinkIndex:        1,
		IPAddress:        net.ParseIP("169.254.0.253"),
		LinkLayerAddress: testMACAddr,
		State:            "Permanent",
	}
	gotNeighbor := testNeighbor.String()
	assert.Equal(t, "LinkIndex: 1, IPAddress: 169.254.0.253, LinkLayerAddress: aa:bb:cc:dd:ee:ff", gotNeighbor)
}

func TestGetNSPath(t *testing.T) {
	testNSPath := "/dev/null"
	gotNSPath, err := GetNSPath(testNSPath)
	require.NoError(t, err)
	assert.Equal(t, testNSPath, gotNSPath)
}

func TestIsVirtualAdapter(t *testing.T) {
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
			defer mockRunCommand(t, []string{
				fmt.Sprintf(`Get-NetAdapter -InterfaceAlias "%s" | Select-Object -Property Virtual | Format-Table -HideTableHeaders`, adapter),
			}, tc.commandOut, tc.commandErr, true)()
			gotIsVirtual, err := IsVirtualAdapter(adapter)
			assert.Equal(t, tc.wantIsVirtual, gotIsVirtual)
			assert.Equal(t, tc.commandErr, err)
		})
	}
}

func TestSetLinkUp(t *testing.T) {
	testName := "test-en0"
	enableCmd := fmt.Sprintf(`Enable-NetAdapter -InterfaceAlias "%s"`, testName)
	getCmd := fmt.Sprintf(`Get-NetAdapter -InterfaceAlias "%s" | Select-Object -Property Status | Format-Table -HideTableHeaders`, testName)
	tests := []struct {
		name           string
		commandOut     string
		commandErr     error
		gwInterface    *net.Interface
		gwInterfaceErr error
		wantCmds       []string
	}{
		{
			name:       "Set Link Up Normal",
			commandOut: " UP ",
			gwInterface: &net.Interface{
				Index:        1,
				Name:         testName,
				HardwareAddr: testMACAddr,
			},
			wantCmds: []string{enableCmd, getCmd},
		},
		{
			name:           "Enable Interface Err",
			commandErr:     fmt.Errorf("fail"),
			gwInterface:    &net.Interface{Index: 0},
			gwInterfaceErr: fmt.Errorf("failed to enable interface %s", testName),
			wantCmds:       []string{enableCmd},
		},
		{
			name:           "Get Interface Err",
			commandOut:     " Up ",
			gwInterface:    &net.Interface{Index: 0},
			gwInterfaceErr: testInvalidErr,
			wantCmds:       []string{enableCmd, getCmd},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, false)()
			defer mockNetInterfaceByName(tc.gwInterface, tc.gwInterfaceErr)()
			gotMac, gotIndex, err := SetLinkUp(testName)
			assert.Equal(t, tc.gwInterface.HardwareAddr, gotMac)
			assert.Equal(t, tc.gwInterface.Index, gotIndex)
			if tc.gwInterfaceErr == nil {
				require.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.gwInterfaceErr.Error())
			}
		})
	}
}

func TestConfigureLinkAddresses(t *testing.T) {
	testNetInterface := generateNetInterface("0")
	ipStr := strings.Split(ipv4ZeroIPNet.String(), "/")
	removeCmd := fmt.Sprintf(`Remove-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -Confirm:$false`, "0", ipv4Public.String())
	newCmd := fmt.Sprintf(`New-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -PrefixLength %s`, "0", ipStr[0], ipStr[1])
	tests := []struct {
		name                string
		ipNets              []*net.IPNet
		commandOut          string
		commandErr          error
		testNetInterfaceErr error
		testNetAddrsErr     error
		wantCmds            []string
		wantErr             error
	}{
		{
			name:       "Configure Link Addr",
			ipNets:     []*net.IPNet{&ipv4ZeroIPNet},
			commandOut: "success",
			wantCmds:   []string{removeCmd, newCmd},
		},
		{
			name:                "Net Interface Err",
			ipNets:              []*net.IPNet{},
			testNetInterfaceErr: testInvalidErr,
			wantErr:             testInvalidErr,
		},
		{
			name:            "Link Addr Err",
			ipNets:          []*net.IPNet{},
			testNetAddrsErr: testInvalidErr,
			wantErr:         fmt.Errorf("failed to query IPv4 address list for interface 0: invalid"),
		},
		{
			name:       "Link Addr No Change",
			ipNets:     []*net.IPNet{&ipv4PublicIPNet},
			commandOut: "success",
		},
		{
			name:       "Link Addr Configure Err",
			ipNets:     []*net.IPNet{&ipv4ZeroIPNet},
			commandErr: fmt.Errorf("interface No matching"),
			wantCmds:   []string{removeCmd, newCmd},
			wantErr:    fmt.Errorf("failed to add address 0.0.0.0/32 to interface 0: interface No matching"),
		},
		{
			name:       "Link Addr Remove Err",
			ipNets:     []*net.IPNet{&ipv4ZeroIPNet},
			commandErr: fmt.Errorf("interface already exists"),
			wantCmds:   []string{removeCmd},
			wantErr:    fmt.Errorf("failed to remove address 8.8.8.8/32 from interface 0: interface already exists"),
		},
		{
			name: "Link Addr IPv6 Not Supported",
			ipNets: []*net.IPNet{
				{
					IP:   net.IPv6zero,
					Mask: net.CIDRMask(128, 128),
				},
			},
			wantCmds: []string{removeCmd},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, true)()
			defer mockNetInterfaceByIndex(&testNetInterface, tc.testNetInterfaceErr)()
			defer mockNetInterfaceAddrs(testNetInterface, tc.testNetAddrsErr)()
			gotErr := ConfigureLinkAddresses(0, tc.ipNets)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestSetAdapterMACAddress(t *testing.T) {
	tests := []struct {
		name       string
		commandOut string
		commandErr error
		wantErr    error
	}{
		{
			name:       "Set adapter MAC",
			commandOut: "success",
		},
		{
			name:       "Set Err",
			commandErr: testInvalidErr,
			wantErr:    testInvalidErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockRunCommand(t, []string{
				fmt.Sprintf(`Set-NetAdapterAdvancedProperty -Name "%s" -RegistryKeyword NetworkAddress -RegistryValue "%s"`,
					"test-adapter", strings.Replace(testMACAddr.String(), ":", "", -1)),
			}, tc.commandOut, tc.commandErr, true)()
			gotErr := SetAdapterMACAddress("test-adapter", &testMACAddr)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestPrepareHNSNetwork(t *testing.T) {
	gw, subnet, _ := net.ParseCIDR("8.8.8.8/32")
	alreadyExistsErr := fmt.Errorf("already exists")
	nodeZeroIPNetStr := strings.Split(ipv4ZeroIPNet.String(), "/")
	routes := []Route{{
		LinkIndex:         0,
		DestinationSubnet: subnet,
		GatewayAddress:    gw,
		RouteMetric:       MetricDefault,
	}}
	testRoutes := convertTestRoutes(routes)
	testSubnetCIDR := &net.IPNet{
		IP:   net.ParseIP("8.8.8.7"),
		Mask: net.CIDRMask(32, 32),
	}
	testAdapterName := "testAdapter"
	testNewName := "newAdapter"
	testUplinkAdapter := &net.Interface{
		Name:         testAdapterName,
		Index:        0,
		HardwareAddr: testMACAddr,
	}
	testUplinkMACStr := strings.Replace(testUplinkAdapter.HardwareAddr.String(), ":", "", -1)
	testDNSServer := "192.168.1.21"
	testNetInterfaces := generateNetInterfaces()
	for i, itf := range testNetInterfaces {
		testNetInterfaces[i].Name = VirtualAdapterName(itf.Name)
	}
	newIPCmd := fmt.Sprintf(`New-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -PrefixLength %s -DefaultGateway %s`, VirtualAdapterName("0"), nodeZeroIPNetStr[0], nodeZeroIPNetStr[1], "testGateway")
	setServerCmd := fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias "%s" -ServerAddresses "%s"`, VirtualAdapterName("0"), testDNSServer)
	getAdapterCmd := fmt.Sprintf(`Get-VMNetworkAdapter -ManagementOS -ComputerName "$(hostname)" -SwitchName "%s" | ? MacAddress -EQ "%s" | Select-Object -Property Name | Format-Table -HideTableHeaders`, LocalHNSNetwork, testUplinkMACStr)
	renameAdapterCmd := fmt.Sprintf(`Get-VMNetworkAdapter -ManagementOS -ComputerName "$(hostname)" -Name "%s" | Rename-VMNetworkAdapter -NewName "%s"`, testAdapterName, testNewName)
	renameNetCmd := fmt.Sprintf(`Get-NetAdapter -Name "%s" | Rename-NetAdapter -NewName "%s"`, VirtualAdapterName(testNewName), testNewName)
	getVMCmd := fmt.Sprintf("Get-VMSwitch -ComputerName $(hostname) -Name %s | Select-Object -Property SoftwareRscEnabled | Format-Table -HideTableHeaders", LocalHNSNetwork)
	setVMCmd := fmt.Sprintf("Set-VMSwitch -ComputerName $(hostname) -Name %s -EnableSoftwareRsc $True", LocalHNSNetwork)
	tests := []struct {
		name                   string
		testAdapterAddresses   *windows.IpAdapterAddresses
		nodeIPNet              *net.IPNet
		dnsServers             string
		newName                string
		ipFound                bool
		hnsNetworkCreateErr    error
		commandErr             error
		hnsNetworkRequestError error
		testNetInterfaceErr    error
		createRowErr           error
		wantCmds               []string
		wantErr                error
	}{
		{
			name:                 "Prepare Success",
			testAdapterAddresses: createTestAdapterAddresses(testAdapterName),
			nodeIPNet:            &ipv4PublicIPNet,
			dnsServers:           testDNSServer,
			newName:              testNewName,
			ipFound:              true,
			wantCmds: []string{getAdapterCmd, renameAdapterCmd, renameNetCmd,
				getVMCmd, setVMCmd},
		},
		{
			name:                 "Create Error",
			testAdapterAddresses: createTestAdapterAddresses(testAdapterName),
			nodeIPNet:            &ipv4PublicIPNet,
			dnsServers:           testDNSServer,
			ipFound:              true,
			hnsNetworkCreateErr:  testInvalidErr,
			wantErr:              fmt.Errorf("error creating HNSNetwork: invalid"),
		},
		{
			name:                 "adapter Err",
			testAdapterAddresses: createTestAdapterAddresses(testAdapterName),
			nodeIPNet:            &ipv4PublicIPNet,
			dnsServers:           testDNSServer,
			ipFound:              true,
			testNetInterfaceErr:  testInvalidErr,
			wantErr:              testInvalidErr,
		},
		{
			name:                 "Rename Err",
			testAdapterAddresses: createTestAdapterAddresses(testAdapterName),
			nodeIPNet:            &ipv4PublicIPNet,
			dnsServers:           testDNSServer,
			newName:              testNewName,
			ipFound:              true,
			commandErr:           testInvalidErr,
			wantCmds:             []string{getAdapterCmd},
			wantErr:              testInvalidErr,
		},
		{
			name:                   "Enable HNS Err",
			testAdapterAddresses:   createTestAdapterAddresses(testAdapterName),
			nodeIPNet:              &ipv4PublicIPNet,
			dnsServers:             testDNSServer,
			ipFound:                true,
			hnsNetworkRequestError: testInvalidErr,
			wantErr:                testInvalidErr,
		},
		{
			name:                 "Enable RSC Err",
			testAdapterAddresses: createTestAdapterAddresses(testAdapterName),
			nodeIPNet:            &ipv4PublicIPNet,
			dnsServers:           testDNSServer,
			ipFound:              true,
			commandErr:           testInvalidErr,
			wantCmds:             []string{getVMCmd},
			wantErr:              testInvalidErr,
		},
		{
			name:                 "IP Not Found",
			testAdapterAddresses: createTestAdapterAddresses(testAdapterName),
			nodeIPNet:            &ipv4ZeroIPNet,
			dnsServers:           testDNSServer,
			ipFound:              false,
			wantCmds:             []string{newIPCmd, setServerCmd, getVMCmd, setVMCmd},
		},
		{
			name:                 "IP Not Found Configure Default Err",
			testAdapterAddresses: createTestAdapterAddresses(testAdapterName),
			nodeIPNet:            &ipv4ZeroIPNet,
			dnsServers:           testDNSServer,
			ipFound:              false,
			commandErr:           testInvalidErr,
			wantCmds:             []string{newIPCmd},
			wantErr:              testInvalidErr,
		},
		{
			name:                 "IP Not Found Set adapter Err",
			testAdapterAddresses: createTestAdapterAddresses(testAdapterName),
			nodeIPNet:            &ipv4ZeroIPNet,
			dnsServers:           testDNSServer,
			ipFound:              false,
			commandErr:           alreadyExistsErr,
			wantCmds:             []string{newIPCmd, setServerCmd},
			wantErr:              alreadyExistsErr,
		},
		{
			name:                 "IP Not Found New Net Route Err",
			testAdapterAddresses: createTestAdapterAddresses(testAdapterName),
			nodeIPNet:            &ipv4ZeroIPNet,
			ipFound:              false,
			createRowErr:         fmt.Errorf("ip route not found"),
			wantCmds:             []string{newIPCmd},
			wantErr:              fmt.Errorf("failed to create new IPForward row: ip route not found"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockRunCommand(t, tc.wantCmds, testAdapterName, tc.commandErr, true)()
			defer mockNetInterfaceGet(testNetInterfaces, tc.testNetInterfaceErr)()
			defer mockNetInterfaceAddrsMultiple(testNetInterfaces, tc.ipFound, nil)()
			defer mockHNSNetworkRequest(nil, tc.hnsNetworkRequestError)()
			defer mockHNSNetworkCreate(tc.hnsNetworkCreateErr)()
			defer mockHNSNetworkDelete(nil)()
			defer mockAntreaNetIO(&antreasyscalltest.MockNetIO{CreateIPForwardEntryErr: tc.createRowErr})()
			defer mockGetAdaptersAddresses(tc.testAdapterAddresses, nil)()
			gotErr := PrepareHNSNetwork(testSubnetCIDR, tc.nodeIPNet, testUplinkAdapter, "testGateway", tc.dnsServers, testRoutes, tc.newName)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestGetDefaultGatewayByInterfaceIndex(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("0.0.0.0/0")
	testIndex := uint32(27)
	testIPForwardRow := createTestMibIPForwardRow(testIndex, subnet, net.ParseIP("1.1.1.254"))
	listIPForwardRowsErr := fmt.Errorf("unable to list Windows IPForward rows: ip route not found")
	tests := []struct {
		name        string
		listRows    []antreasyscall.MibIPForwardRow
		listRowsErr error
		wantGateway string
		wantErr     error
	}{
		{
			name:        "Index Success",
			listRows:    []antreasyscall.MibIPForwardRow{testIPForwardRow},
			wantGateway: "1.1.1.254",
		},
		{
			name:        "Index Error",
			listRowsErr: fmt.Errorf("ip route not found"),
			wantErr:     listIPForwardRowsErr,
		},
		{
			name:     "Routes not found",
			listRows: []antreasyscall.MibIPForwardRow{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockAntreaNetIO(&antreasyscalltest.MockNetIO{ListIPForwardRowsErr: tc.listRowsErr, IPForwardRows: tc.listRows})()
			gotGateway, err := GetDefaultGatewayByInterfaceIndex((int)(testIndex))
			assert.Equal(t, tc.wantGateway, gotGateway)
			assert.Equal(t, tc.wantErr, err)
		})
	}
}

func TestGetDNServersByInterfaceIndex(t *testing.T) {
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
			defer mockRunCommand(t, []string{
				fmt.Sprintf("$(Get-DnsClientServerAddress -InterfaceIndex %d -AddressFamily IPv4).ServerAddresses", testIndex),
			}, tc.commandOut, tc.commandErr, true)()
			gotDNSServer, err := GetDNServersByInterfaceIndex(testIndex)
			assert.Equal(t, tc.wantDNSServer, gotDNSServer)
			assert.Equal(t, tc.commandErr, err)
		})
	}
}

func TestHostInterfaceExists(t *testing.T) {
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
			defer mockGetAdaptersAddresses(tc.testAdapterAddresses, nil)()
			gotExists := HostInterfaceExists(tc.testNetInterfaceName)
			assert.Equal(t, tc.testNetInterfaceName != "", gotExists)
		})
	}
}

func TestSetInterfaceMTU(t *testing.T) {
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
			wantErr: fmt.Errorf("unable to find NetAdapter on host in all compartments with name %s: %v", "",
				&net.OpError{Op: "route", Net: "ip+net", Source: nil, Addr: nil, Err: errInvalidInterfaceName}),
		},
		{
			name:                 "Get Interface Err",
			testNetInterfaceName: testName,
			testAdapterAddresses: testAdapterAddresses,
			getIPInterfaceErr:    fmt.Errorf("IP interface not found"),
			wantErr: fmt.Errorf("unable to set IPInterface with MTU %d: %v", testMTU,
				fmt.Errorf("unable to get IPInterface entry with Index %d: IP interface not found", (int)(testAdapterAddresses.IfIndex))),
		},
		{
			name:                 "Set Interface Err",
			testNetInterfaceName: testName,
			testAdapterAddresses: testAdapterAddresses,
			setIPInterfaceErr:    fmt.Errorf("IP interface set error"),
			wantErr:              fmt.Errorf("unable to set IPInterface with MTU %d: IP interface set error", testMTU),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockGetAdaptersAddresses(tc.testAdapterAddresses, nil)()
			defer mockAntreaNetIO(&antreasyscalltest.MockNetIO{GetIPInterfaceEntryErr: tc.getIPInterfaceErr, SetIPInterfaceEntryErr: tc.setIPInterfaceErr})()
			gotErr := SetInterfaceMTU(tc.testNetInterfaceName, testMTU)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestReplaceNetRoute(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("1.1.1.0/28")
	testIP := net.ParseIP("1.1.1.254")
	testIndex := uint32(27)
	testIPForwardRow := createTestMibIPForwardRow(testIndex, subnet, testIP)
	testRoute := Route{
		LinkIndex:         (int)(testIPForwardRow.Index),
		DestinationSubnet: subnet,
		GatewayAddress:    net.ParseIP("1.1.1.254"),
		RouteMetric:       MetricDefault,
	}
	listIPForwardRowsErr := fmt.Errorf("unable to list Windows IPForward rows: unable to list IP forward entry")
	deleteIPForwardEntryErr := fmt.Errorf("failed to delete existing route with nextHop %s: unable to delete IP forward entry", testRoute.GatewayAddress)
	createIPForwardEntryErr := fmt.Errorf("failed to create new IPForward row: unable to create IP forward entry")
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
			listRows: []antreasyscall.MibIPForwardRow{createTestMibIPForwardRow(testIndex, subnet, testIP)},
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
			defer mockAntreaNetIO(&antreasyscalltest.MockNetIO{CreateIPForwardEntryErr: tc.createIPForwardErr, DeleteIPForwardEntryErr: tc.deleteIPForwardErr, ListIPForwardRowsErr: tc.listRowsErr, IPForwardRows: tc.listRows})()
			gotErr := ReplaceNetRoute(&testRoute)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestNewNetNat(t *testing.T) {
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
			wantErr:    testInvalidErr,
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
			wantErr:    notFoundErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, true)()
			gotErr := NewNetNat(testNetNat, testSubnetCIDR)
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
			defer mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, true)()
			gotErr := ReplaceNetNatStaticMapping(testNetNat)
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
			defer mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, false)()
			gotErr := RemoveNetNatStaticMapping(testNetNat)
			assert.Equal(t, tc.wantErr, gotErr)
			gotErr = RemoveNetNatStaticMappingByNPLTuples(testNetNat)
			assert.Equal(t, tc.wantErr, gotErr)
			gotErr = RemoveNetNatStaticMappingByNAME(testNetNat.Name)
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
			defer mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, true)()
			gotErr := ReplaceNetNeighbor(testNeighbor)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestVirtualAdapterName(t *testing.T) {
	gotName := VirtualAdapterName("0")
	assert.Equal(t, "vEthernet (0)", gotName)
}

func TestGetInterfaceConfig(t *testing.T) {
	gw, subnet, _ := net.ParseCIDR("192.168.2.0/24")
	testRow := createTestMibIPForwardRow(0, subnet, gw)
	routes := []Route{*routeFromIPForwardRow(&testRow)}
	testRoutes := convertTestRoutes(routes)
	testNetInterface := generateNetInterface("0")
	tests := []struct {
		name                string
		testNetInterfaceErr error
		listRows            []antreasyscall.MibIPForwardRow
		listRowsErr         error
		wantAddrs           []*net.IPNet
		wantRoutes          []interface{}
		wantErr             error
	}{
		{
			name:       "Get Interface Config Success",
			listRows:   []antreasyscall.MibIPForwardRow{testRow},
			wantAddrs:  []*net.IPNet{&ipv4PublicIPNet},
			wantRoutes: testRoutes,
		},
		{
			name:                "Interface Err",
			testNetInterfaceErr: testInvalidErr,
			wantErr:             fmt.Errorf("failed to get interface %s: %v", "0", testInvalidErr),
		},
		{
			name:        "Route Err",
			listRows:    []antreasyscall.MibIPForwardRow{testRow},
			listRowsErr: fmt.Errorf("unable to list IP forward rows"),
			wantErr: fmt.Errorf("failed to get routes for interface index %d: %v", testNetInterface.Index,
				fmt.Errorf("unable to list Windows IPForward rows: unable to list IP forward rows")),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockNetInterfaceByName(&testNetInterface, tc.testNetInterfaceErr)()
			defer mockNetInterfaceAddrs(testNetInterface, nil)()
			defer mockAntreaNetIO(&antreasyscalltest.MockNetIO{IPForwardRows: tc.listRows, ListIPForwardRowsErr: tc.listRowsErr})()
			gotInterface, gotAddrs, gotRoutes, gotErr := GetInterfaceConfig("0")
			if tc.wantErr == nil {
				assert.EqualValues(t, testNetInterface, *gotInterface)
			}
			assert.Equal(t, tc.wantAddrs, gotAddrs)
			assert.EqualValues(t, tc.wantRoutes, gotRoutes)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestRenameInterface(t *testing.T) {
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
			wantErr:    fmt.Errorf("failed to rename host interface name test1 to test2"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockRunCommand(t, []string{
				fmt.Sprintf(`Get-NetAdapter -Name "%s" | Rename-NetAdapter -NewName "%s"`, "test1", "test2"),
			}, tc.commandOut, tc.commandErr, false)()
			gotErr := RenameInterface("test1", "test2")
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestCreateVMSwitch(t *testing.T) {
	notfoundErr := fmt.Errorf("unable to find a virtual switch with name \"antrea-switch\"")
	testSwitchName := "test-switch"
	getVMCmd := fmt.Sprintf(`Get-VMSwitch -Name "%s" -ComputerName $(hostname)`, LocalVMSwitch)
	getExtensionCmd := fmt.Sprintf(`Get-VMSwitchExtension -VMSwitchName "%s" -ComputerName $(hostname) | ? Id -EQ "%s"`, LocalVMSwitch, OVSExtensionID)
	newVMCmd := fmt.Sprintf(`New-VMSwitch -Name "%s" -NetAdapterName "%s" -EnableEmbeddedTeaming $true -AllowManagementOS $true -ComputerName $(hostname)| Enable-VMSwitchExtension "%s"`, LocalVMSwitch, testSwitchName, ovsExtensionName)
	enableCmd := fmt.Sprintf(`Get-VMSwitch -Name "%s" -ComputerName $(hostname)| Enable-VMSwitchExtension "%s"`, LocalVMSwitch, ovsExtensionName)
	type testFormat struct {
		name       string
		commandOut string
		commandErr error
		wantCmds   []string
		wantErr    error
	}
	tests := []testFormat{
		{
			name:       "VM Exists Enabled",
			commandOut: "Open vSwitch Extension Enabled True",
			wantCmds:   []string{getVMCmd, getExtensionCmd},
		},
		{
			name:       "Create Err",
			commandErr: notfoundErr,
			wantCmds:   []string{getVMCmd, newVMCmd},
			wantErr:    notfoundErr,
		},
		{
			name:       "VM Exists Err",
			commandErr: testInvalidErr,
			wantCmds:   []string{getVMCmd},
			wantErr:    testInvalidErr,
		},
		{
			name:       "VM Not Enabled",
			commandOut: "Open vSwitch Extension False",
			wantCmds:   []string{getVMCmd, getExtensionCmd, enableCmd},
		},
		{
			name:       "Extension Err",
			commandOut: "Extension False",
			wantCmds:   []string{getVMCmd, getExtensionCmd},
			wantErr:    fmt.Errorf("open vswitch extension driver is not installed"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, true)()
			gotErr := CreateVMSwitch(testSwitchName)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestGetVMSwitchInterfaceName(t *testing.T) {
	getVMCmd := fmt.Sprintf(`Get-VMSwitchTeam -Name "%s" | select NetAdapterInterfaceDescription |  Format-Table -HideTableHeaders`, LocalVMSwitch)
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
			defer mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, true)()
			gotName, gotErr := GetVMSwitchInterfaceName()
			assert.Equal(t, tc.wantName, gotName)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestRemoveVMSwitch(t *testing.T) {
	getCmd := fmt.Sprintf(`Get-VMSwitch -Name "%s" -ComputerName $(hostname)`, LocalVMSwitch)
	removeCmd := fmt.Sprintf(`Remove-VMSwitch -Name "%s" -ComputerName $(hostname) -Force`, LocalVMSwitch)
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
			defer mockRunCommand(t, tc.wantCmds, tc.commandOut, tc.commandErr, true)()
			gotErr := RemoveVMSwitch()
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestGenHostInterfaceName(t *testing.T) {
	hostInterface := GenHostInterfaceName("host~")
	assert.Equal(t, "host", hostInterface)
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
			defer mockGetAdaptersAddresses(tc.testAdapters, tc.testAdaptersErr)()
			gotAdapters, gotErr := getAdapterInAllCompartmentsByName(tc.testName)
			assert.EqualValues(t, tc.wantAdapters, gotAdapters)
			assert.EqualValues(t, tc.wantErr, gotErr)
		})
	}
}

func convertTestRoutes(routes []Route) []interface{} {
	testRoutes := make([]interface{}, len(routes))
	for i, v := range routes {
		testRoutes[i] = v
	}
	return testRoutes
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

func mockAntreaNetIO(mockNetIO *antreasyscalltest.MockNetIO) func() {
	originalNetIO := antreaNetIO
	antreaNetIO = mockNetIO
	return func() {
		antreaNetIO = originalNetIO
	}
}

func mockGetAdaptersAddresses(testAdaptersAddresses *windows.IpAdapterAddresses, err error) func() {
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
	return func() {
		getAdaptersAddresses = originalGetAdaptersAddresses
	}
}

// mockRunCommand mocks runCommand with a custom command output and error message.
// If exactMatch is enabled, this function asserts that the executed commands are
// exactly the same with wantCmds in terms of order and value. Otherwise, for tests
// with retry functions, the commands will be executed multiple times. This function
// asserts that wantCmds is strictly a subset of these executed commands.
func mockRunCommand(t *testing.T, wantCmds []string, commandOut string, err error, exactMatch bool) func() {
	originalRunCommand := runCommand
	actCmds := make([]string, 0)
	runCommand = func(cmd string) (string, error) {
		actCmds = append(actCmds, cmd)
		return commandOut, err
	}
	return func() {
		runCommand = originalRunCommand
		if wantCmds == nil {
			assert.Empty(t, actCmds)
		} else if exactMatch {
			assert.Equal(t, wantCmds, actCmds)
		} else {
			assert.Subset(t, actCmds, wantCmds)
		}
	}
}

func mockHNSNetworkRequest(testNetwork *hcsshim.HNSNetwork, err error) func() {
	originalHNSNetworkRequest := hnsNetworkRequest
	hnsNetworkRequest = func(method, path, request string) (*hcsshim.HNSNetwork, error) {
		return testNetwork, err
	}
	return func() {
		hnsNetworkRequest = originalHNSNetworkRequest
	}
}

func mockHNSNetworkCreate(err error) func() {
	originalHNSNetworkCreate := hnsNetworkCreate
	hnsNetworkCreate = func(network *hcsshim.HNSNetwork) (*hcsshim.HNSNetwork, error) {
		return network, err
	}
	return func() {
		hnsNetworkCreate = originalHNSNetworkCreate
	}
}

func mockHNSNetworkDelete(err error) func() {
	originalHNSNetworkDelete := hnsNetworkDelete
	hnsNetworkDelete = func(network *hcsshim.HNSNetwork) (*hcsshim.HNSNetwork, error) {
		return network, err
	}
	return func() {
		hnsNetworkDelete = originalHNSNetworkDelete
	}
}
