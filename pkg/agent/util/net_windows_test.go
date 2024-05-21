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
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	antreasyscall "antrea.io/antrea/pkg/agent/util/syscall"
	"antrea.io/antrea/pkg/agent/util/winnet"
	winnettesting "antrea.io/antrea/pkg/agent/util/winnet/testing"
)

func TestGetNSPath(t *testing.T) {
	testNSPath := "/dev/null"
	gotNSPath, err := GetNSPath(testNSPath)
	require.NoError(t, err)
	assert.Equal(t, testNSPath, gotNSPath)
}

func TestSetLinkUp(t *testing.T) {
	testName := "test-link"
	tests := []struct {
		name           string
		gwInterface    *net.Interface
		gwInterfaceErr error
		expectedError  error
		expectedCalls  func(mockNetUtil *winnettesting.MockInterfaceMockRecorder)
	}{
		{
			name: "Set Link Up Normal",
			gwInterface: &net.Interface{
				Index:        1,
				Name:         testName,
				HardwareAddr: testMACAddr,
			},
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.EnableNetAdapter(testName).Return(nil).MinTimes(1)
				mockUtil.IsNetAdapterStatusUp(testName).Return(true, nil).Times(1)
			},
		},
		{
			name:           "Enable Interface Err",
			gwInterface:    &net.Interface{Index: 0},
			gwInterfaceErr: fmt.Errorf("failed to enable network adapter %s", testName),
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.EnableNetAdapter(testName).Return(fmt.Errorf("failed to enable interface %s: failed reason", testName)).MinTimes(1)
			},
		},
		{
			name:           "Get Interface Err",
			gwInterface:    &net.Interface{Index: 0},
			gwInterfaceErr: testInvalidErr,
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.EnableNetAdapter(testName).Return(nil).MinTimes(1)
				mockUtil.IsNetAdapterStatusUp(testName).Return(true, nil).Times(1)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer mockUtilWinnet(ctrl, tc.expectedCalls)()
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
	tests := []struct {
		name                string
		ipNets              []*net.IPNet
		testNetInterfaceErr error
		testNetAddrsErr     error
		expectedCalls       func(mockNetUtil *winnettesting.MockInterfaceMockRecorder)
		wantErr             error
	}{
		{
			name:   "Configure Link Addr",
			ipNets: []*net.IPNet{&ipv4ZeroIPNet},
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.RemoveNetAdapterIPAddress("0", ipv4Public).Return(nil).Times(1)
				mockUtil.AddNetAdapterIPAddress("0", &ipv4ZeroIPNet, "").Return(nil).Times(1)
			},
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
			name:   "Link Addr No Change",
			ipNets: []*net.IPNet{&ipv4PublicIPNet},
		},
		{
			name:    "Link Addr Configure Err",
			ipNets:  []*net.IPNet{&ipv4ZeroIPNet},
			wantErr: fmt.Errorf("failed to add address 0.0.0.0/32 to interface 0: interface No matching"),
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.RemoveNetAdapterIPAddress("0", ipv4Public).Return(nil).Times(1)
				mockUtil.AddNetAdapterIPAddress("0", &ipv4ZeroIPNet, "").Return(fmt.Errorf("interface No matching")).Times(1)
			},
		},
		{
			name:    "Link Addr Remove Err",
			ipNets:  []*net.IPNet{&ipv4ZeroIPNet},
			wantErr: fmt.Errorf("failed to remove address 8.8.8.8/32 from interface 0: interface already exists"),
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.RemoveNetAdapterIPAddress("0", ipv4Public).Return(fmt.Errorf("interface already exists")).Times(1)
			},
		},
		{
			name: "Link Addr IPv6 Not Supported",
			ipNets: []*net.IPNet{
				{
					IP:   net.IPv6zero,
					Mask: net.CIDRMask(128, 128),
				},
			},
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.RemoveNetAdapterIPAddress("0", ipv4Public).Return(nil).Times(1)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer mockUtilWinnet(ctrl, tc.expectedCalls)()
			defer mockNetInterfaceByIndex(&testNetInterface, tc.testNetInterfaceErr)()
			defer mockNetInterfaceAddrs(testNetInterface, tc.testNetAddrsErr)()
			gotErr := ConfigureLinkAddresses(0, tc.ipNets)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestPrepareHNSNetwork(t *testing.T) {
	gw, subnet, _ := net.ParseCIDR("8.8.8.8/32")
	alreadyExistsErr := fmt.Errorf("already exists")
	routes := []winnet.Route{{
		LinkIndex:         0,
		DestinationSubnet: subnet,
		GatewayAddress:    gw,
		RouteMetric:       winnet.MetricDefault,
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
		testNetInterfaces[i].Name = winnet.VirtualAdapterName(itf.Name)
	}
	tests := []struct {
		name                   string
		nodeIPNet              *net.IPNet
		dnsServers             string
		newName                string
		ipFound                bool
		hnsNetworkCreateErr    error
		hnsNetworkRequestError error
		testNetInterfaceErr    error
		createRowErr           error
		expectedCalls          func(mockNetUtil *winnettesting.MockInterfaceMockRecorder)
		wantErr                error
	}{
		{
			name:       "Prepare Success",
			nodeIPNet:  &ipv4PublicIPNet,
			dnsServers: testDNSServer,
			newName:    testNewName,
			ipFound:    true,
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.RenameVMNetworkAdapter(LocalHNSNetwork, testUplinkMACStr, testNewName, true).Times(1)
				mockUtil.EnableRSCOnVSwitch(LocalHNSNetwork).Times(1)
			},
		},
		{
			name:                "Create Error",
			nodeIPNet:           &ipv4PublicIPNet,
			dnsServers:          testDNSServer,
			ipFound:             true,
			hnsNetworkCreateErr: testInvalidErr,
			wantErr:             fmt.Errorf("error creating HNSNetwork: invalid"),
		},
		{
			name:                "adapter Err",
			nodeIPNet:           &ipv4PublicIPNet,
			dnsServers:          testDNSServer,
			ipFound:             true,
			testNetInterfaceErr: testInvalidErr,
			wantErr:             testInvalidErr,
		},
		{
			name:       "Rename Err",
			nodeIPNet:  &ipv4PublicIPNet,
			dnsServers: testDNSServer,
			newName:    testNewName,
			ipFound:    true,
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.RenameVMNetworkAdapter(LocalHNSNetwork, testUplinkMACStr, testNewName, true).Return(testInvalidErr).Times(1)
			},
			wantErr: testInvalidErr,
		},
		{
			name:                   "Enable HNS Err",
			nodeIPNet:              &ipv4PublicIPNet,
			dnsServers:             testDNSServer,
			ipFound:                true,
			hnsNetworkRequestError: testInvalidErr,
			wantErr:                testInvalidErr,
		},
		{
			name:       "Enable RSC Err",
			nodeIPNet:  &ipv4PublicIPNet,
			dnsServers: testDNSServer,
			ipFound:    true,
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.EnableRSCOnVSwitch(LocalHNSNetwork).Return(testInvalidErr).Times(1)
			},
			wantErr: testInvalidErr,
		},
		{
			name:       "IP Not Found",
			nodeIPNet:  &ipv4ZeroIPNet,
			dnsServers: testDNSServer,
			ipFound:    false,
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.IsNetAdapterIPv4DHCPEnabled(testAdapterName).Times(1)
				mockUtil.AddNetAdapterIPAddress(winnet.VirtualAdapterName("0"), &ipv4ZeroIPNet, "testGateway").Times(1)
				mockUtil.SetNetAdapterDNSServers(winnet.VirtualAdapterName("0"), testDNSServer).Times(1)
				mockUtil.AddNetRoute(gomock.Any()).Times(1)
				mockUtil.EnableRSCOnVSwitch(LocalHNSNetwork).Times(1)
			},
		},
		{
			name:       "IP Not Found Configure adapter Err",
			nodeIPNet:  &ipv4ZeroIPNet,
			dnsServers: testDNSServer,
			ipFound:    false,
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.IsNetAdapterIPv4DHCPEnabled(testAdapterName).Times(1)
				mockUtil.AddNetAdapterIPAddress(winnet.VirtualAdapterName("0"), &ipv4ZeroIPNet, "testGateway").Return(alreadyExistsErr).Times(1)
			},
			wantErr: alreadyExistsErr,
		},
		{
			name:         "IP Not Found New Net Route Err",
			nodeIPNet:    &ipv4ZeroIPNet,
			ipFound:      false,
			createRowErr: fmt.Errorf("ip route not found"),
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.IsNetAdapterIPv4DHCPEnabled(testAdapterName).Times(1)
				mockUtil.AddNetAdapterIPAddress(winnet.VirtualAdapterName("0"), &ipv4ZeroIPNet, "testGateway").Times(1)
				mockUtil.AddNetRoute(gomock.Any()).Return(fmt.Errorf("failed to create new IPForward row: ip route not found")).Times(1)
			},
			wantErr: fmt.Errorf("failed to create new IPForward row: ip route not found"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer mockUtilWinnet(ctrl, tc.expectedCalls)()
			defer mockNetInterfaceGet(testNetInterfaces, tc.testNetInterfaceErr)()
			defer mockNetInterfaceAddrsMultiple(testNetInterfaces, tc.ipFound, nil)()
			defer mockHNSNetworkRequest(nil, tc.hnsNetworkRequestError)()
			defer mockHNSNetworkCreate(tc.hnsNetworkCreateErr)()
			defer mockHNSNetworkDelete(nil)()
			gotErr := PrepareHNSNetwork(testSubnetCIDR, tc.nodeIPNet, testUplinkAdapter, "testGateway", tc.dnsServers, testRoutes, tc.newName)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestGetDefaultGatewayByInterfaceIndex(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("1.1.1.0/28")
	testGateway := net.ParseIP("1.1.1.254")
	testIndex := 27
	testRoutes := []winnet.Route{
		{
			LinkIndex:         testIndex,
			DestinationSubnet: subnet,
			GatewayAddress:    testGateway,
			RouteMetric:       winnet.MetricDefault,
		},
	}

	ip, defaultDestination, _ := net.ParseCIDR("0.0.0.0/0")
	family := winnet.AddressFamilyByIP(ip)
	filter := &winnet.Route{
		LinkIndex:         testIndex,
		DestinationSubnet: defaultDestination,
	}
	filterMask := winnet.RT_FILTER_IF | winnet.RT_FILTER_DST
	listRouteErr := fmt.Errorf("unable to list Windows IPForward rows: ip route not found")

	tests := []struct {
		name          string
		expectedCalls func(mockNetUtil *winnettesting.MockInterfaceMockRecorder)
		wantGateway   string
		wantErr       error
	}{
		{
			name:        "Index Success",
			wantGateway: testGateway.String(),
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.RouteListFiltered(family, filter, filterMask).Return(testRoutes, nil).Times(1)
			},
		},
		{
			name: "Index Error",
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.RouteListFiltered(family, filter, filterMask).Return(nil, listRouteErr).Times(1)
			},
			wantErr: listRouteErr,
		},
		{
			name: "Routes not found",
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.RouteListFiltered(family, filter, filterMask).Return(nil, nil).Times(1)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer mockUtilWinnet(ctrl, tc.expectedCalls)()
			gotGateway, err := GetDefaultGatewayByInterfaceIndex((int)(testIndex))
			assert.Equal(t, tc.wantGateway, gotGateway)
			assert.Equal(t, tc.wantErr, err)
		})
	}
}

func TestGetInterfaceConfig(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("1.1.1.0/28")
	testGateway := net.ParseIP("1.1.1.254")
	testIndex := 0
	testRoutes := []winnet.Route{
		{
			LinkIndex:         testIndex,
			DestinationSubnet: subnet,
			GatewayAddress:    testGateway,
			RouteMetric:       winnet.MetricDefault,
		},
	}
	testNetInterface := generateNetInterface("0")

	family := antreasyscall.AF_UNSPEC
	filter := &winnet.Route{
		LinkIndex: testIndex,
	}
	filterMask := winnet.RT_FILTER_IF

	listRouteErr := fmt.Errorf("unable to list Windows IPForward rows: unable to list IP forward rows")

	tests := []struct {
		name                string
		testNetInterfaceErr error
		expectedCalls       func(mockNetUtil *winnettesting.MockInterfaceMockRecorder)
		wantAddrs           []*net.IPNet
		wantRoutes          []interface{}
		wantErr             error
	}{
		{
			name:       "Get Interface Config Success",
			wantAddrs:  []*net.IPNet{&ipv4PublicIPNet},
			wantRoutes: convertTestRoutes(testRoutes),
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.RouteListFiltered(family, filter, filterMask).Return(testRoutes, nil).Times(1)
			},
		},
		{
			name:                "Interface Err",
			testNetInterfaceErr: testInvalidErr,
			wantErr:             fmt.Errorf("failed to get interface %s: %v", "0", testInvalidErr),
		},
		{
			name:    "Route Err",
			wantErr: fmt.Errorf("failed to get routes for interface index %d: %v", testNetInterface.Index, listRouteErr),
			expectedCalls: func(mockUtil *winnettesting.MockInterfaceMockRecorder) {
				mockUtil.RouteListFiltered(family, filter, filterMask).Return(nil, listRouteErr).Times(1)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer mockUtilWinnet(ctrl, tc.expectedCalls)()
			defer mockNetInterfaceByName(&testNetInterface, tc.testNetInterfaceErr)()
			defer mockNetInterfaceAddrs(testNetInterface, nil)()

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

func convertTestRoutes(routes []winnet.Route) []interface{} {
	testRoutes := make([]interface{}, len(routes))
	for i, v := range routes {
		testRoutes[i] = v
	}
	return testRoutes
}

func TestGenHostInterfaceName(t *testing.T) {
	hostInterface := GenHostInterfaceName("host~")
	assert.Equal(t, "host", hostInterface)
}

func mockUtilWinnet(ctrl *gomock.Controller, expectedCalls func(mockWinnet *winnettesting.MockInterfaceMockRecorder)) func() {
	originalWinnetInterface := winnetUtil
	testWinnetInterface := winnettesting.NewMockInterface(ctrl)
	winnetUtil = testWinnetInterface
	if expectedCalls != nil {
		expectedCalls(testWinnetInterface.EXPECT())
	}
	return func() {
		winnetUtil = originalWinnetInterface
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
