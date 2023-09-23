//go:build linux
// +build linux

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
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"go.uber.org/mock/gomock"

	netlinktest "antrea.io/antrea/pkg/agent/util/netlink/testing"
)

type mockLink struct {
	index        int
	name         string
	masterIndex  int
	hardwareAddr net.HardwareAddr
}

func (l mockLink) Attrs() *netlink.LinkAttrs {
	return &netlink.LinkAttrs{
		Index:        l.index,
		Name:         l.name,
		MasterIndex:  l.masterIndex,
		HardwareAddr: l.hardwareAddr,
	}
}

func (l mockLink) Type() string {
	return "mock"
}

type mockNetNS struct {
	file string
}

func (ns *mockNetNS) Do(toRun func(ns.NetNS) error) error {
	return toRun(ns)
}

func (ns *mockNetNS) Set() error {
	return nil
}

func (ns *mockNetNS) Path() string {
	return ns.file
}

func (ns *mockNetNS) Fd() uintptr {
	return 0
}

func (ns *mockNetNS) Close() error {
	return nil
}

func TestGetNSPeerDevBridge(t *testing.T) {
	testNetInterface := generateNetInterface("0")
	tests := []struct {
		name                string
		getNSErr            error
		getVethPeerErr      error
		testNetInterfaceErr error
		expectedCalls       func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
		wantErrStr          string
		wantName            string
	}{
		{
			name: "Get Bridge",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByIndex(2).Return(mockLink{masterIndex: 1}, nil)
				mockNetlink.LinkByIndex(1).Return((netlink.Link)(&netlink.Bridge{
					LinkAttrs: netlink.LinkAttrs{
						Name: "test-b0",
					},
				}), nil)
			},
			wantName: "test-b0",
		},
		{
			name:       "Get NS Err",
			getNSErr:   testInvalidErr,
			wantErrStr: "failed to get NS for path",
		},
		{
			name:           "Get V-eth Peer Err",
			getVethPeerErr: testInvalidErr,
			wantErrStr:     "failed to get peer idx for dev",
		},
		{
			name:                "Get Interface Err",
			testNetInterfaceErr: testInvalidErr,
			wantErrStr:          "failed to get interface for idx",
		},
		{
			name: "Get Link Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByIndex(2).Return(nil, testInvalidErr)
			},
			wantErrStr: "failed to get link for idx",
		},
		{
			name: "Not Attached to Bridge",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByIndex(2).Return(mockLink{masterIndex: -1}, nil)
			},
		},
		{
			name: "Get Bridge Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByIndex(2).Return(mockLink{masterIndex: 1}, nil)
				mockNetlink.LinkByIndex(1).Return(nil, testInvalidErr)
			},
			wantErrStr: "failed to get master link for dev",
		},
		{
			name: "Master Link not Bridge",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByIndex(2).Return(mockLink{masterIndex: 1}, nil)
				mockNetlink.LinkByIndex(1).Return(mockLink{}, nil)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer mockUtilNetlink(ctrl, tc.expectedCalls)()
			defer mockGetNS(&mockNetNS{}, tc.getNSErr)()
			defer mockNetNSDo()()
			defer mockGetVethPeerIfindex(nil, 2, tc.getVethPeerErr)()
			defer mockNetInterfaceByIndex(&testNetInterface, tc.testNetInterfaceErr)()
			gotInterface, gotName, gotErr := GetNSPeerDevBridge("test-path", "test-dev")
			assert.Equal(t, tc.wantName, gotName)
			if tc.wantErrStr == "" {
				assert.EqualValues(t, testNetInterface, *gotInterface)
				require.NoError(t, gotErr)
			} else {
				assert.Nil(t, gotInterface)
				assert.ErrorContains(t, gotErr, tc.wantErrStr)
			}
		})
	}
}

func TestGetNSDevInterface(t *testing.T) {
	testNetInterface := generateNetInterface("0")
	tests := []struct {
		name                string
		getNSErr            error
		testNetInterfaceErr error
		wantErrStr          string
	}{
		{
			name: "Get Interface",
		},
		{
			name:       "Get NS Err",
			getNSErr:   testInvalidErr,
			wantErrStr: "failed to get NS for path",
		},
		{
			name:                "Get Interface Err",
			testNetInterfaceErr: testInvalidErr,
			wantErrStr:          "failed to get interface",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockGetNS(&mockNetNS{}, tc.getNSErr)()
			defer mockNetNSDo()()
			defer mockNetInterfaceByName(&testNetInterface, tc.testNetInterfaceErr)()
			gotInterface, gotErr := GetNSDevInterface("test-path", "test-dev")
			if tc.wantErrStr == "" {
				assert.EqualValues(t, testNetInterface, *gotInterface)
				require.NoError(t, gotErr)
			} else {
				assert.Nil(t, gotInterface)
				assert.ErrorContains(t, gotErr, tc.wantErrStr)
			}
		})
	}
}

func TestGetNSPath(t *testing.T) {
	testPath := "test-path"
	testNetNS := &mockNetNS{file: testPath}
	tests := []struct {
		name       string
		getNSErr   error
		wantPath   string
		wantErrStr string
	}{
		{
			name:     "Get NS Path",
			wantPath: testPath,
		},
		{
			name:       "Get NS Err",
			getNSErr:   testInvalidErr,
			wantErrStr: "failed to open netns",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockGetNS(testNetNS, tc.getNSErr)()
			defer mockNetNSPath(testNetNS)()
			defer mockNetNSClose(testNetNS)()
			gotPath, gotErr := GetNSPath(testPath)
			assert.Equal(t, tc.wantPath, gotPath)
			if tc.wantErrStr == "" {
				require.NoError(t, gotErr)
			} else {
				assert.ErrorContains(t, gotErr, tc.wantErrStr)
			}
		})
	}
}

func TestSetLinkUp(t *testing.T) {
	testLink := mockLink{
		index:        1,
		name:         "antrea-en0",
		hardwareAddr: testMACAddr,
	}
	tests := []struct {
		name          string
		expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
		wantErr       error
		wantMac       net.HardwareAddr
		wantIndex     int
	}{
		{
			name: "Set Link Up Normal",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("antrea-en0").Return(testLink, nil)
				mockNetlink.LinkSetUp(testLink).Return(nil)
			},
			wantMac:   testMACAddr,
			wantIndex: 1,
		},
		{
			name: "Get Link Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("antrea-en0").Return(nil, testInvalidErr)
			},
			wantErr:   testInvalidErr,
			wantIndex: 0,
		},
		{
			name: "Get Link Not Found",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("antrea-en0").Return(nil, netlink.LinkNotFoundError{})
			},
			wantErr: LinkNotFound{
				fmt.Errorf("link antrea-en0 not found"),
			},
			wantIndex: 0,
		},
		{
			name: "Setup Link Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("antrea-en0").Return(testLink, nil)
				mockNetlink.LinkSetUp(testLink).Return(testInvalidErr)
			},
			wantErr:   testInvalidErr,
			wantIndex: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer mockUtilNetlink(ctrl, tc.expectedCalls)()
			defer mockUtilNetlinkAttrs(testLink)()
			gotMac, gotIndex, gotErr := SetLinkUp("antrea-en0")
			assert.Equal(t, tc.wantMac, gotMac)
			assert.Equal(t, tc.wantIndex, gotIndex)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestConfigureLinkAddresses(t *testing.T) {
	testLink := mockLink{name: "test-en0"}
	testPublicAddr := netlink.Addr{IPNet: &ipv4PublicIPNet}
	testZeroAddr := netlink.Addr{IPNet: &ipv4ZeroIPNet}
	testPublicAddrList := []netlink.Addr{testPublicAddr}
	testLocalAddrList := append(testPublicAddrList, netlink.Addr{
		IPNet: &net.IPNet{
			IP:   net.ParseIP("169.254.0.0"),
			Mask: net.CIDRMask(32, 32),
		}})
	tests := []struct {
		name          string
		ipNets        []*net.IPNet
		expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
		wantErr       error
	}{
		{
			name:   "Configure Link Addr",
			ipNets: []*net.IPNet{&ipv4ZeroIPNet},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByIndex(0).Return(testLink, nil)
				mockNetlink.AddrList(testLink, netlink.FAMILY_ALL).Return(testPublicAddrList, nil)
				mockNetlink.AddrDel(testLink, &testPublicAddr).Return(nil)
				mockNetlink.AddrAdd(testLink, &testZeroAddr).Return(nil)
			},
		},
		{
			name:   "Configure Link Addr with link-local",
			ipNets: []*net.IPNet{&ipv4ZeroIPNet},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByIndex(0).Return(testLink, nil)
				mockNetlink.AddrList(testLink, netlink.FAMILY_ALL).Return(testLocalAddrList, nil)
				mockNetlink.AddrDel(testLink, &testPublicAddr).Return(nil)
				mockNetlink.AddrAdd(testLink, &testZeroAddr).Return(nil)
			},
		},
		{
			name:   "Net Interface Err",
			ipNets: []*net.IPNet{},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByIndex(0).Return(testLink, testInvalidErr)
			},
			wantErr: testInvalidErr,
		},
		{
			name:   "Link Addr Err",
			ipNets: []*net.IPNet{},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByIndex(0).Return(testLink, nil)
				mockNetlink.AddrList(testLink, netlink.FAMILY_ALL).Return(testPublicAddrList, testInvalidErr)
			},
			wantErr: fmt.Errorf("failed to query address list for interface test-en0: invalid"),
		},
		{
			name:   "Link Addr No Change",
			ipNets: []*net.IPNet{&ipv4PublicIPNet},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByIndex(0).Return(testLink, nil)
				mockNetlink.AddrList(testLink, netlink.FAMILY_ALL).Return(testPublicAddrList, nil)
			},
		},
		{
			name:   "Link Addr Remove Err",
			ipNets: []*net.IPNet{&ipv4ZeroIPNet},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByIndex(0).Return(testLink, nil)
				mockNetlink.AddrList(testLink, netlink.FAMILY_ALL).Return(testPublicAddrList, nil)
				mockNetlink.AddrDel(testLink, &testPublicAddr).Return(testInvalidErr)
			},
			wantErr: fmt.Errorf("failed to remove address 8.8.8.8/32 from interface test-en0: invalid"),
		},
		{
			name:   "Link Addr Add Err",
			ipNets: []*net.IPNet{&ipv4ZeroIPNet},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByIndex(0).Return(testLink, nil)
				mockNetlink.AddrList(testLink, netlink.FAMILY_ALL).Return(testPublicAddrList, nil)
				mockNetlink.AddrDel(testLink, &testPublicAddr).Return(nil)
				mockNetlink.AddrAdd(testLink, &testZeroAddr).Return(testInvalidErr)
			},
			wantErr: fmt.Errorf("failed to add address 0.0.0.0/32 to interface test-en0: invalid"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer mockUtilNetlink(ctrl, tc.expectedCalls)()
			defer mockUtilNetlinkAttrs(testLink)()
			gotErr := ConfigureLinkAddresses(0, tc.ipNets)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestSetAdapterMACAddress(t *testing.T) {
	testLink := mockLink{name: "test-en0"}
	tests := []struct {
		name          string
		expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
		wantErr       error
	}{
		{
			name: "Set adapter MAC",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("test-en0").Return(testLink, nil)
				mockNetlink.LinkSetHardwareAddr(testLink, testMACAddr).Return(nil)
			},
		},
		{
			name: "Get Link Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("test-en0").Return(nil, testInvalidErr)
			},
			wantErr: testInvalidErr,
		},
		{
			name: "Set Hardware Addr Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("test-en0").Return(testLink, nil)
				mockNetlink.LinkSetHardwareAddr(testLink, testMACAddr).Return(testInvalidErr)
			},
			wantErr: testInvalidErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer mockUtilNetlink(ctrl, tc.expectedCalls)()
			gotErr := SetAdapterMACAddress("test-en0", &testMACAddr)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestHostInterfaceExists(t *testing.T) {
	tests := []struct {
		name          string
		expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
		wantExists    bool
	}{
		{
			name: "Interface Exists",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("test-en0").Return(mockLink{name: "test-en0"}, nil)
			},
			wantExists: true,
		},
		{
			name: "Interface Fail",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("test-en0").Return(nil, testInvalidErr)
			},
			wantExists: false,
		},
		{
			name: "Interface Not Exist",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("test-en0").Return(nil, netlink.LinkNotFoundError{})
			},
			wantExists: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer mockUtilNetlink(ctrl, tc.expectedCalls)()
			gotExists := HostInterfaceExists("test-en0")
			assert.Equal(t, tc.wantExists, gotExists)
		})
	}
}

func TestGetInterfaceConfig(t *testing.T) {
	routes := []netlink.Route{{
		LinkIndex: 0,
	}}
	testRoutes := createTestRoutes(routes)
	testNetInterface := generateNetInterface("0")
	tests := []struct {
		name                string
		testNetInterfaceErr error
		testNetAddrsErr     error
		expectedCalls       func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
		wantAddrs           []*net.IPNet
		wantRoutes          []interface{}
		wantErrStr          string
	}{
		{
			name: "Get Interface Config Success",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByIndex(0).Return(mockLink{name: "test-en0"}, nil)
				mockNetlink.RouteList(mockLink{name: "test-en0"}, netlink.FAMILY_ALL).Return(routes, nil)
			},
			wantAddrs: []*net.IPNet{
				{
					IP:   ipv4Public,
					Mask: net.CIDRMask(32, 32),
				},
			},
			wantRoutes: testRoutes,
		},
		{
			name:                "Interface Err",
			testNetInterfaceErr: testInvalidErr,
			wantErrStr:          "failed to get interface by name 0",
		},
		{
			name:            "Get Address Err",
			testNetAddrsErr: testInvalidErr,
			wantErrStr:      "failed to get address for interface 0",
		},
		{
			name: "Net Link Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByIndex(0).Return(nil, testInvalidErr)
			},
			wantErrStr: "failed to get routes for iface.Index 0",
		},
		{
			name: "Route List Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByIndex(0).Return(mockLink{name: "test-en0"}, nil)
				mockNetlink.RouteList(mockLink{name: "test-en0"}, netlink.FAMILY_ALL).Return(nil, testInvalidErr)
			},
			wantErrStr: "failed to get routes for iface.Index 0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer mockUtilNetlink(ctrl, tc.expectedCalls)()
			defer mockNetInterfaceByName(&testNetInterface, tc.testNetInterfaceErr)()
			defer mockNetInterfaceAddrs(testNetInterface, tc.testNetAddrsErr)()
			gotInterface, gotAddrs, gotRoutes, gotErr := GetInterfaceConfig("0")
			assert.Equal(t, tc.wantAddrs, gotAddrs)
			assert.EqualValues(t, tc.wantRoutes, gotRoutes)
			if tc.wantErrStr == "" {
				assert.EqualValues(t, testNetInterface, *gotInterface)
				require.NoError(t, gotErr)
			} else {
				assert.Nil(t, gotInterface)
				assert.ErrorContains(t, gotErr, tc.wantErrStr)
			}
		})
	}
}

func TestRenameInterface(t *testing.T) {
	renameFailErr := fmt.Errorf("failed to rename host interface name test1 to test2")
	tests := []struct {
		name          string
		expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
		wantErr       error
	}{
		{
			name: "Rename Interface Success",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("test1").Return(mockLink{name: "test1"}, nil)
				mockNetlink.LinkSetDown(mockLink{name: "test1"}).Return(nil)
				mockNetlink.LinkSetName(mockLink{name: "test1"}, "test2").Return(nil)
				mockNetlink.LinkSetUp(mockLink{name: "test1"}).Return(nil)
			},
		},
		{
			name: "Interface Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("test1").Return(mockLink{name: "test1"}, testInvalidErr).AnyTimes()
			},
			wantErr: renameFailErr,
		},
		{
			name: "Set Down Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("test1").Return(mockLink{name: "test1"}, nil).AnyTimes()
				mockNetlink.LinkSetDown(mockLink{name: "test1"}).Return(testInvalidErr).AnyTimes()
			},
			wantErr: renameFailErr,
		},
		{
			name: "Set Name Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("test1").Return(mockLink{name: "test1"}, nil).AnyTimes()
				mockNetlink.LinkSetDown(mockLink{name: "test1"}).Return(nil).AnyTimes()
				mockNetlink.LinkSetName(mockLink{name: "test1"}, "test2").Return(testInvalidErr).AnyTimes()
			},
			wantErr: renameFailErr,
		},
		{
			name: "Set Up Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("test1").Return(mockLink{name: "test1"}, nil).AnyTimes()
				mockNetlink.LinkSetDown(mockLink{name: "test1"}).Return(nil).AnyTimes()
				mockNetlink.LinkSetName(mockLink{name: "test1"}, "test2").Return(nil).AnyTimes()
				mockNetlink.LinkSetUp(mockLink{name: "test1"}).Return(testInvalidErr).AnyTimes()
			},
			wantErr: renameFailErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer mockUtilNetlink(ctrl, tc.expectedCalls)()
			gotErr := RenameInterface("test1", "test2")
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestRemoveLinkIPs(t *testing.T) {
	testLink := mockLink{name: "test"}
	testAddrList := []netlink.Addr{{IPNet: &ipv4PublicIPNet}}
	tests := []struct {
		name          string
		expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
		wantErr       error
	}{
		{
			name: "Remove Link IP Success",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.AddrList(testLink, netlink.FAMILY_ALL).Return(testAddrList, nil)
				mockNetlink.AddrDel(testLink, &testAddrList[0]).Return(nil)
			},
		},
		{
			name: "Addr List Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.AddrList(testLink, netlink.FAMILY_ALL).Return(testAddrList, testInvalidErr)
			},
			wantErr: testInvalidErr,
		},
		{
			name: "Addr Del Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.AddrList(testLink, netlink.FAMILY_ALL).Return(testAddrList, nil)
				mockNetlink.AddrDel(testLink, &testAddrList[0]).Return(testInvalidErr)
			},
			wantErr: testInvalidErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer mockUtilNetlink(ctrl, tc.expectedCalls)()
			gotErr := RemoveLinkIPs(mockLink{name: "test"})
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestRemoveLinkRoutes(t *testing.T) {
	testLink := mockLink{name: "test"}
	testRoute := netlink.Route{LinkIndex: 0}
	tests := []struct {
		name          string
		expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
		wantErr       error
	}{
		{
			name: "Remove Link Route Success",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteList(testLink, netlink.FAMILY_ALL).Return([]netlink.Route{testRoute}, nil)
				mockNetlink.RouteDel(&testRoute).Return(nil)
			},
		},
		{
			name: "Route List Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteList(testLink, netlink.FAMILY_ALL).Return(nil, testInvalidErr)
			},
			wantErr: testInvalidErr,
		},
		{
			name: "Route Del Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteList(testLink, netlink.FAMILY_ALL).Return([]netlink.Route{testRoute}, nil)
				mockNetlink.RouteDel(&testRoute).Return(testInvalidErr)
			},
			wantErr: testInvalidErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer mockUtilNetlink(ctrl, tc.expectedCalls)()
			gotErr := RemoveLinkRoutes(mockLink{name: "test"})
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestConfigureLinkRoutes(t *testing.T) {
	routes := []netlink.Route{{LinkIndex: 0}}
	testRoutes := createTestRoutes(routes)
	routes[0].LinkIndex = 1
	testLink := mockLink{index: 1}
	tests := []struct {
		name          string
		expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
		wantErr       error
	}{
		{
			name: "Configure Link Route Success",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(&routes[0]).Return(nil)
			},
		},
		{
			name: "Route Replace Err",
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(&routes[0]).Return(testInvalidErr)
			},
			wantErr: testInvalidErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer mockUtilNetlink(ctrl, tc.expectedCalls)()
			defer mockUtilNetlinkAttrs(testLink)()
			gotErr := ConfigureLinkRoutes(testLink, testRoutes)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func createTestRoutes(routes []netlink.Route) []interface{} {
	testRoutes := make([]interface{}, len(routes))
	for i, v := range routes {
		testRoutes[i] = v
	}
	return testRoutes
}

func mockUtilNetlink(ctrl *gomock.Controller, expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)) func() {
	originalNetlinkInterface := netlinkUtil
	testNetlinkInterface := netlinktest.NewMockInterface(ctrl)
	netlinkUtil = testNetlinkInterface
	if expectedCalls != nil {
		expectedCalls(testNetlinkInterface.EXPECT())
	}
	return func() {
		netlinkUtil = originalNetlinkInterface
	}
}

func mockUtilNetlinkAttrs(testLink netlink.Link) func() {
	originalNetlinkAttrs := netlinkAttrs
	netlinkAttrs = func(link netlink.Link) *netlink.LinkAttrs {
		return testLink.Attrs()
	}
	return func() {
		netlinkAttrs = originalNetlinkAttrs
	}
}

func mockGetNS(testNS ns.NetNS, err error) func() {
	originalGetNS := getNS
	getNS = func(nspath string) (ns.NetNS, error) {
		return testNS, err
	}
	return func() {
		getNS = originalGetNS
	}
}

func mockNetNSDo() func() {
	originalNetNSDo := netNSDo
	netNSDo = func(netNS ns.NetNS, f func(ns.NetNS) error) error {
		return f(netNS)
	}
	return func() {
		netNSDo = originalNetNSDo
	}
}

func mockNetNSPath(testNS ns.NetNS) func() {
	originalNetNSPath := netNSPath
	netNSPath = func(netNS ns.NetNS) string {
		return testNS.Path()
	}
	return func() {
		netNSPath = originalNetNSPath
	}
}

func mockNetNSClose(testNS ns.NetNS) func() {
	originalNetNSClose := netNSClose
	netNSClose = func(netNS ns.NetNS) error {
		return testNS.Close()
	}
	return func() {
		netNSClose = originalNetNSClose
	}
}

func mockGetVethPeerIfindex(testLink netlink.Link, ifindex int, err error) func() {
	originalGetVethPeerIfindex := getVethPeerIfindex
	getVethPeerIfindex = func(ifName string) (netlink.Link, int, error) {
		return testLink, ifindex, err
	}
	return func() {
		getVethPeerIfindex = originalGetVethPeerIfindex
	}
}
