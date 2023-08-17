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

package ipassigner

import (
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	gomock "go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/util/sets"

	respondertest "antrea.io/antrea/pkg/agent/ipassigner/responder/testing"
	netlinktest "antrea.io/antrea/pkg/agent/util/netlink/testing"
	crdv1b1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

func ensureRPFInt(name string, y int) error {
	return nil
}

func DummyInterfaceByName(name string) (*net.Interface, error) {
	return &net.Interface{
		Index:        0,
		MTU:          1500,
		Name:         "eth0",
		HardwareAddr: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	}, nil
}

func newFakeNetworkInterface() *net.Interface {
	return &net.Interface{
		Index:        0,
		MTU:          1500,
		Name:         "eth0",
		HardwareAddr: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	}
}

type dummyDeviceMock struct {
	addedIPs []net.IPNet
	vlanID   int
}

func (d *dummyDeviceMock) Attrs() *netlink.LinkAttrs {
	if d.vlanID == 0 {
		return &netlink.LinkAttrs{Name: "antrea-dummy0"}
	}
	return &netlink.LinkAttrs{Name: fmt.Sprintf("antrea-ext.%d", d.vlanID)}
}

func (d *dummyDeviceMock) AddrAdd(addr *netlink.Addr) error {
	ipNet := net.IPNet{
		IP:   addr.IPNet.IP,
		Mask: net.CIDRMask(32, 32),
	}
	d.addedIPs = append(d.addedIPs, ipNet)
	return nil
}

func (d *dummyDeviceMock) Type() string {
	return "dummy"
}

func TestIPAssigner_AssignIP(t *testing.T) {
	var err error
	var subnetInfo *crdv1b1.SubnetInfo

	controller := gomock.NewController(t)
	mockResponder := respondertest.NewMockResponder(controller)
	mockNetlink := netlinktest.NewMockInterface(controller)

	tests := []struct {
		name                string
		ip                  string
		vlanid              int
		assignedIPs         map[string]*crdv1b1.SubnetInfo
		ips                 sets.Set[string]
		expectedError       bool
		expectedAssignedIPs map[string]*crdv1b1.SubnetInfo
		expectFunc          func(mock *respondertest.MockResponder)
		expectedCalls       func(mockNetlink *netlinktest.MockInterface)
	}{
		{
			name:                "Invalid IP",
			ip:                  "abc",
			vlanid:              0,
			assignedIPs:         make(map[string]*crdv1b1.SubnetInfo),
			ips:                 sets.New[string](),
			expectedError:       true,
			expectedAssignedIPs: make(map[string]*crdv1b1.SubnetInfo),
			expectFunc: func(mock *respondertest.MockResponder) {
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {
			},
		},
		{
			name:        "Assign new IP",
			ip:          "2.1.1.1",
			vlanid:      0,
			assignedIPs: make(map[string]*crdv1b1.SubnetInfo),
			ips:         sets.New[string](),
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.1.1.1": subnetInfo,
			},
			expectFunc: func(mock *respondertest.MockResponder) {
				mock.EXPECT().AddIP(net.ParseIP("2.1.1.1")).Return(nil)
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {
				ipAddress := "2.1.1.1"
				ipNet := &net.IPNet{
					IP:   net.ParseIP(ipAddress),
					Mask: net.CIDRMask(32, 32),
				}
				addr := &netlink.Addr{IPNet: ipNet}
				mockNetlink.EXPECT().AddrAdd(&dummyDeviceMock{}, addr).Return(nil)
				netlinkAddrAdd = mockNetlink.AddrAdd
			},
		},
		{
			name:   "Assign existing IP",
			ip:     "2.1.1.1",
			vlanid: 0,
			assignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.1.1.1": subnetInfo,
			},
			ips: sets.New[string]("2.1.1.1"),
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.1.1.1": subnetInfo,
			},
			expectFunc: func(mock *respondertest.MockResponder) {
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {
			},
		},
		{
			name:   "Add more IP",
			ip:     "2.2.2.1",
			vlanid: 0,
			assignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.1.1.1": subnetInfo,
			},
			ips: sets.New[string]("2.1.1.1"),
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.1.1.1": subnetInfo,
				"2.2.2.1": subnetInfo,
			},
			expectFunc: func(mock *respondertest.MockResponder) {
				mock.EXPECT().AddIP(net.ParseIP("2.2.2.1")).Return(nil)
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {
				ipNet := &net.IPNet{
					IP:   net.ParseIP("2.2.2.1"),
					Mask: net.CIDRMask(32, 32),
				}
				addr := &netlink.Addr{IPNet: ipNet}
				mockNetlink.EXPECT().AddrAdd(&dummyDeviceMock{}, addr).Return(nil)
				netlinkAddrAdd = mockNetlink.AddrAdd
			},
		},
		{
			name:   "Assign IPv6",
			ip:     "2001:db8::1",
			vlanid: 0,
			assignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.1.1.1": subnetInfo,
				"2.2.2.1": subnetInfo,
			},
			ips: sets.New[string]("2.1.1.1", "2.2.2.1"),
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.1.1.1":     subnetInfo,
				"2.2.2.1":     subnetInfo,
				"2001:db8::1": subnetInfo,
			},
			expectFunc: func(mock *respondertest.MockResponder) {
				mock.EXPECT().AddIP(net.ParseIP("2001:db8::1")).Return(nil)
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {
				ipNet := &net.IPNet{
					IP:   net.ParseIP("2001:db8::1"),
					Mask: net.CIDRMask(128, 128),
				}
				addr := &netlink.Addr{IPNet: ipNet}
				mockNetlink.EXPECT().AddrAdd(&dummyDeviceMock{}, addr).Return(nil)
				netlinkAddrAdd = mockNetlink.AddrAdd
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.vlanid == 0 {
				a := &ipAssigner{
					externalInterface: newFakeNetworkInterface(),
					defaultAssignee: &assignee{
						logicalInterface: newFakeNetworkInterface(),
						ips:              tt.ips,
					},
					assignedIPs: tt.assignedIPs,
					mutex:       sync.RWMutex{},
				}
				a.defaultAssignee.link = &dummyDeviceMock{}
				a.defaultAssignee.advertiseFn = advertiseFnc
				a.defaultAssignee.arpResponder = mockResponder
				a.defaultAssignee.ndpResponder = mockResponder
				tt.expectFunc(mockResponder)
				tt.expectedCalls(mockNetlink)

				_, err = a.AssignIP(tt.ip, subnetInfo, false)
				if tt.expectedError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
				assert.Equal(t, tt.expectedAssignedIPs, a.assignedIPs, "Assigned IPs don't match")
			}
		})
	}
}

func TestIPAssigner_AssignIPVlan(t *testing.T) {
	var err error
	controller := gomock.NewController(t)
	mockResponder := respondertest.NewMockResponder(controller)
	var subnetInfo *crdv1b1.SubnetInfo
	mockNetlink := netlinktest.NewMockInterface(controller)

	tests := []struct {
		name                string
		ip                  string
		vlanid              int
		assignedIPs         map[string]*crdv1b1.SubnetInfo
		ips                 sets.Set[string]
		expectedError       bool
		expectedAssignedIPs map[string]*crdv1b1.SubnetInfo
		expectFunc          func(mock *respondertest.MockResponder)
		expectedCalls       func(mockNetlink *netlinktest.MockInterface)
	}{
		{
			name:   "Assign IPv4 vlan 12",
			ip:     "4.4.4.2",
			vlanid: 12,
			ips:    sets.New[string](),
			assignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.1.1.1":     subnetInfo,
				"2.2.2.1":     subnetInfo,
				"2001:db8::1": subnetInfo,
			},
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.1.1.1":     subnetInfo,
				"2.2.2.1":     subnetInfo,
				"2001:db8::1": subnetInfo,
				"4.4.4.2": {PrefixLength: 32,
					VLAN: 12,
				},
			},
			expectFunc: func(mock *respondertest.MockResponder) {
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {
				ipAddress := "4.4.4.2"
				ipNet := &net.IPNet{
					IP:   net.ParseIP(ipAddress),
					Mask: net.CIDRMask(32, 32),
				}
				addr := &netlink.Addr{IPNet: ipNet}

				vlan := &netlink.Vlan{
					LinkAttrs: netlink.LinkAttrs{
						Name: "antrea-ext.12",
					},
					VlanId: 12,
				}
				mockNetlink.EXPECT().LinkSetUp(vlan).Return(nil)
				mockNetlink.EXPECT().AddrAdd(vlan, addr).Return(nil)
				mockNetlink.EXPECT().LinkAdd(vlan).Return(nil)
				netlinkAdd = mockNetlink.LinkAdd
				netlinkSetUp = mockNetlink.LinkSetUp
				netlinkAddrAdd = mockNetlink.AddrAdd
			},
		},
		{
			name:   "Assign IPv4 vlan 13",
			ip:     "5.5.5.2",
			vlanid: 13,
			ips:    sets.New[string](),
			assignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.1.1.1":     subnetInfo,
				"2.2.2.1":     subnetInfo,
				"2001:db8::1": subnetInfo,
				"4.4.4.2": {PrefixLength: 32,
					VLAN: 12,
				},
			},
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.1.1.1":     subnetInfo,
				"2.2.2.1":     subnetInfo,
				"2001:db8::1": subnetInfo,
				"4.4.4.2": {PrefixLength: 32,
					VLAN: 12,
				},
				"5.5.5.2": {PrefixLength: 32,
					VLAN: 13,
				},
			},
			expectFunc: func(mock *respondertest.MockResponder) {
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {
				ipAddress := "5.5.5.2"
				ipNet := &net.IPNet{
					IP:   net.ParseIP(ipAddress),
					Mask: net.CIDRMask(32, 32),
				}
				addr := &netlink.Addr{IPNet: ipNet}
				vlan := &netlink.Vlan{
					LinkAttrs: netlink.LinkAttrs{
						Name: "antrea-ext.13",
					},
					VlanId: 13,
				}
				mockNetlink.EXPECT().AddrAdd(vlan, addr).Return(nil)
				mockNetlink.EXPECT().LinkSetUp(vlan).Return(nil)
				mockNetlink.EXPECT().LinkAdd(vlan).Return(nil)
				netlinkAdd = mockNetlink.LinkAdd
				netlinkSetUp = mockNetlink.LinkSetUp
				netlinkAddrAdd = mockNetlink.AddrAdd
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			a := &ipAssigner{
				externalInterface: newFakeNetworkInterface(),
				defaultAssignee: &assignee{
					logicalInterface: newFakeNetworkInterface(),
					ips:              sets.New[string](),
				},

				vlanAssignees: map[int32]*assignee{},

				assignedIPs: tt.assignedIPs,
				mutex:       sync.RWMutex{},
			}

			subnetInfo := &crdv1b1.SubnetInfo{
				PrefixLength: 32,
				VLAN:         int32(tt.vlanid),
			}

			tt.expectFunc(mockResponder)
			tt.expectedCalls(mockNetlink)

			ensRpfFunc := ensureRPF
			defer func() { ensureRPF = ensRpfFunc }()
			ensureRPF = ensureRPFInt

			netInterfaceByNameFunc := netInterfaceByName
			defer func() { netInterfaceByName = netInterfaceByNameFunc }()
			netInterfaceByName = DummyInterfaceByName

			_, err = a.AssignIP(tt.ip, subnetInfo, false)
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.expectedAssignedIPs, a.assignedIPs, "Assigned IPs don't match")
		})
	}
}

func TestIPAssigner_UnAssignIP(t *testing.T) {
	controller := gomock.NewController(t)
	mockResponder := respondertest.NewMockResponder(controller)
	var subnetInfo *crdv1b1.SubnetInfo
	mockNetlink := netlinktest.NewMockInterface(controller)

	tests := []struct {
		name                string
		ip                  string
		assignedIPs         map[string]*crdv1b1.SubnetInfo
		ips                 sets.Set[string]
		expectedError       bool
		expectedAssignedIPs map[string]*crdv1b1.SubnetInfo
		expectFunc          func(mock *respondertest.MockResponder)
		expectedCalls       func(mockNetlink *netlinktest.MockInterface)
	}{
		{
			name:                "Invalid IP",
			ip:                  "abc",
			assignedIPs:         make(map[string]*crdv1b1.SubnetInfo),
			ips:                 sets.New[string](),
			expectedError:       true,
			expectedAssignedIPs: make(map[string]*crdv1b1.SubnetInfo),
			expectFunc: func(mock *respondertest.MockResponder) {
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {
			},
		},
		{
			name:                "UnassignIP not assigned",
			ip:                  "3.3.3.2",
			assignedIPs:         make(map[string]*crdv1b1.SubnetInfo),
			ips:                 sets.New[string](),
			expectedAssignedIPs: make(map[string]*crdv1b1.SubnetInfo),
			expectFunc: func(mock *respondertest.MockResponder) {
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {
			},
		},
		{
			name: "Unassign IPv4",
			ip:   "2.1.1.1",
			assignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.1.1.1": subnetInfo,
				"2.2.2.1": subnetInfo,
			},
			ips: sets.New[string]("2.1.1.1", "2.2.2.1"),
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.2.2.1": subnetInfo,
			},
			expectFunc: func(mock *respondertest.MockResponder) {
				mock.EXPECT().RemoveIP(net.ParseIP("2.1.1.1")).Return(nil)
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {

				ipNet := &net.IPNet{
					IP:   net.ParseIP("2.1.1.1"),
					Mask: net.CIDRMask(32, 32),
				}
				addr := &netlink.Addr{IPNet: ipNet}
				mockNetlink.EXPECT().AddrDel(&dummyDeviceMock{}, addr).Return(nil)
				netlinkAddrDel = mockNetlink.AddrDel
			},
		},
		{
			name: "Unassign IPv6",
			ip:   "2001:db8::1",
			assignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.2.2.1":     subnetInfo,
				"2001:db8::1": subnetInfo,
			},
			ips: sets.New[string]("2.2.2.1", "2001:db8::1"),
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.2.2.1": subnetInfo,
			},
			expectFunc: func(mock *respondertest.MockResponder) {
				mock.EXPECT().RemoveIP(net.ParseIP("2001:db8::1")).Return(nil)
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {
				ipNet := &net.IPNet{
					IP:   net.ParseIP("2001:db8::1"),
					Mask: net.CIDRMask(128, 128),
				}
				addr := &netlink.Addr{IPNet: ipNet}
				mockNetlink.EXPECT().AddrDel(&dummyDeviceMock{}, addr).Return(nil)
				netlinkAddrDel = mockNetlink.AddrDel
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			a := &ipAssigner{
				externalInterface: newFakeNetworkInterface(),
				defaultAssignee: &assignee{
					logicalInterface: newFakeNetworkInterface(),
					ips:              tt.ips,
				},
				assignedIPs: tt.assignedIPs,
				mutex:       sync.RWMutex{},
			}
			a.defaultAssignee.link = &dummyDeviceMock{}
			a.defaultAssignee.advertiseFn = advertiseFnc
			a.defaultAssignee.arpResponder = mockResponder
			a.defaultAssignee.ndpResponder = mockResponder
			tt.expectFunc(mockResponder)
			tt.expectedCalls(mockNetlink)

			_, err := a.UnassignIP(tt.ip)
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.expectedAssignedIPs, a.assignedIPs, "Unassigned IPs don't match")
		})
	}
}

func TestIPAssigner_UnAssignIPVlan(t *testing.T) {
	controller := gomock.NewController(t)
	mockResponder := respondertest.NewMockResponder(controller)
	var subnetInfo *crdv1b1.SubnetInfo
	mockNetlink := netlinktest.NewMockInterface(controller)

	tests := []struct {
		name                string
		ip                  string
		vlanid              int
		assignedIPs         map[string]*crdv1b1.SubnetInfo
		ips                 sets.Set[string]
		vlanAssignees       map[int32]*assignee
		expectedError       bool
		expectedAssignedIPs map[string]*crdv1b1.SubnetInfo
		expectFunc          func(mock *respondertest.MockResponder)
		expectedCalls       func(mockNetlink *netlinktest.MockInterface)
	}{
		{
			name:   "Unassign IPv4 Vlan IP",
			ip:     "4.4.4.2",
			vlanid: 12,
			assignedIPs: map[string]*crdv1b1.SubnetInfo{
				"4.4.4.2": {PrefixLength: 32,
					VLAN: 12,
				},
				"2.1.1.1":     subnetInfo,
				"2.2.2.1":     subnetInfo,
				"2001:db8::1": subnetInfo,
			},

			ips: sets.New[string]("4.4.4.2", "2.1.1.1", "2.2.2.1", "2001:db8::1"),
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.1.1.1":     subnetInfo,
				"2.2.2.1":     subnetInfo,
				"2001:db8::1": subnetInfo,
			},
			expectFunc: func(mock *respondertest.MockResponder) {
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {
				ipAddress := "4.4.4.2"
				ipNet := &net.IPNet{
					IP:   net.ParseIP(ipAddress),
					Mask: net.CIDRMask(32, 32),
				}
				addr := &netlink.Addr{IPNet: ipNet}
				vlan := &netlink.Vlan{
					LinkAttrs: netlink.LinkAttrs{
						Name: "antrea-ext.12",
					},
					VlanId: 12,
				}
				mockNetlink.EXPECT().AddrDel(vlan, addr).Return(nil)
				mockNetlink.EXPECT().LinkDel(vlan).Return(nil)
				netlinkDel = mockNetlink.LinkDel
				netlinkAddrDel = mockNetlink.AddrDel
			},
		},
		{
			name:   "Unassign IPv4 Vlan IP-2",
			ip:     "5.5.5.2",
			vlanid: 13,
			assignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.2.2.1":     subnetInfo,
				"2001:db8::1": subnetInfo,
				"5.5.5.2": {PrefixLength: 32,
					VLAN: 13,
				},
			},
			ips: sets.New[string]("5.5.5.2", "2.2.2.1", "2001:db8::1"),
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.2.2.1":     subnetInfo,
				"2001:db8::1": subnetInfo,
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {
				ipAddress := "5.5.5.2"
				ipNet := &net.IPNet{
					IP:   net.ParseIP(ipAddress),
					Mask: net.CIDRMask(32, 32),
				}
				addr := &netlink.Addr{IPNet: ipNet}
				vlan := &netlink.Vlan{
					LinkAttrs: netlink.LinkAttrs{
						Name: "antrea-ext.13",
					},
					VlanId: 13,
				}
				mockNetlink.EXPECT().AddrDel(vlan, addr).Return(nil)
				mockNetlink.EXPECT().LinkDel(vlan).Return(nil)
				netlinkDel = mockNetlink.LinkDel
				netlinkAddrDel = mockNetlink.AddrDel
			},
			expectFunc: func(mock *respondertest.MockResponder) {
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &ipAssigner{
				externalInterface: newFakeNetworkInterface(),
				defaultAssignee: &assignee{
					logicalInterface: newFakeNetworkInterface(),
					ips:              sets.New[string](),
				},

				vlanAssignees: map[int32]*assignee{
					12: {
						link: &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{
							Name: "antrea-ext.12",
						},
							VlanId: 12},
						logicalInterface: newFakeNetworkInterface(),
						ips:              sets.New[string](),
					},
					13: {
						link: &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{
							Name: "antrea-ext.13",
						},
							VlanId: 13},
						logicalInterface: newFakeNetworkInterface(),
						ips:              sets.New[string](),
					},
				},

				assignedIPs: tt.assignedIPs,
				mutex:       sync.RWMutex{},
			}

			tt.expectFunc(mockResponder)
			tt.expectedCalls(mockNetlink)

			ensRpfFunc := ensureRPF
			defer func() { ensureRPF = ensRpfFunc }()
			ensureRPF = ensureRPFInt

			netInterfaceByNameFunc := netInterfaceByName
			defer func() { netInterfaceByName = netInterfaceByNameFunc }()
			netInterfaceByName = DummyInterfaceByName

			_, err := a.UnassignIP(tt.ip)
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.expectedAssignedIPs, a.assignedIPs, "Unassigned IPs don't match")
		})
	}

}

func TestIPAssigner_AssignedIPs(t *testing.T) {
	var subnetInfo *crdv1b1.SubnetInfo
	controller := gomock.NewController(t)
	mockResponder := respondertest.NewMockResponder(controller)

	a := &ipAssigner{
		externalInterface: newFakeNetworkInterface(),
		defaultAssignee: &assignee{
			logicalInterface: newFakeNetworkInterface(),
			//ips:              tt.ips,
		},
		assignedIPs: map[string]*crdv1b1.SubnetInfo{
			"2.1.1.1": subnetInfo,
			"3.3.3.1": subnetInfo,
		},
		mutex: sync.RWMutex{},
	}
	a.defaultAssignee.link = &dummyDeviceMock{}
	a.defaultAssignee.advertiseFn = advertiseFnc
	a.defaultAssignee.arpResponder = mockResponder
	a.defaultAssignee.ndpResponder = mockResponder

	ips := a.AssignedIPs()

	expectedIPs := map[string]*crdv1b1.SubnetInfo{
		"2.1.1.1": subnetInfo,
		"3.3.3.1": subnetInfo,
	}
	if !reflect.DeepEqual(a.assignedIPs, expectedIPs) {
		t.Errorf("expected IPs: %v, but got: %v", expectedIPs, ips)
	}
}

func TestIPAssigner_AssignedIPsVlan(t *testing.T) {
	var subnetInfo *crdv1b1.SubnetInfo
	tests := []struct {
		name                string
		ip                  string
		vlanid              int
		assignedIPs         map[string]*crdv1b1.SubnetInfo
		ips                 sets.Set[string]
		vlanAssignees       map[int32]*assignee
		expectedError       bool
		expectedAssignedIPs map[string]*crdv1b1.SubnetInfo
		expectFunc          func(mock *respondertest.MockResponder)
	}{
		{
			name:   "AssignedIPsVlan IPv4",
			ip:     "4.4.4.2",
			vlanid: 12,
			assignedIPs: map[string]*crdv1b1.SubnetInfo{
				"4.4.4.2": {PrefixLength: 24,
					VLAN: 12,
				},
				"2.1.1.1":     subnetInfo,
				"2.2.2.1":     subnetInfo,
				"2001:db8::1": subnetInfo,
			},

			ips: sets.New[string]("4.4.4.2", "2.1.1.1", "2.2.2.1", "2001:db8::1"),
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"4.4.4.2": {PrefixLength: 24,
					VLAN: 12,
				},
				"2.1.1.1":     subnetInfo,
				"2.2.2.1":     subnetInfo,
				"2001:db8::1": subnetInfo,
			},
			expectFunc: func(mock *respondertest.MockResponder) {
			},
		},
		{
			name:   "Unassign IPv4 Vlan IP-2",
			ip:     "5.5.5.2",
			vlanid: 13,
			assignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.2.2.1":     subnetInfo,
				"2001:db8::1": subnetInfo,
				"5.5.5.2": {PrefixLength: 24,
					VLAN: 13,
				},
			},
			ips: sets.New[string]("5.5.5.2", "2.2.2.1", "2001:db8::1"),
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"5.5.5.2": {PrefixLength: 24,
					VLAN: 13,
				},
				"2.2.2.1":     subnetInfo,
				"2001:db8::1": subnetInfo,
			},
			expectFunc: func(mock *respondertest.MockResponder) {
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			a := &ipAssigner{
				externalInterface: newFakeNetworkInterface(),
				defaultAssignee: &assignee{
					logicalInterface: newFakeNetworkInterface(),
					ips:              sets.New[string](),
				},

				vlanAssignees: map[int32]*assignee{
					12: {
						link: &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{
							Name: "antrea-ext.12",
						},
							VlanId: 12},
						logicalInterface: newFakeNetworkInterface(),
						ips:              sets.New[string](),
					},
					13: {
						link: &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{
							Name: "antrea-ext.13",
						},
							VlanId: 13},
						logicalInterface: newFakeNetworkInterface(),
						ips:              sets.New[string](),
					},
				},

				assignedIPs: tt.assignedIPs,
				mutex:       sync.RWMutex{},
			}

			ips := a.AssignedIPs()

			if !reflect.DeepEqual(a.assignedIPs, tt.expectedAssignedIPs) {
				t.Errorf("expected IPs: %v, but got: %v", tt.expectedAssignedIPs, ips)
			}
		})
	}
}

func TestIPAssigner_InitIPs(t *testing.T) {
	var err error
	var subnetInfo *crdv1b1.SubnetInfo
	controller := gomock.NewController(t)
	mockResponder := respondertest.NewMockResponder(controller)
	mockNetlink := netlinktest.NewMockInterface(controller)

	tests := []struct {
		name                string
		desiredIPs          map[string]*crdv1b1.SubnetInfo
		assignedIPs         map[string]*crdv1b1.SubnetInfo
		ips                 sets.Set[string]
		expectedError       bool
		expectedAssignedIPs map[string]*crdv1b1.SubnetInfo
		expectFunc          func(mock *respondertest.MockResponder)
		expectedCalls       func(mockNetlink *netlinktest.MockInterface)
	}{
		{

			name: "InitIPs with new IP",
			desiredIPs: map[string]*crdv1b1.SubnetInfo{
				"8.8.8.1": subnetInfo,
			},
			assignedIPs: map[string]*crdv1b1.SubnetInfo{
				"192.168.1.5": subnetInfo,
				"2.1.1.3":     subnetInfo,
			},
			ips: sets.New[string]("8.8.8.1"),
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"8.8.8.1": subnetInfo,
			},
			expectFunc: func(mock *respondertest.MockResponder) {
				mock.EXPECT().AddIP(net.ParseIP("8.8.8.1")).Return(nil)

			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {
				ipAddress := "8.8.8.1"
				ipNet := &net.IPNet{
					IP:   net.ParseIP(ipAddress),
					Mask: net.CIDRMask(32, 32),
				}
				addr := &netlink.Addr{IPNet: ipNet}
				mockNetlink.EXPECT().AddrAdd(&dummyDeviceMock{}, addr).Return(nil)
				netlinkAddrAdd = mockNetlink.AddrAdd
			},
		},
		{
			name: "InitIPs with new and old ip",
			desiredIPs: map[string]*crdv1b1.SubnetInfo{
				"8.8.8.1": subnetInfo,
				"8.8.8.2": subnetInfo,
			},
			assignedIPs: map[string]*crdv1b1.SubnetInfo{
				"192.168.1.5":   subnetInfo,
				"192.168.1.105": subnetInfo,
				"2.1.1.3":       subnetInfo,
			},
			ips: sets.New[string]("8.8.8.1", "8.8.8.2"),
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"8.8.8.1": subnetInfo,
				"8.8.8.2": subnetInfo,
			},
			expectFunc: func(mock *respondertest.MockResponder) {
				mock.EXPECT().AddIP(net.ParseIP("8.8.8.1")).Return(nil)
				mock.EXPECT().AddIP(net.ParseIP("8.8.8.2")).Return(nil)
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {
				ipAddress := "8.8.8.1"
				ipNet := &net.IPNet{
					IP:   net.ParseIP(ipAddress),
					Mask: net.CIDRMask(32, 32),
				}
				addr := &netlink.Addr{IPNet: ipNet}
				ipAddress1 := "8.8.8.2"
				ipNet1 := &net.IPNet{
					IP:   net.ParseIP(ipAddress1),
					Mask: net.CIDRMask(32, 32),
				}
				addr1 := &netlink.Addr{IPNet: ipNet1}
				mockNetlink.EXPECT().AddrAdd(&dummyDeviceMock{}, addr).Return(nil)
				mockNetlink.EXPECT().AddrAdd(&dummyDeviceMock{}, addr1).Return(nil)
				netlinkAddrAdd = mockNetlink.AddrAdd
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &ipAssigner{
				externalInterface: newFakeNetworkInterface(),
				defaultAssignee: &assignee{
					logicalInterface: newFakeNetworkInterface(),
					ips:              tt.ips,
				},
				assignedIPs: tt.assignedIPs,
				mutex:       sync.RWMutex{},
			}
			a.defaultAssignee.link = &dummyDeviceMock{}
			a.defaultAssignee.advertiseFn = advertiseFnc
			a.defaultAssignee.arpResponder = mockResponder
			a.defaultAssignee.ndpResponder = mockResponder
			tt.expectFunc(mockResponder)
			tt.expectedCalls(mockNetlink)

			netlinkAddrDel = mockNetlink.AddrDel

			err = a.InitIPs(tt.desiredIPs)
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestIPAssigner_InitIPsVlan(t *testing.T) {
	var err error
	var subnetInfo *crdv1b1.SubnetInfo
	controller := gomock.NewController(t)
	mockResponder := respondertest.NewMockResponder(controller)
	mockNetlink := netlinktest.NewMockInterface(controller)

	tests := []struct {
		name                string
		vlanid              int
		vlanAssignees       map[int32]*assignee
		desiredIPs          map[string]*crdv1b1.SubnetInfo
		assignedIPs         map[string]*crdv1b1.SubnetInfo
		ips                 sets.Set[string]
		expectedError       bool
		expectedAssignedIPs map[string]*crdv1b1.SubnetInfo
		expectFunc          func(mock *respondertest.MockResponder)
		expectedCalls       func(mockNetlink *netlinktest.MockInterface)
	}{
		{
			name:   "InitIPs with vlan IP",
			vlanid: 12,
			desiredIPs: map[string]*crdv1b1.SubnetInfo{
				"8.8.8.1": {PrefixLength: 32,
					VLAN: 12,
				},
			},
			assignedIPs: map[string]*crdv1b1.SubnetInfo{
				"192.168.1.5": subnetInfo,
				"2.1.1.3":     subnetInfo,
			},
			ips: sets.New[string]("8.8.8.1"),
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"8.8.8.1": {PrefixLength: 24,
					VLAN: 12,
				},
			},
			expectFunc: func(mock *respondertest.MockResponder) {
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterface) {
				ipAddress := "8.8.8.1"
				ipNet := &net.IPNet{
					IP:   net.ParseIP(ipAddress),
					Mask: net.CIDRMask(32, 32),
				}
				addr := &netlink.Addr{IPNet: ipNet}
				vlan := &netlink.Vlan{
					LinkAttrs: netlink.LinkAttrs{
						Name: "antrea-ext.12",
					},
					VlanId: 12,
				}
				mockNetlink.EXPECT().AddrAdd(vlan, addr).Return(nil)
				mockNetlink.EXPECT().AddrList(&dummyDeviceMock{}, netlink.FAMILY_ALL).Return(nil, nil)
				mockNetlink.EXPECT().LinkSetUp(vlan).Return(nil)
				mockNetlink.EXPECT().LinkAdd(vlan).Return(nil)
				netlinkSetUp = mockNetlink.LinkSetUp
				netlinkAddrAdd = mockNetlink.AddrAdd
				netlinkAddrList = mockNetlink.AddrList
				netlinkAdd = mockNetlink.LinkAdd
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &ipAssigner{
				externalInterface: newFakeNetworkInterface(),
				defaultAssignee: &assignee{
					logicalInterface: newFakeNetworkInterface(),
					ips:              tt.ips,
				},
				vlanAssignees: map[int32]*assignee{},
				assignedIPs:   tt.assignedIPs,
				mutex:         sync.RWMutex{},
			}
			a.defaultAssignee.link = &dummyDeviceMock{}
			a.defaultAssignee.advertiseFn = advertiseFnc
			a.defaultAssignee.arpResponder = mockResponder
			a.defaultAssignee.ndpResponder = mockResponder
			tt.expectFunc(mockResponder)
			tt.expectedCalls(mockNetlink)

			ensRpfFunc := ensureRPF
			defer func() { ensureRPF = ensRpfFunc }()
			ensureRPF = ensureRPFInt

			netInterfaceByNameFunc := netInterfaceByName
			defer func() { netInterfaceByName = netInterfaceByNameFunc }()
			netInterfaceByName = DummyInterfaceByName

			err = a.InitIPs(tt.desiredIPs)
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
