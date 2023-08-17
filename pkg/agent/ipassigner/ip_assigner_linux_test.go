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
	crdv1b1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

func netlinkLinkSetup(link netlink.Link) error {
	return nil
}

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

func netLinkAddel(vlan netlink.Link) error {
	return nil
}

type AddrRecord struct {
	Link    netlink.Link
	Address []*netlink.Addr
}

var addedAddresses []*AddrRecord

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

func DummyDeviceMockVlan(vlanID int) *dummyDeviceMock {
	return &dummyDeviceMock{vlanID: vlanID}
}

func addrAddDel(link netlink.Link, addr *netlink.Addr) error {

	fmt.Println("calling addrAddDel")
	// Find the existing record for the link
	var linkRecord *AddrRecord
	for _, record := range addedAddresses {
		if record.Link == link {
			linkRecord = record
			break
		}
	}

	// If the link record doesn't exist, create a new one
	if linkRecord == nil {
		linkRecord = &AddrRecord{
			Link:    link,
			Address: []*netlink.Addr{addr},
		}
		addedAddresses = append(addedAddresses, linkRecord)
	} else {
		// Check if the address already exists in the record
		var addrIndex = -1
		for i, existingAddr := range linkRecord.Address {
			if existingAddr.IPNet.IP.Equal(addr.IPNet.IP) {
				addrIndex = i
				break
			}
		}

		if addrIndex != -1 {
			// Address already exists, remove it
			linkRecord.Address = append(linkRecord.Address[:addrIndex], linkRecord.Address[addrIndex+1:]...)
		} else {
			// Address doesn't exist, add it
			linkRecord.Address = append(linkRecord.Address, addr)
		}
	}

	return nil
}

func netlinkAddrLst(link netlink.Link, family int) ([]netlink.Addr, error) {
	return []netlink.Addr{}, nil
}

func TestIPAssigner_AssignIP(t *testing.T) {
	var err error
	var subnetInfo *crdv1b1.SubnetInfo

	controller := gomock.NewController(t)
	mockResponder := respondertest.NewMockResponder(controller)

	tests := []struct {
		name                string
		ip                  string
		vlanid              int
		assignedIPs         map[string]*crdv1b1.SubnetInfo
		ips                 sets.Set[string]
		expectedError       bool
		expectedAssignedIPs map[string]*crdv1b1.SubnetInfo
		expectFunc          func(mock *respondertest.MockResponder)
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

				netlinkAddrAddFunc := netlinkAddrAdd
				defer func() { netlinkAddrAdd = netlinkAddrAddFunc }()
				netlinkAddrAdd = addrAddDel

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

	tests := []struct {
		name                string
		ip                  string
		vlanid              int
		assignedIPs         map[string]*crdv1b1.SubnetInfo
		ips                 sets.Set[string]
		expectedError       bool
		expectedAssignedIPs map[string]*crdv1b1.SubnetInfo
		expectFunc          func(mock *respondertest.MockResponder)
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
				"4.4.4.2": {PrefixLength: 24,
					VLAN: 12,
				},
			},
			expectFunc: func(mock *respondertest.MockResponder) {
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
				"4.4.4.2": {PrefixLength: 24,
					VLAN: 12,
				},
			},
			expectedAssignedIPs: map[string]*crdv1b1.SubnetInfo{
				"2.1.1.1":     subnetInfo,
				"2.2.2.1":     subnetInfo,
				"2001:db8::1": subnetInfo,
				"4.4.4.2": {PrefixLength: 24,
					VLAN: 12,
				},
				"5.5.5.2": {PrefixLength: 24,
					VLAN: 13,
				},
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

				vlanAssignees: map[int32]*assignee{},

				assignedIPs: tt.assignedIPs,
				mutex:       sync.RWMutex{},
			}

			subnetInfo := &crdv1b1.SubnetInfo{
				PrefixLength: 24,
				VLAN:         int32(tt.vlanid),
			}

			tt.expectFunc(mockResponder)

			netlinkAddFunc := netlinkAdd
			defer func() { netlinkAdd = netlinkAddFunc }()
			netlinkAdd = netLinkAddel

			ensRpfFunc := ensureRPF
			defer func() { ensureRPF = ensRpfFunc }()
			ensureRPF = ensureRPFInt

			netlinkSetUpFunc := netlinkSetUp
			defer func() { netlinkSetUp = netlinkSetUpFunc }()
			netlinkSetUp = netlinkLinkSetup

			netInterfaceByNameFunc := netInterfaceByName
			defer func() { netInterfaceByName = netInterfaceByNameFunc }()
			netInterfaceByName = DummyInterfaceByName

			netlinkAddrAddFunc := netlinkAddrAdd
			defer func() { netlinkAddrAdd = netlinkAddrAddFunc }()
			netlinkAddrAdd = addrAddDel

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

	tests := []struct {
		name                string
		ip                  string
		assignedIPs         map[string]*crdv1b1.SubnetInfo
		ips                 sets.Set[string]
		expectedError       bool
		expectedAssignedIPs map[string]*crdv1b1.SubnetInfo
		expectFunc          func(mock *respondertest.MockResponder)
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
		},
		{
			name:                "UnassignIP not assigned",
			ip:                  "3.3.3.2",
			assignedIPs:         make(map[string]*crdv1b1.SubnetInfo),
			ips:                 sets.New[string](),
			expectedAssignedIPs: make(map[string]*crdv1b1.SubnetInfo),
			expectFunc: func(mock *respondertest.MockResponder) {
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

			netlinkAddrAddFunc := netlinkAddrDel
			defer func() { netlinkAddrDel = netlinkAddrAddFunc }()
			netlinkAddrDel = addrAddDel

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
			name:   "Unassign IPv4 Vlan IP",
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

			tt.expectFunc(mockResponder)

			netlinkAddFunc := netlinkDel
			defer func() { netlinkDel = netlinkAddFunc }()
			netlinkDel = netLinkAddel

			ensRpfFunc := ensureRPF
			defer func() { ensureRPF = ensRpfFunc }()
			ensureRPF = ensureRPFInt

			netlinkSetUpFunc := netlinkSetUp
			defer func() { netlinkSetUp = netlinkSetUpFunc }()
			netlinkSetUp = netlinkLinkSetup

			netInterfaceByNameFunc := netInterfaceByName
			defer func() { netInterfaceByName = netInterfaceByNameFunc }()
			netInterfaceByName = DummyInterfaceByName

			netlinkAddrAddFunc := netlinkAddrDel
			defer func() { netlinkAddrDel = netlinkAddrAddFunc }()
			netlinkAddrDel = addrAddDel

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

	tests := []struct {
		name                string
		desiredIPs          map[string]*crdv1b1.SubnetInfo
		assignedIPs         map[string]*crdv1b1.SubnetInfo
		ips                 sets.Set[string]
		expectedError       bool
		expectedAssignedIPs map[string]*crdv1b1.SubnetInfo
		expectFunc          func(mock *respondertest.MockResponder)
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
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			controller := gomock.NewController(t)
			mockResponder := respondertest.NewMockResponder(controller)

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

			netlinkAddrAddFunc := netlinkAddrAdd
			defer func() { netlinkAddrAdd = netlinkAddrAddFunc }()
			netlinkAddrAdd = addrAddDel

			netlinkAddrAddFunc1 := netlinkAddrDel
			defer func() { netlinkAddrDel = netlinkAddrAddFunc1 }()
			netlinkAddrDel = addrAddDel

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
	}{
		{

			name:   "InitIPs with vlan IP",
			vlanid: 12,
			desiredIPs: map[string]*crdv1b1.SubnetInfo{
				"8.8.8.1": {PrefixLength: 24,
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
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			controller := gomock.NewController(t)
			mockResponder := respondertest.NewMockResponder(controller)

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

			netlinkAddFunc := netlinkAdd
			defer func() { netlinkAdd = netlinkAddFunc }()
			netlinkAdd = netLinkAddel

			ensRpfFunc := ensureRPF
			defer func() { ensureRPF = ensRpfFunc }()
			ensureRPF = ensureRPFInt

			netlinkSetUpFunc := netlinkSetUp
			defer func() { netlinkSetUp = netlinkSetUpFunc }()
			netlinkSetUp = netlinkLinkSetup

			netInterfaceByNameFunc := netInterfaceByName
			defer func() { netInterfaceByName = netInterfaceByNameFunc }()
			netInterfaceByName = DummyInterfaceByName

			netlinkAddrAddFunc := netlinkAddrAdd
			defer func() { netlinkAddrAdd = netlinkAddrAddFunc }()
			netlinkAddrAdd = addrAddDel

			netlinkAddrAddFunc1 := netlinkAddrDel
			defer func() { netlinkAddrDel = netlinkAddrAddFunc1 }()
			netlinkAddrDel = addrAddDel

			netlinkAdrLst := netlinkAddrList
			defer func() { netlinkAddrList = netlinkAdrLst }()
			netlinkAddrList = netlinkAddrLst

			err = a.InitIPs(tt.desiredIPs)
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
