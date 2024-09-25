// Copyright 2022 Antrea Authors
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

package responder

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/mdlayher/ndp"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/ipv6"
	"k8s.io/apimachinery/pkg/util/sets"
)

type fakeNDPConn struct {
	readFrom   func() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error)
	writeTo    func(ndp.Message, *ipv6.ControlMessage, netip.Addr) error
	joinGroup  func(ip netip.Addr) error
	leaveGroup func(ip netip.Addr) error
}

func (c *fakeNDPConn) ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error) {
	return c.readFrom()
}

func (c *fakeNDPConn) WriteTo(message ndp.Message, cm *ipv6.ControlMessage, dstIP netip.Addr) error {
	return c.writeTo(message, cm, dstIP)
}

func (c *fakeNDPConn) Close() error {
	return nil
}

func (c *fakeNDPConn) JoinGroup(ip netip.Addr) error {
	return c.joinGroup(ip)
}

func (c *fakeNDPConn) LeaveGroup(ip netip.Addr) error {
	return c.leaveGroup(ip)
}

func TestNDPResponder_handleNeighborSolicitation(t *testing.T) {
	hwAddr := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	iface := newFakeNetworkInterface(hwAddr)

	tests := []struct {
		name           string
		requestMessage []byte
		requestIP      netip.Addr
		assignedIPs    []netip.Addr
		expectError    bool
		expectedReply  []byte
	}{
		{
			name: "request to assigned IP",
			requestMessage: []byte{
				0x87,       // type - 135 for Neighbor Solicitation
				0x00,       // code
				0x00, 0x00, // checksum
				0x00, 0x00, 0x00, 0x00, // reserved bits.
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa1, // IPv6 address
				0x01,                               // option - 1 for Source Link-layer Address
				0x01,                               // length (units of 8 octets including type and length fields)
				0x00, 0x11, 0x22, 0x33, 0x44, 0x66, // hardware address
			},
			requestIP: netip.MustParseAddr("fe80::c1"),
			assignedIPs: []netip.Addr{
				netip.MustParseAddr("fe80::a1"),
				netip.MustParseAddr("fe80::a2"),
			},
			expectError: false,
			expectedReply: []byte{
				0x88,       // type - 136 for Neighbor Advertisement
				0x00,       // code
				0x00, 0x00, // checksum
				0x60, 0x00, 0x00, 0x00, // flags and reserved bits. Solicited and Override bits are set.
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa1, // IPv6 address
				0x02,                               // option - 2 for Target Link-layer Address
				0x01,                               // length (units of 8 octets including type and length fields)
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // hardware address
			},
		},
		{
			name: "request to not assigned IP",
			requestMessage: []byte{
				0x87,       // type - 135 for Neighbor Solicitation
				0x00,       // code
				0x00, 0x00, // checksum
				0x00, 0x00, 0x00, 0x00, // reserved bits.
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa3, // IPv6 address
				0x01,                               // option - 1 for Source Link-layer Address
				0x01,                               // length (units of 8 octets including type and length fields)
				0x00, 0x11, 0x22, 0x33, 0x44, 0x66, // hardware address
			},
			requestIP: netip.MustParseAddr("fe80::c1"),
			assignedIPs: []netip.Addr{
				netip.MustParseAddr("fe80::a1"),
				netip.MustParseAddr("fe80::a2"),
			},
			expectError:   false,
			expectedReply: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffer := bytes.NewBuffer(nil)
			fakeConn := &fakeNDPConn{
				writeTo: func(msg ndp.Message, _ *ipv6.ControlMessage, _ netip.Addr) error {
					bs, err := ndp.MarshalMessage(msg)
					assert.NoError(t, err)
					buffer.Write(bs)
					return nil
				},
				readFrom: func() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error) {
					msg, err := ndp.ParseMessage(tt.requestMessage)
					return msg, nil, tt.requestIP, err
				},
			}
			assignedIPs := sets.New[string]()
			for _, ip := range tt.assignedIPs {
				assignedIPs.Insert(ip.String())
			}
			responder := &ndpResponder{
				linkName:    iface.Name,
				conn:        fakeConn,
				assignedIPs: sets.New[netip.Addr](),
			}
			for _, ip := range tt.assignedIPs {
				responder.assignedIPs[ip] = struct{}{}
			}
			err := responder.handleNeighborSolicitation(fakeConn, iface)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedReply, buffer.Bytes())
			}
		})
	}
}

func Test_parseIPv6SolicitedNodeMulticastAddress(t *testing.T) {
	tests := []struct {
		name          string
		ip            netip.Addr
		expectedGroup netip.Addr
		expectedKey   int
	}{
		{
			name:          "global unicast IPv6 address 1",
			ip:            netip.MustParseAddr("2022:abcd::11:1111"),
			expectedGroup: netip.MustParseAddr("ff02::1:ff11:1111"),
		},
		{
			name:          "global unicast IPv6 address 2",
			ip:            netip.MustParseAddr("2022:ffff::1234:5678"),
			expectedGroup: netip.MustParseAddr("ff02::1:ff34:5678"),
		},
		{
			name:          "link-local unicast IPv6 address",
			ip:            netip.MustParseAddr("fe80::1122:3344"),
			expectedGroup: netip.MustParseAddr("ff02::1:ff22:3344"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := parseIPv6SolicitedNodeMulticastAddress(tt.ip)
			assert.Equal(t, tt.expectedGroup, group)
		})
	}
}

func Test_ndpResponder_addIP(t *testing.T) {
	hwAddr := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	iface := newFakeNetworkInterface(hwAddr)

	tests := []struct {
		name                    string
		ip                      netip.Addr
		conn                    ndpConn
		assignedIPs             sets.Set[netip.Addr]
		multicastGroups         map[netip.Addr]int
		expectedJoinedGroups    []netip.Addr
		expectedLeftGroups      []netip.Addr
		expectedMulticastGroups map[netip.Addr]int
		expectedAssigndIPs      sets.Set[netip.Addr]
		expectedError           bool
	}{
		{
			name:                 "Add new IP from a new multicast group 1",
			ip:                   netip.MustParseAddr("2022::beaf"),
			assignedIPs:          sets.New[netip.Addr](),
			multicastGroups:      map[netip.Addr]int{},
			expectedJoinedGroups: []netip.Addr{netip.MustParseAddr("ff02::1:ff00:beaf")},
			expectedLeftGroups:   nil,
			expectedMulticastGroups: map[netip.Addr]int{
				netip.MustParseAddr("ff02::1:ff00:beaf"): 1,
			},
			expectedAssigndIPs: sets.New[netip.Addr](netip.MustParseAddr("2022::beaf")),
		},
		{
			name:                 "Add new IP from a new multicast group 2",
			ip:                   netip.MustParseAddr("2022::beaf:beaf"),
			assignedIPs:          sets.New[netip.Addr](),
			multicastGroups:      map[netip.Addr]int{},
			expectedJoinedGroups: []netip.Addr{netip.MustParseAddr("ff02::1:ffaf:beaf")},
			expectedLeftGroups:   nil,
			expectedMulticastGroups: map[netip.Addr]int{
				netip.MustParseAddr("ff02::1:ffaf:beaf"): 1,
			},
			expectedAssigndIPs: sets.New[netip.Addr](netip.MustParseAddr("2022::beaf:beaf")),
		},
		{
			name:        "Add new IP from an existing multicast group",
			ip:          netip.MustParseAddr("2021::beaf"),
			assignedIPs: sets.New[netip.Addr](netip.MustParseAddr("2022::beaf")),
			multicastGroups: map[netip.Addr]int{
				netip.MustParseAddr("ff02::1:ff00:beaf"): 1,
			},
			expectedJoinedGroups: nil,
			expectedLeftGroups:   nil,
			expectedMulticastGroups: map[netip.Addr]int{
				netip.MustParseAddr("ff02::1:ff00:beaf"): 2,
			},
			expectedAssigndIPs: sets.New[netip.Addr](netip.MustParseAddr("2021::beaf"), netip.MustParseAddr("2022::beaf")),
		},
		{
			name:                    "Add invalid IP",
			ip:                      netip.MustParseAddr("1.2.3.4"),
			assignedIPs:             sets.New[netip.Addr](),
			multicastGroups:         map[netip.Addr]int{},
			expectedError:           true,
			expectedMulticastGroups: map[netip.Addr]int{},
			expectedAssigndIPs:      sets.New[netip.Addr](),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var joinedGroup, leftGroup []netip.Addr
			r := &ndpResponder{
				linkName: iface.Name,
				conn: &fakeNDPConn{
					joinGroup: func(ip netip.Addr) error {
						joinedGroup = append(joinedGroup, ip)
						return nil
					},
					leaveGroup: func(ip netip.Addr) error {
						leftGroup = append(leftGroup, ip)
						return nil
					},
					writeTo: func(_ ndp.Message, _ *ipv6.ControlMessage, _ netip.Addr) error {
						return nil
					},
				},
				assignedIPs:     tt.assignedIPs,
				multicastGroups: tt.multicastGroups,
			}
			err := r.AddIP(tt.ip.AsSlice())
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedJoinedGroups, joinedGroup)
			assert.Equal(t, tt.expectedLeftGroups, leftGroup)
			assert.Equal(t, tt.expectedAssigndIPs, r.assignedIPs)
			assert.Equal(t, tt.expectedMulticastGroups, r.multicastGroups)
		})
	}
}

func Test_ndpResponder_removeIP(t *testing.T) {
	hwAddr := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	iface := newFakeNetworkInterface(hwAddr)

	tests := []struct {
		name                    string
		ip                      netip.Addr
		conn                    ndpConn
		assignedIPs             sets.Set[netip.Addr]
		multicastGroups         map[netip.Addr]int
		expectedJoinedGroups    []netip.Addr
		expectedLeftGroups      []netip.Addr
		expectedMulticastGroups map[netip.Addr]int
		expectedAssigndIPs      sets.Set[netip.Addr]
		expectedError           bool
	}{
		{
			name:        "Remove IP and leave multicast group",
			ip:          netip.MustParseAddr("2022::beaf"),
			assignedIPs: sets.New[netip.Addr](netip.MustParseAddr("2022::beaf")),
			multicastGroups: map[netip.Addr]int{
				netip.MustParseAddr("ff02::1:ff00:beaf"): 1,
			},
			expectedJoinedGroups:    nil,
			expectedLeftGroups:      []netip.Addr{netip.MustParseAddr("ff02::1:ff00:beaf")},
			expectedMulticastGroups: map[netip.Addr]int{},
			expectedAssigndIPs:      sets.New[netip.Addr](),
		},
		{
			name: "Remove IP and should not leave multicast group",
			ip:   netip.MustParseAddr("2022::beaf"),
			assignedIPs: sets.New[netip.Addr](
				netip.MustParseAddr("2022::beaf"),
				netip.MustParseAddr("2021::beaf"),
			),
			multicastGroups: map[netip.Addr]int{
				netip.MustParseAddr("ff02::1:ff00:beaf"): 2,
			},
			expectedJoinedGroups: nil,
			expectedLeftGroups:   nil,
			expectedMulticastGroups: map[netip.Addr]int{
				netip.MustParseAddr("ff02::1:ff00:beaf"): 1,
			},
			expectedAssigndIPs: sets.New[netip.Addr](netip.MustParseAddr("2021::beaf")),
		},
		{
			name:        "Remove non-existent IP",
			ip:          netip.MustParseAddr("2022::beaf"),
			assignedIPs: sets.New[netip.Addr](netip.MustParseAddr("2021::beaf")),
			multicastGroups: map[netip.Addr]int{
				netip.MustParseAddr("ff02::1:ff00:beaf"): 1,
			},
			expectedJoinedGroups: nil,
			expectedLeftGroups:   nil,
			expectedMulticastGroups: map[netip.Addr]int{
				netip.MustParseAddr("ff02::1:ff00:beaf"): 1,
			},
			expectedAssigndIPs: sets.New[netip.Addr](netip.MustParseAddr("2021::beaf")),
		}, {
			name:        "Remove invalid IP",
			ip:          netip.MustParseAddr("1.2.3.4"),
			assignedIPs: sets.New[netip.Addr](netip.MustParseAddr("2021::beaf")),
			multicastGroups: map[netip.Addr]int{
				netip.MustParseAddr("ff02::1:ff00:beaf"): 1,
			},
			expectedJoinedGroups: nil,
			expectedLeftGroups:   nil,
			expectedMulticastGroups: map[netip.Addr]int{
				netip.MustParseAddr("ff02::1:ff00:beaf"): 1,
			},
			expectedAssigndIPs: sets.New[netip.Addr](netip.MustParseAddr("2021::beaf")),
			expectedError:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var joinedGroup, leftGroup []netip.Addr
			r := &ndpResponder{
				linkName: iface.Name,
				conn: &fakeNDPConn{
					joinGroup: func(ip netip.Addr) error {
						joinedGroup = append(joinedGroup, ip)
						return nil
					},
					leaveGroup: func(ip netip.Addr) error {
						leftGroup = append(leftGroup, ip)
						return nil
					},
				},
				assignedIPs:     tt.assignedIPs,
				multicastGroups: tt.multicastGroups,
			}
			err := r.RemoveIP(tt.ip.AsSlice())
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedJoinedGroups, joinedGroup)
			assert.Equal(t, tt.expectedLeftGroups, leftGroup)
			assert.Equal(t, tt.expectedAssigndIPs, r.assignedIPs)
			assert.Equal(t, tt.expectedMulticastGroups, r.multicastGroups)
		})
	}
}
