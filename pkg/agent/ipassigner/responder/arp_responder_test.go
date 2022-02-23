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
	"net"
	"testing"
	"time"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/raw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
)

type fakePacketConn struct {
	addr   raw.Addr
	buffer *bytes.Buffer
}

var _ net.PacketConn = (*fakePacketConn)(nil)

func (pc *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := pc.buffer.Read(p)
	return n, &pc.addr, err
}

func (pc *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return pc.buffer.Write(p)
}

func (pc *fakePacketConn) Close() error {
	return nil
}

func (pc *fakePacketConn) LocalAddr() net.Addr {
	return &pc.addr
}

func (pc *fakePacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (pc *fakePacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (pc *fakePacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func newFakeARPClient(iface *net.Interface, conn *fakePacketConn) (*arp.Client, error) {
	return arp.New(iface, conn)
}

func newFakeNetworkInterface() *net.Interface {
	return &net.Interface{
		Index:        0,
		MTU:          1500,
		Name:         "eth0",
		HardwareAddr: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	}
}

func TestARPResponder_Advertise(t *testing.T) {
	tests := []struct {
		name          string
		iface         *net.Interface
		ip            net.IP
		expectError   bool
		expectedBytes []byte
	}{
		{
			name:        "GratuitousARP for IPv4",
			iface:       newFakeNetworkInterface(),
			ip:          net.ParseIP("192.168.10.1").To4(),
			expectError: false,
			expectedBytes: []byte{
				// ethernet header (16 bytes)
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 6 bytes: destination hardware address
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // 6 bytes: source hardware address
				0x08, 0x06, // 2 bytes: ethernet type
				// arp payload (46 bytes)
				0x00, 0x01, // 2 bytes: hardware type
				0x08, 0x00, // 2 bytes: protocol type
				0x06,       // 1 byte : hardware address length
				0x04,       // 1 byte : protocol length
				0x00, 0x01, // 2 bytes: operation
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // 6 bytes: source hardware address
				0xc0, 0xa8, 0x0a, 0x01, // 4 bytes: source protocol address
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 6 bytes: target hardware address
				0xc0, 0xa8, 0x0a, 0x01, // 4 bytes: target protocol address
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 18 bytes: padding
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{
				buffer: bytes.NewBuffer(nil),
				addr: raw.Addr{
					HardwareAddr: tt.iface.HardwareAddr,
				},
			}
			fakeARPClient, err := newFakeARPClient(tt.iface, conn)
			require.NoError(t, err)

			r := arpResponder{
				iface: tt.iface,
				conn:  fakeARPClient,
			}
			err = r.advertise(tt.ip)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBytes, conn.buffer.Bytes())
			}
		})
	}
}

func TestARPResponder_HandleARPRequest(t *testing.T) {
	tests := []struct {
		name                 string
		iface                *net.Interface
		arpOperation         arp.Operation
		srcHWAddr, dstHWAddr net.HardwareAddr
		srcIP, dstIP         net.IP
		assignedIPs          []net.IP
		expectError          bool
		expectedBytes        []byte
	}{
		{
			name:         "Response for assigned IP",
			iface:        newFakeNetworkInterface(),
			arpOperation: arp.OperationRequest,
			srcHWAddr:    net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			dstHWAddr:    ethernet.Broadcast,
			srcIP:        net.ParseIP("192.168.10.2"),
			dstIP:        net.ParseIP("192.168.10.1"),
			assignedIPs:  []net.IP{net.ParseIP("192.168.10.1")},
			expectError:  false,
			expectedBytes: []byte{
				// ethernet header (16 bytes)
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // 6 bytes: destination hardware address
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // 6 bytes: source hardware address
				0x08, 0x06, // 2 bytes: ethernet type
				// arp payload (46 bytes)
				0x00, 0x01, // 2 bytes: hardware type
				0x08, 0x00, // 2 bytes: protocol type
				0x06,       // 1 byte : hardware address length
				0x04,       // 1 byte : protocol length
				0x00, 0x02, // 2 bytes: operation
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // 6 bytes: source hardware address
				0xc0, 0xa8, 0x0a, 0x01, // 4 bytes: source protocol address
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // 6 bytes: target hardware address
				0xc0, 0xa8, 0x0a, 0x02, // 4 bytes: target protocol address
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 18 bytes: padding
			},
		},
		{
			name:          "Response for not assigned IP",
			iface:         newFakeNetworkInterface(),
			arpOperation:  arp.OperationRequest,
			srcHWAddr:     net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			dstHWAddr:     ethernet.Broadcast,
			srcIP:         net.ParseIP("192.168.10.2"),
			dstIP:         net.ParseIP("192.168.10.3"),
			assignedIPs:   []net.IP{net.ParseIP("192.168.10.1")},
			expectError:   false,
			expectedBytes: []byte{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{
				buffer: bytes.NewBuffer(nil),
				addr: raw.Addr{
					HardwareAddr: tt.iface.HardwareAddr,
				},
			}
			fakeARPClient, err := newFakeARPClient(tt.iface, conn)
			require.NoError(t, err)
			packet, err := arp.NewPacket(tt.arpOperation, tt.srcHWAddr, tt.srcIP, tt.dstHWAddr, tt.dstIP)
			require.NoError(t, err)
			err = fakeARPClient.WriteTo(packet, tt.dstHWAddr)
			require.NoError(t, err)
			assignedIPs := sets.NewString()
			for _, ip := range tt.assignedIPs {
				assignedIPs.Insert(ip.String())
			}
			r := arpResponder{
				iface:       tt.iface,
				conn:        fakeARPClient,
				assignedIPs: sets.NewString(),
			}
			for _, ip := range tt.assignedIPs {
				r.AddIP(ip)
			}
			err = r.handleARPRequest()
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBytes, conn.buffer.Bytes())
		})
	}
}

func Test_arpResponder_addIP(t *testing.T) {
	tests := []struct {
		name                string
		ip                  net.IP
		assignedIPs         sets.String
		expectedError       bool
		expectedAssignedIPs sets.String
	}{
		{
			name:                "Add new IP",
			ip:                  net.ParseIP("2.0.2.2"),
			assignedIPs:         sets.NewString(),
			expectedAssignedIPs: sets.NewString("2.0.2.2"),
		},
		{
			name:                "Add new IP with some IPs added",
			ip:                  net.ParseIP("2.0.2.2"),
			assignedIPs:         sets.NewString("2.0.2.1"),
			expectedAssignedIPs: sets.NewString("2.0.2.1", "2.0.2.2"),
		},
		{
			name:                "Add invalid IP",
			ip:                  net.ParseIP("2022::abcd"),
			assignedIPs:         sets.NewString("2.0.2.1"),
			expectedAssignedIPs: sets.NewString("2.0.2.1"),
			expectedError:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &arpResponder{
				iface:       newFakeNetworkInterface(),
				assignedIPs: tt.assignedIPs,
			}
			conn := &fakePacketConn{
				buffer: bytes.NewBuffer(nil),
				addr: raw.Addr{
					HardwareAddr: r.iface.HardwareAddr,
				},
			}
			fakeARPClient, err := newFakeARPClient(r.iface, conn)
			require.NoError(t, err)
			r.conn = fakeARPClient
			err = r.AddIP(tt.ip)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedAssignedIPs, r.assignedIPs)
		})
	}
}

func Test_arpResponder_removeIP(t *testing.T) {
	tests := []struct {
		name                string
		ip                  net.IP
		assignedIPs         sets.String
		expectedError       bool
		expectedAssignedIPs sets.String
	}{
		{
			name:                "Remove existing IP",
			ip:                  net.ParseIP("2.0.2.2"),
			assignedIPs:         sets.NewString("2.0.2.2"),
			expectedAssignedIPs: sets.NewString(),
		},
		{
			name:                "Remove non-existent IP",
			ip:                  net.ParseIP("2.0.2.2"),
			assignedIPs:         sets.NewString("2.0.2.1"),
			expectedAssignedIPs: sets.NewString("2.0.2.1"),
		},
		{
			name:                "Remove invalid IP",
			ip:                  net.ParseIP("2022::abcd"),
			assignedIPs:         sets.NewString("2.0.2.1"),
			expectedAssignedIPs: sets.NewString("2.0.2.1"),
			expectedError:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &arpResponder{
				iface:       newFakeNetworkInterface(),
				assignedIPs: tt.assignedIPs,
			}
			err := r.RemoveIP(tt.ip)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedAssignedIPs, r.assignedIPs)
		})
	}
}
