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
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/packet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/v2/pkg/agent/util/nettest"
)

func newFakeARPClient(iface *net.Interface, conn *nettest.PacketConn) (*arp.Client, error) {
	return arp.New(iface, conn)
}

// loopbackIndex returns the OS interface index of the first loopback interface.
// net.Interface.Addrs() queries the OS by Index, so pointing the fake interface
// at the loopback index makes Addrs() return a valid IPv4 address, satisfying
// arp.New (since commit 6706a29) without borrowing an entirely separate struct.
func loopbackIndex() (int, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface.Index, nil
		}
	}
	return 0, fmt.Errorf("no loopback interface found")
}

// newFakeNetworkInterface creates a fake net.Interface with the given index and
// hardware address. Callers that pass the interface to arp.New must supply a
// valid OS interface index (e.g. from loopbackIndex); callers that only need
// the interface for its name or hardware address can use any non-zero index.
func newFakeNetworkInterface(index int, hardwareAddr []byte) *net.Interface {
	return &net.Interface{
		Index:        index,
		MTU:          1500,
		Name:         "eth0",
		HardwareAddr: hardwareAddr,
	}
}

func getEthernetForARPPacket(p *arp.Packet, addr net.HardwareAddr) []byte {
	pb, _ := p.MarshalBinary()
	f := &ethernet.Frame{
		Destination: addr,
		Source:      p.SenderHardwareAddr,
		EtherType:   ethernet.EtherTypeARP,
		Payload:     pb,
	}
	fb, _ := f.MarshalBinary()
	return fb
}

func TestARPResponder_HandleARPRequest(t *testing.T) {
	// arp.New calls iface.Addrs() internally; a real OS interface index is
	// required so that the OS can resolve addresses for the interface.
	loopbackIdx, err := loopbackIndex()
	if err != nil {
		t.Skipf("Skipping test: loopback interface not available: %v", err)
	}

	// The "local" endpoint is the one running the ARPResponder.
	// The "remote" endpoint is the one sending ARP requests to the "local" endpoint.
	localHWAddr := net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	remoteHWAddr := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	localIPAddr := netip.MustParseAddr("192.168.10.1")
	remoteIPAddr := netip.MustParseAddr("192.168.10.2")

	tests := []struct {
		name          string
		assignedIPs   []netip.Addr
		replyExpected bool
	}{
		{
			name:          "Response for assigned IP",
			assignedIPs:   []netip.Addr{localIPAddr},
			replyExpected: true,
		},
		{
			name:          "Response for not assigned IP",
			assignedIPs:   []netip.Addr{netip.MustParseAddr("192.168.10.3")},
			replyExpected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			localIface := newFakeNetworkInterface(loopbackIdx, localHWAddr)
			remoteIface := newFakeNetworkInterface(loopbackIdx, remoteHWAddr)
			localAddr := &packet.Addr{
				HardwareAddr: localHWAddr,
			}
			remoteAddr := &packet.Addr{
				HardwareAddr: remoteHWAddr,
			}
			localConn, remoteConn := nettest.PacketConnPipe(localAddr, remoteAddr, 1)
			localARPClient, err := newFakeARPClient(localIface, localConn)
			require.NoError(t, err)
			remoteARPClient, err := newFakeARPClient(remoteIface, remoteConn)
			require.NoError(t, err)
			request, err := arp.NewPacket(arp.OperationRequest, remoteHWAddr, remoteIPAddr, ethernet.Broadcast, localIPAddr)
			require.NoError(t, err)
			expectedReply, err := arp.NewPacket(arp.OperationReply, localHWAddr, localIPAddr, remoteHWAddr, remoteIPAddr)
			require.NoError(t, err)
			expectedBytes := getEthernetForARPPacket(expectedReply, remoteHWAddr)
			require.NoError(t, remoteARPClient.WriteTo(request, localAddr.HardwareAddr))
			r := arpResponder{
				linkName:    localIface.Name,
				assignedIPs: sets.New[netip.Addr](),
			}
			for _, ip := range tt.assignedIPs {
				r.AddIP(ip)
			}
			err = r.handleARPRequest(localARPClient, localIface)
			require.NoError(t, err)
			// We cannot use remoteARPClient.ReadFrom as it is blocking.
			replyB, addr, err := remoteConn.Receive()
			if !tt.replyExpected {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, remoteAddr, addr)
				assert.Equal(t, expectedBytes, replyB)
			}
		})
	}
}

func Test_arpResponder_addIP(t *testing.T) {
	hwAddr := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	iface := newFakeNetworkInterface(1, hwAddr)

	tests := []struct {
		name                string
		ip                  netip.Addr
		assignedIPs         sets.Set[netip.Addr]
		expectedError       bool
		expectedAssignedIPs sets.Set[netip.Addr]
	}{
		{
			name:                "Add new IP",
			ip:                  netip.MustParseAddr("2.0.2.2"),
			assignedIPs:         sets.New[netip.Addr](),
			expectedAssignedIPs: sets.New[netip.Addr](netip.MustParseAddr("2.0.2.2")),
		},
		{
			name:                "Add new IP with some IPs added",
			ip:                  netip.MustParseAddr("2.0.2.2"),
			assignedIPs:         sets.New[netip.Addr](netip.MustParseAddr("2.0.2.1")),
			expectedAssignedIPs: sets.New[netip.Addr](netip.MustParseAddr("2.0.2.1"), netip.MustParseAddr("2.0.2.2")),
		},
		{
			name:                "Add invalid IP",
			ip:                  netip.MustParseAddr("2022::abcd"),
			assignedIPs:         sets.New[netip.Addr](netip.MustParseAddr("2.0.2.1")),
			expectedAssignedIPs: sets.New[netip.Addr](netip.MustParseAddr("2.0.2.1")),
			expectedError:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &arpResponder{
				linkName:    iface.Name,
				assignedIPs: tt.assignedIPs,
			}
			err := r.AddIP(tt.ip)
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
	hwAddr := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	iface := newFakeNetworkInterface(1, hwAddr)

	tests := []struct {
		name                string
		ip                  netip.Addr
		assignedIPs         sets.Set[netip.Addr]
		expectedError       bool
		expectedAssignedIPs sets.Set[netip.Addr]
	}{
		{
			name:                "Remove existing IP",
			ip:                  netip.MustParseAddr("2.0.2.2"),
			assignedIPs:         sets.New[netip.Addr](netip.MustParseAddr("2.0.2.2")),
			expectedAssignedIPs: sets.New[netip.Addr](),
		},
		{
			name:                "Remove non-existent IP",
			ip:                  netip.MustParseAddr("2.0.2.2"),
			assignedIPs:         sets.New[netip.Addr](netip.MustParseAddr("2.0.2.1")),
			expectedAssignedIPs: sets.New[netip.Addr](netip.MustParseAddr("2.0.2.1")),
		},
		{
			name:                "Remove invalid IP",
			ip:                  netip.MustParseAddr("2022::abcd"),
			assignedIPs:         sets.New[netip.Addr](netip.MustParseAddr("2.0.2.1")),
			expectedAssignedIPs: sets.New[netip.Addr](netip.MustParseAddr("2.0.2.1")),
			expectedError:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &arpResponder{
				linkName:    iface.Name,
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
