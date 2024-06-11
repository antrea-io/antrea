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
	"net"
	"testing"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/packet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/util/nettest"
)

func newFakeARPClient(iface *net.Interface, conn *nettest.PacketConn) (*arp.Client, error) {
	return arp.New(iface, conn)
}

func newFakeNetworkInterface(hardwareAddr []byte) *net.Interface {
	return &net.Interface{
		Index:        0,
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
	// The "local" endpoint is the one running the ARPRespondder.
	// The "remote" endpoint is the one sending ARP requests to the "local" endpoint.
	localHWAddr := net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	remoteHWAddr := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	localIP := net.ParseIP("192.168.10.1")
	remoteIP := net.ParseIP("192.168.10.2")

	tests := []struct {
		name          string
		assignedIPs   []net.IP
		replyExpected bool
	}{
		{
			name:          "Response for assigned IP",
			assignedIPs:   []net.IP{localIP},
			replyExpected: true,
		},
		{
			name:          "Response for not assigned IP",
			assignedIPs:   []net.IP{net.ParseIP("192.168.10.3")},
			replyExpected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			localIface := newFakeNetworkInterface(localHWAddr)
			remoteIface := newFakeNetworkInterface(remoteHWAddr)
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
			request, err := arp.NewPacket(arp.OperationRequest, remoteHWAddr, remoteIP, ethernet.Broadcast, localIP)
			require.NoError(t, err)
			expectedReply, err := arp.NewPacket(arp.OperationReply, localHWAddr, localIP, remoteHWAddr, remoteIP)
			require.NoError(t, err)
			expectedBytes := getEthernetForARPPacket(expectedReply, remoteHWAddr)
			require.NoError(t, remoteARPClient.WriteTo(request, localAddr.HardwareAddr))
			assignedIPs := sets.New[string]()
			for _, ip := range tt.assignedIPs {
				assignedIPs.Insert(ip.String())
			}
			r := arpResponder{
				iface:       localIface,
				conn:        localARPClient,
				assignedIPs: sets.New[string](),
			}
			for _, ip := range tt.assignedIPs {
				r.AddIP(ip)
			}
			err = r.handleARPRequest()
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
	iface := newFakeNetworkInterface(hwAddr)

	tests := []struct {
		name                string
		ip                  net.IP
		assignedIPs         sets.Set[string]
		expectedError       bool
		expectedAssignedIPs sets.Set[string]
	}{
		{
			name:                "Add new IP",
			ip:                  net.ParseIP("2.0.2.2"),
			assignedIPs:         sets.New[string](),
			expectedAssignedIPs: sets.New[string]("2.0.2.2"),
		},
		{
			name:                "Add new IP with some IPs added",
			ip:                  net.ParseIP("2.0.2.2"),
			assignedIPs:         sets.New[string]("2.0.2.1"),
			expectedAssignedIPs: sets.New[string]("2.0.2.1", "2.0.2.2"),
		},
		{
			name:                "Add invalid IP",
			ip:                  net.ParseIP("2022::abcd"),
			assignedIPs:         sets.New[string]("2.0.2.1"),
			expectedAssignedIPs: sets.New[string]("2.0.2.1"),
			expectedError:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &arpResponder{
				iface:       iface,
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
	iface := newFakeNetworkInterface(hwAddr)

	tests := []struct {
		name                string
		ip                  net.IP
		assignedIPs         sets.Set[string]
		expectedError       bool
		expectedAssignedIPs sets.Set[string]
	}{
		{
			name:                "Remove existing IP",
			ip:                  net.ParseIP("2.0.2.2"),
			assignedIPs:         sets.New[string]("2.0.2.2"),
			expectedAssignedIPs: sets.New[string](),
		},
		{
			name:                "Remove non-existent IP",
			ip:                  net.ParseIP("2.0.2.2"),
			assignedIPs:         sets.New[string]("2.0.2.1"),
			expectedAssignedIPs: sets.New[string]("2.0.2.1"),
		},
		{
			name:                "Remove invalid IP",
			ip:                  net.ParseIP("2022::abcd"),
			assignedIPs:         sets.New[string]("2.0.2.1"),
			expectedAssignedIPs: sets.New[string]("2.0.2.1"),
			expectedError:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &arpResponder{
				iface:       iface,
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
