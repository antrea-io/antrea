// Copyright 2021 Antrea Authors
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

package openflow

import (
	"net"
	"testing"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
)

func TestGetTCPHeaderData(t *testing.T) {
	type args struct {
		tcp              protocol.TCP
		expectTCPSrcPort uint16
		expectTCPDstPort uint16
		expectTCPSeqNum  uint32
		expectTCPAckNum  uint32
		expectTCPCode    uint8
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "GetTCPHeader-ipv4",
			args: args{
				tcp: protocol.TCP{
					PortSrc: 1080,
					PortDst: 80,
					SeqNum:  0,
					AckNum:  0,
					Code:    2,
				},
				expectTCPSrcPort: 1080,
				expectTCPDstPort: 80,
				expectTCPSeqNum:  0,
				expectTCPAckNum:  0,
				expectTCPCode:    2,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tcp := tt.args.tcp
			pktIn := new(protocol.IPv4)
			bytes, _ := tcp.MarshalBinary()
			bf := new(util.Buffer)
			bf.UnmarshalBinary(bytes)
			pktIn.Data = bf

			tcpSrcPort, tcpDstPort, tcpSeqNum, tcpAckNum, tcpCode, err := GetTCPHeaderData(pktIn)
			require.NoError(t, err, "GetTCPHeaderData() returned an error")
			assert.Equal(t, tt.args.expectTCPSrcPort, tcpSrcPort)
			assert.Equal(t, tt.args.expectTCPDstPort, tcpDstPort)
			assert.Equal(t, tt.args.expectTCPSeqNum, tcpSeqNum)
			assert.Equal(t, tt.args.expectTCPAckNum, tcpAckNum)
			assert.Equal(t, tt.args.expectTCPCode, tcpCode)
		})
	}
}

func TestGetUDPHeaderData(t *testing.T) {
	type args struct {
		udp              protocol.UDP
		expectUDPSrcPort uint16
		expectUDPDstPort uint16
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "GetUDPHeader-ipv4",
			args: args{
				udp: protocol.UDP{
					PortSrc: 1080,
					PortDst: 80,
				},
				expectUDPSrcPort: 1080,
				expectUDPDstPort: 80,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pktIn := new(protocol.IPv4)
			pktIn.Data = &tt.args.udp

			udpSrcPort, udpDstPort, err := GetUDPHeaderData(pktIn)
			require.NoError(t, err, "GetUDPHeaderData() returned an error")
			assert.Equal(t, tt.args.expectUDPSrcPort, udpSrcPort)
			assert.Equal(t, tt.args.expectUDPDstPort, udpDstPort)
		})
	}
}

func TestGetICMPHeaderData(t *testing.T) {
	testEcho, _ := (&icmp.Echo{ID: 1, Seq: 2}).Marshal(0)
	type args struct {
		icmp              protocol.ICMP
		expectICMPType    uint8
		expectICMPCode    uint8
		expectICMPEchoID  uint16
		expectICMPEchoSeq uint16
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "GetICMPHeader-ipv4",
			args: args{
				icmp: protocol.ICMP{
					Type: icmpEchoRequestType,
					Code: 0,
					Data: testEcho,
				},
				expectICMPType:    icmpEchoRequestType,
				expectICMPCode:    0,
				expectICMPEchoID:  1,
				expectICMPEchoSeq: 2,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pktIn := new(protocol.IPv4)
			pktIn.Data = &tt.args.icmp

			icmpType, icmpCode, icmpEchoID, icmpEchoSeq, err := getICMPHeaderData(pktIn)
			require.NoError(t, err, "GetICMPHeaderData() returned an error")
			assert.Equal(t, tt.args.expectICMPType, icmpType)
			assert.Equal(t, tt.args.expectICMPCode, icmpCode)
			assert.Equal(t, tt.args.expectICMPEchoID, icmpEchoID)
			assert.Equal(t, tt.args.expectICMPEchoSeq, icmpEchoSeq)
		})
	}
}

func TestParsePacketIn(t *testing.T) {
	testMac1, _ := net.ParseMAC("00:00:5e:00:53:01")
	testMac2, _ := net.ParseMAC("00:00:5e:00:53:00")
	testIP1 := net.ParseIP("2001:db8::68")
	testIP2 := net.ParseIP("2001:db8::69")
	testTCP := protocol.TCP{
		PortSrc: 1080,
		PortDst: 80,
		Code:    uint8(net.FlagBroadcast),
	}
	testBytes, _ := testTCP.MarshalBinary()
	testBuffer := new(util.Buffer)
	testBuffer.UnmarshalBinary(testBytes)
	tests := []struct {
		name       string
		pktIn      *ofctrl.PacketIn
		expectedOb *Packet
		wantErr    bool
	}{
		{
			"ParsePacketIn-ipv6",
			&ofctrl.PacketIn{
				Reason: 1,
				Data: protocol.Ethernet{
					Ethertype: protocol.IPv6_MSG,
					HWDst:     testMac1,
					HWSrc:     testMac2,
					Data: util.Message(&protocol.IPv6{
						Length:     1,
						NextHeader: protocol.Type_TCP,
						HopLimit:   0,
						NWSrc:      testIP1,
						NWDst:      testIP2,
						Data:       testBuffer,
					}),
				},
			},
			&Packet{
				IsIPv6:          true,
				DestinationMAC:  testMac1,
				SourceMAC:       testMac2,
				DestinationIP:   testIP2,
				SourceIP:        testIP1,
				IPLength:        41,
				IPProto:         protocol.Type_TCP,
				TTL:             0,
				DestinationPort: 80,
				SourcePort:      1080,
				TCPFlags:        uint8(net.FlagBroadcast),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualOb, err := ParsePacketIn(tt.pktIn)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePacketIn() returned an error = %v, expected error = %v", err, tt.wantErr)
			}
			assert.Equal(t, tt.expectedOb, actualOb)
		})
	}
}
