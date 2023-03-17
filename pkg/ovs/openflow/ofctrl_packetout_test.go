// Copyright 2022 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openflow

import (
	"math/rand"
	"net"
	"reflect"
	"testing"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
)

func Test_ofPacketOutBuilder_SetSrcIP(t *testing.T) {
	type fields struct {
		pktOut  *ofctrl.PacketOut
		icmpID  *uint16
		icmpSeq *uint16
	}
	type args struct {
		ip net.IP
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   PacketOutBuilder
	}{
		{
			name: "IPv4 new",
			fields: fields{
				pktOut:  new(ofctrl.PacketOut),
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{ip: net.ParseIP("1.2.3.4")},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						NWSrc: net.ParseIP("1.2.3.4"),
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "IPv4 existing",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{ip: net.ParseIP("1.2.3.4")},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						NWSrc: net.ParseIP("1.2.3.4"),
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "IPv6 new",
			fields: fields{
				pktOut:  new(ofctrl.PacketOut),
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{ip: net.ParseIP("aaaa::")},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{
						NWSrc: net.ParseIP("aaaa::"),
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "IPv6 existing",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{ip: net.ParseIP("aaaa::")},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{
						NWSrc: net.ParseIP("aaaa::"),
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &ofPacketOutBuilder{
				pktOut:  tt.fields.pktOut,
				icmpID:  tt.fields.icmpID,
				icmpSeq: tt.fields.icmpSeq,
			}
			if got := b.SetSrcIP(tt.args.ip); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetSrcIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ofPacketOutBuilder_SetDstIP(t *testing.T) {
	type fields struct {
		pktOut  *ofctrl.PacketOut
		icmpID  *uint16
		icmpSeq *uint16
	}
	type args struct {
		ip net.IP
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   PacketOutBuilder
	}{
		{
			name: "IPv4 new",
			fields: fields{
				pktOut:  new(ofctrl.PacketOut),
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{ip: net.ParseIP("1.2.3.4")},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						NWDst: net.ParseIP("1.2.3.4"),
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "IPv4 existing",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{ip: net.ParseIP("1.2.3.4")},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						NWDst: net.ParseIP("1.2.3.4"),
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "IPv6 new",
			fields: fields{
				pktOut:  new(ofctrl.PacketOut),
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{ip: net.ParseIP("aaaa::")},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{
						NWDst: net.ParseIP("aaaa::"),
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "IPv6 existing",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{ip: net.ParseIP("aaaa::")},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{
						NWDst: net.ParseIP("aaaa::"),
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &ofPacketOutBuilder{
				pktOut:  tt.fields.pktOut,
				icmpID:  tt.fields.icmpID,
				icmpSeq: tt.fields.icmpSeq,
			}
			if got := b.SetDstIP(tt.args.ip); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetDstIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ofPacketOutBuilder_SetIPProtocol(t *testing.T) {
	type fields struct {
		pktOut  *ofctrl.PacketOut
		icmpID  *uint16
		icmpSeq *uint16
	}
	type args struct {
		proto Protocol
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   PacketOutBuilder
	}{
		{
			name: "ProtocolTCPv6",
			fields: fields{
				pktOut:  &ofctrl.PacketOut{},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{proto: ProtocolTCPv6},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{
						NextHeader: protocol.Type_TCP,
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "ProtocolUDPv6",
			fields: fields{
				pktOut:  &ofctrl.PacketOut{},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{proto: ProtocolUDPv6},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{
						NextHeader: protocol.Type_UDP,
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "ProtocolSCTPv6",
			fields: fields{
				pktOut:  &ofctrl.PacketOut{},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{proto: ProtocolSCTPv6},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{
						NextHeader: 0x84,
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "ProtocolICMPv6",
			fields: fields{
				pktOut:  &ofctrl.PacketOut{},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{proto: ProtocolICMPv6},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{
						NextHeader: protocol.Type_IPv6ICMP,
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "ProtocolTCP",
			fields: fields{
				pktOut:  &ofctrl.PacketOut{},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{proto: ProtocolTCP},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						Protocol: protocol.Type_TCP,
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "ProtocolUDP",
			fields: fields{
				pktOut:  &ofctrl.PacketOut{},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{proto: ProtocolUDP},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						Protocol: protocol.Type_UDP,
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "ProtocolSCTP",
			fields: fields{
				pktOut:  &ofctrl.PacketOut{},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{proto: ProtocolSCTP},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						Protocol: 0x84,
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "ProtocolICMP",
			fields: fields{
				pktOut:  &ofctrl.PacketOut{},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{proto: ProtocolICMP},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						Protocol: protocol.Type_ICMP,
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "ProtocolUnknown",
			fields: fields{
				pktOut:  &ofctrl.PacketOut{},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{proto: "abc"},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						Protocol: 0xff,
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &ofPacketOutBuilder{
				pktOut:  tt.fields.pktOut,
				icmpID:  tt.fields.icmpID,
				icmpSeq: tt.fields.icmpSeq,
			}
			if got := b.SetIPProtocol(tt.args.proto); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetIPProtocol() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ofPacketOutBuilder_SetTTL(t *testing.T) {
	type fields struct {
		pktOut  *ofctrl.PacketOut
		icmpID  *uint16
		icmpSeq *uint16
	}
	type args struct {
		ttl uint8
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   PacketOutBuilder
	}{
		{
			name: "New IPv4 TTL",
			fields: fields{
				pktOut:  &ofctrl.PacketOut{},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{ttl: 120},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						TTL: 120,
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "Existing IPv4 TTL",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{ttl: 120},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						TTL: 120,
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "Existing IPv6 TTL",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{ttl: 120},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{
						HopLimit: 120,
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &ofPacketOutBuilder{
				pktOut:  tt.fields.pktOut,
				icmpID:  tt.fields.icmpID,
				icmpSeq: tt.fields.icmpSeq,
			}
			if got := b.SetTTL(tt.args.ttl); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetTTL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ofPacketOutBuilder_SetIPFlags(t *testing.T) {
	type fields struct {
		pktOut  *ofctrl.PacketOut
		icmpID  *uint16
		icmpSeq *uint16
	}
	type args struct {
		flags uint16
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   PacketOutBuilder
	}{
		{
			name: "New IPv4 flags",
			fields: fields{
				pktOut:  &ofctrl.PacketOut{},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{flags: 120},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						Flags: 120,
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "Existing IPv4 flags",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{flags: 120},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						Flags: 120,
					},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
		{
			name: "Existing IPv6 flags",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{flags: 120},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &ofPacketOutBuilder{
				pktOut:  tt.fields.pktOut,
				icmpID:  tt.fields.icmpID,
				icmpSeq: tt.fields.icmpSeq,
			}
			if got := b.SetIPFlags(tt.args.flags); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetIPFlags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ofPacketOutBuilder_SetTCPHdrLen(t *testing.T) {
	tests := []struct {
		name          string
		pktOutBuilder *ofPacketOutBuilder
		tcpHdrLen     uint8
		want          PacketOutBuilder
	}{
		{
			name:          "New TCP header",
			pktOutBuilder: &ofPacketOutBuilder{pktOut: new(ofctrl.PacketOut)},
			tcpHdrLen:     5,
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					TCPHeader: &protocol.TCP{
						HdrLen: 5,
					},
				},
			},
		},
		{
			name: "Existing TCP header",
			pktOutBuilder: &ofPacketOutBuilder{pktOut: &ofctrl.PacketOut{
				TCPHeader: &protocol.TCP{},
			}},
			tcpHdrLen: 5,
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					TCPHeader: &protocol.TCP{
						HdrLen: 5,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pktOutBuilder.SetTCPHdrLen(tt.tcpHdrLen); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetTCPHdrLen() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ofPacketOutBuilder_SetTCPWinSize(t *testing.T) {
	tests := []struct {
		name          string
		pktOutBuilder *ofPacketOutBuilder
		tcpWinSize    uint16
		want          PacketOutBuilder
	}{
		{
			name:          "New TCP header",
			pktOutBuilder: &ofPacketOutBuilder{pktOut: new(ofctrl.PacketOut)},
			tcpWinSize:    1,
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					TCPHeader: &protocol.TCP{
						WinSize: 1,
					},
				},
			},
		},
		{
			name: "Existing TCP header",
			pktOutBuilder: &ofPacketOutBuilder{pktOut: &ofctrl.PacketOut{
				TCPHeader: &protocol.TCP{},
			}},
			tcpWinSize: 1,
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					TCPHeader: &protocol.TCP{
						WinSize: 1,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pktOutBuilder.SetTCPWinSize(tt.tcpWinSize); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetTCPWinSize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ofPacketOutBuilder_SetTCPData(t *testing.T) {
	tests := []struct {
		name          string
		pktOutBuilder *ofPacketOutBuilder
		tcpData       []byte
		want          PacketOutBuilder
	}{
		{
			name:          "New TCP header",
			pktOutBuilder: &ofPacketOutBuilder{pktOut: new(ofctrl.PacketOut)},
			tcpData:       []byte{1},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					TCPHeader: &protocol.TCP{
						Data: []byte{1},
					},
				},
			},
		},
		{
			name: "Existing TCP header",
			pktOutBuilder: &ofPacketOutBuilder{pktOut: &ofctrl.PacketOut{
				TCPHeader: &protocol.TCP{},
			}},
			tcpData: []byte{1},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					TCPHeader: &protocol.TCP{
						Data: []byte{1},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pktOutBuilder.SetTCPData(tt.tcpData); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetTCPData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ofPacketOutBuilder_Done(t *testing.T) {
	type fields struct {
		pktOut  *ofctrl.PacketOut
		icmpID  *uint16
		icmpSeq *uint16
	}
	icmpID := uint16(1)
	icmpSeq := uint16(2)
	tests := []struct {
		name   string
		fields fields
		want   *ofctrl.PacketOut
	}{
		{
			name: "Invalid",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPHeader:   &protocol.IPv4{},
					IPv6Header: &protocol.IPv6{},
				},
				icmpID:  nil,
				icmpSeq: nil,
			},
			want: nil,
		},
		{
			name: "IPv4 ICMP",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{},
					ICMPHeader: &protocol.ICMP{
						Type: 3,
						Code: 4,
					},
				},
				icmpID:  &icmpID,
				icmpSeq: &icmpSeq,
			},
			want: &ofctrl.PacketOut{
				IPHeader: &protocol.IPv4{
					Version:  0x4,
					Length:   28,
					Checksum: 46753,
					Id:       1090,
				},
				ICMPHeader: &protocol.ICMP{
					Type:     3,
					Code:     4,
					Checksum: 64760,
					Data:     []byte{0x0, 0x1, 0x0, 0x2},
				},
			},
		},
		{
			name: "IPv4 TCP",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{},
					TCPHeader: &protocol.TCP{
						PortSrc: 10000,
						PortDst: 10001,
						HdrLen:  5,
					},
				},
			},
			want: &ofctrl.PacketOut{
				IPHeader: &protocol.IPv4{
					Version:  0x4,
					Length:   40,
					Checksum: 8009,
					Id:       39822,
				},
				TCPHeader: &protocol.TCP{
					PortSrc:  10000,
					PortDst:  10001,
					HdrLen:   5,
					Checksum: 40408,
					SeqNum:   2596996162,
					AckNum:   4039455774,
				},
			},
		},
		{
			name: "IPv4 UDP",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{},
					UDPHeader: &protocol.UDP{
						PortSrc: 10000,
						PortDst: 10001,
					},
				},
			},
			want: &ofctrl.PacketOut{
				IPHeader: &protocol.IPv4{
					Version:  0x4,
					Length:   28,
					Checksum: 46753,
					Id:       1090,
				},
				UDPHeader: &protocol.UDP{
					PortSrc:  10000,
					PortDst:  10001,
					Length:   8,
					Checksum: 45518,
				},
			},
		},
		{
			name: "IPv6 ICMP",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{},
					ICMPHeader: &protocol.ICMP{
						Type: 3,
						Code: 4,
					},
				},
				icmpID:  &icmpID,
				icmpSeq: &icmpSeq,
			},
			want: &ofctrl.PacketOut{
				IPv6Header: &protocol.IPv6{
					Version: 0x6,
					Length:  8,
				},
				ICMPHeader: &protocol.ICMP{
					Type:     3,
					Code:     4,
					Checksum: 64752,
					Data:     []byte{0x0, 0x1, 0x0, 0x2},
				},
			},
		},
		{
			name: "IPv6 TCP",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{},
					TCPHeader: &protocol.TCP{
						PortSrc: 10000,
						PortDst: 10001,
						HdrLen:  5,
					},
				},
			},
			want: &ofctrl.PacketOut{
				IPv6Header: &protocol.IPv6{
					Version: 0x6,
					Length:  20,
				},
				TCPHeader: &protocol.TCP{
					PortSrc:  10000,
					PortDst:  10001,
					HdrLen:   5,
					Checksum: 40408,
					SeqNum:   2596996162,
					AckNum:   4039455774,
				},
			},
		},
		{
			name: "IPv6 UDP",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{},
					UDPHeader: &protocol.UDP{
						PortSrc: 10000,
						PortDst: 10001,
					},
				},
			},
			want: &ofctrl.PacketOut{
				IPv6Header: &protocol.IPv6{
					Version: 0x6,
					Length:  8,
				},
				UDPHeader: &protocol.UDP{
					PortSrc:  10000,
					PortDst:  10001,
					Length:   8,
					Checksum: 45518,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Specify a hardcoded seed for testing to make output predictable.
			// #nosec G404: random number generator not used for security purposes
			pktRand = rand.New(rand.NewSource(1))
			b := &ofPacketOutBuilder{
				pktOut:  tt.fields.pktOut,
				icmpID:  tt.fields.icmpID,
				icmpSeq: tt.fields.icmpSeq,
			}
			got := b.Done()
			assert.Equal(t, tt.want, got)
		})
	}
}
