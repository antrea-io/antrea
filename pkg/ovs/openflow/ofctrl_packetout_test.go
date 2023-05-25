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

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
)

func Test_ofPacketOutBuilder(t *testing.T) {
	newPktOutBuilder := func() *ofPacketOutBuilder {
		return &ofPacketOutBuilder{
			pktOut: &ofctrl.PacketOut{},
		}
	}

	t.Run("SetSrcMAC", func(t *testing.T) {
		mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		b := newPktOutBuilder()
		pb := b.SetSrcMAC(mac)
		assert.Equal(t, mac, pb.(*ofPacketOutBuilder).pktOut.SrcMAC)
	})
	t.Run("SetDstMAC", func(t *testing.T) {
		mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		b := newPktOutBuilder()
		pb := b.SetDstMAC(mac)
		assert.Equal(t, mac, pb.(*ofPacketOutBuilder).pktOut.DstMAC)

	})
	t.Run("SetIPProtocolValue", func(t *testing.T) {
		ipv4ProtoValue := uint8(6)
		ipv6ProtoValue := uint8(17)
		testCases := []struct {
			isIPv6     bool
			protoValue uint8
			expected   *ofctrl.PacketOut
		}{
			{
				isIPv6:     true,
				protoValue: ipv6ProtoValue,
				expected: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{
						NextHeader: ipv6ProtoValue,
					},
				},
			},
			{
				isIPv6:     false,
				protoValue: ipv4ProtoValue,
				expected: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						Protocol: ipv4ProtoValue,
					},
				},
			},
		}
		for _, tc := range testCases {
			b := newPktOutBuilder()
			pb := b.SetIPProtocolValue(tc.isIPv6, tc.protoValue)
			assert.Equal(t, tc.expected, pb.(*ofPacketOutBuilder).pktOut)
		}
	})
	t.Run("SetIPHeaderID", func(t *testing.T) {
		id := uint16(111)
		testCases := []struct {
			id       uint16
			pktOut   *ofctrl.PacketOut
			expected *ofctrl.PacketOut
		}{
			{
				id:     id,
				pktOut: &ofctrl.PacketOut{},
				expected: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						Id: id,
					},
				},
			},
			{
				pktOut: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{},
				},
				expected: &ofctrl.PacketOut{
					IPv6Header: &protocol.IPv6{},
				},
			},
		}
		for _, tc := range testCases {
			b := newPktOutBuilder()
			b.pktOut = tc.pktOut
			pb := b.SetIPHeaderID(tc.id)
			assert.Equal(t, tc.expected, pb.(*ofPacketOutBuilder).pktOut)
		}
	})
	t.Run("SetTCPSrcPort", func(t *testing.T) {
		port := uint16(30000)
		b := newPktOutBuilder()
		pb := b.SetTCPSrcPort(port)
		assert.Equal(t, port, pb.(*ofPacketOutBuilder).pktOut.TCPHeader.PortSrc)
	})
	t.Run("SetTCPDstPort", func(t *testing.T) {
		port := uint16(30000)
		b := newPktOutBuilder()
		pb := b.SetTCPDstPort(port)
		assert.Equal(t, port, pb.(*ofPacketOutBuilder).pktOut.TCPHeader.PortDst)
	})
	t.Run("SetTCPFlags", func(t *testing.T) {
		tcpFlags := uint8(1)
		b := newPktOutBuilder()
		pb := b.SetTCPFlags(tcpFlags)
		assert.Equal(t, tcpFlags, pb.(*ofPacketOutBuilder).pktOut.TCPHeader.Code)
	})
	t.Run("SetTCPSeqNum", func(t *testing.T) {
		tcpSeqNum := uint32(1345678)
		b := newPktOutBuilder()
		pb := b.SetTCPSeqNum(tcpSeqNum)
		assert.Equal(t, tcpSeqNum, pb.(*ofPacketOutBuilder).pktOut.TCPHeader.SeqNum)
	})
	t.Run("SetTCPAckNum", func(t *testing.T) {
		tcpAckNum := uint32(1345678)
		b := newPktOutBuilder()
		pb := b.SetTCPAckNum(tcpAckNum)
		assert.Equal(t, tcpAckNum, pb.(*ofPacketOutBuilder).pktOut.TCPHeader.AckNum)
	})
	t.Run("SetUDPSrcPort", func(t *testing.T) {
		port := uint16(30000)
		b := newPktOutBuilder()
		pb := b.SetUDPSrcPort(port)
		assert.Equal(t, port, pb.(*ofPacketOutBuilder).pktOut.UDPHeader.PortSrc)
	})
	t.Run("SetUDPDstPort", func(t *testing.T) {
		port := uint16(30000)
		b := newPktOutBuilder()
		pb := b.SetUDPDstPort(port)
		assert.Equal(t, port, pb.(*ofPacketOutBuilder).pktOut.UDPHeader.PortDst)
	})
	t.Run("SetICMPType", func(t *testing.T) {
		icmpType := uint8(1)
		b := newPktOutBuilder()
		pb := b.SetICMPType(icmpType)
		assert.Equal(t, icmpType, pb.(*ofPacketOutBuilder).pktOut.ICMPHeader.Type)
	})
	t.Run("SetICMPCode", func(t *testing.T) {
		icmpCode := uint8(1)
		b := newPktOutBuilder()
		pb := b.SetICMPCode(icmpCode)
		assert.Equal(t, icmpCode, pb.(*ofPacketOutBuilder).pktOut.ICMPHeader.Code)
	})
	t.Run("SetICMPID", func(t *testing.T) {
		icmpID := uint16(1)
		b := newPktOutBuilder()
		pb := b.SetICMPID(icmpID)
		assert.Equal(t, icmpID, *pb.(*ofPacketOutBuilder).icmpID)
	})
	t.Run("SetICMPSequence", func(t *testing.T) {
		seq := uint16(1)
		b := newPktOutBuilder()
		pb := b.SetICMPSequence(seq)
		assert.Equal(t, seq, *pb.(*ofPacketOutBuilder).icmpSeq)
	})
	t.Run("SetICMPData", func(t *testing.T) {
		data := []byte{0x11, 0x22}
		b := newPktOutBuilder()
		pb := b.SetICMPData(data)
		assert.Equal(t, data, pb.(*ofPacketOutBuilder).pktOut.ICMPHeader.Data)
	})
	t.Run("SetUDPData", func(t *testing.T) {
		data := []byte{0x11, 0x22}
		b := newPktOutBuilder()
		pb := b.SetUDPData(data)
		assert.Equal(t, data, pb.(*ofPacketOutBuilder).pktOut.UDPHeader.Data)
	})
	t.Run("SetInport", func(t *testing.T) {
		inPort := uint32(1)
		b := newPktOutBuilder()
		pb := b.SetInport(inPort)
		assert.Equal(t, inPort, pb.(*ofPacketOutBuilder).pktOut.InPort)
	})
	t.Run("SetOutport", func(t *testing.T) {
		outPort := uint32(1)
		b := newPktOutBuilder()
		pb := b.SetOutport(outPort)
		assert.Equal(t, outPort, pb.(*ofPacketOutBuilder).pktOut.OutPort)
	})
	t.Run("SetL4Packet", func(t *testing.T) {
		igmp := &protocol.IGMPv1or2{
			Type:         protocol.IGMPQuery,
			GroupAddress: net.ParseIP("1.2.3.4"),
		}
		b := newPktOutBuilder()
		b.pktOut.IPHeader = new(protocol.IPv4)
		pb := b.SetL4Packet(igmp)
		assert.Equal(t, igmp, pb.(*ofPacketOutBuilder).pktOut.IPHeader.Data)
	})
	t.Run("AddSetIPTOSAction", func(t *testing.T) {
		data := uint8(1)
		b := newPktOutBuilder()
		pb := b.AddSetIPTOSAction(data)
		pktOut := pb.(*ofPacketOutBuilder).pktOut

		assert.Equal(t, 1, len(pktOut.Actions))
		action := pktOut.Actions[0]

		assert.IsType(t, &ofctrl.SetFieldAction{}, action)
		setFieldAction := action.(*ofctrl.SetFieldAction)

		assert.Equal(t, openflow15.OXM_CLASS_NXM_0, int(setFieldAction.Field.Class))
		assert.Equal(t, openflow15.NXM_OF_IP_TOS, setFieldAction.Field.Field)

		assert.IsType(t, &openflow15.IpDscpField{}, setFieldAction.Field.Value)
		value := setFieldAction.Field.Value.(*openflow15.IpDscpField)
		assert.Equal(t, data<<2, value.Dscp)
	})
	t.Run("AddLoadRegMark", func(t *testing.T) {
		mark := NewRegMark(NewRegField(1, 0, 15), 0x1234)
		b := newPktOutBuilder()
		pb := b.AddLoadRegMark(mark)
		pktOut := pb.(*ofPacketOutBuilder).pktOut

		assert.Equal(t, 1, len(pktOut.Actions))
		action := pktOut.Actions[0]

		assert.IsType(t, &ofctrl.SetFieldAction{}, action)
		setFieldAction := action.(*ofctrl.SetFieldAction)

		assert.Equal(t, openflow15.OXM_CLASS_NXM_1, int(setFieldAction.Field.Class))
		assert.Equal(t, openflow15.NXM_NX_REG1, int(setFieldAction.Field.Field))

		assert.IsType(t, &openflow15.Uint32Message{}, setFieldAction.Field.Value)
		assert.IsType(t, &openflow15.Uint32Message{}, setFieldAction.Field.Mask)
		value := setFieldAction.Field.Value.(*openflow15.Uint32Message)
		mask := setFieldAction.Field.Mask.(*openflow15.Uint32Message)

		assert.Equal(t, uint32(0x1234), value.Data)
		assert.Equal(t, uint32(0xffff), mask.Data)
	})
	t.Run("AddResubmitAction", func(t *testing.T) {
		table := uint8(1)
		b := newPktOutBuilder()
		pb := b.AddResubmitAction(nil, &table)
		pktOut := pb.(*ofPacketOutBuilder).pktOut

		assert.Equal(t, 1, len(pktOut.Actions))
		action := pktOut.Actions[0]

		assert.IsType(t, &ofctrl.Resubmit{}, action)
	})
}

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
			name: "ProtocolIGMP",
			fields: fields{
				pktOut:  &ofctrl.PacketOut{},
				icmpID:  nil,
				icmpSeq: nil,
			},
			args: args{proto: ProtocolIGMP},
			want: &ofPacketOutBuilder{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						Protocol: protocol.Type_IGMP,
					},
				},
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
			name: "IPv4 IGMPv1or2",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						Protocol: protocol.Type_IGMP,
						Data: &protocol.IGMPv1or2{
							GroupAddress: net.ParseIP("1.2.3.4"),
						},
					},
				},
			},
			want: &ofctrl.PacketOut{
				IPHeader: &protocol.IPv4{
					Version:  uint8(4),
					Id:       uint16(1090),
					Protocol: protocol.Type_IGMP,
					Length:   uint16(28),
					Checksum: uint16(46751),
					Data: &protocol.IGMPv1or2{
						Checksum:     uint16(64505),
						GroupAddress: net.ParseIP("1.2.3.4"),
					},
				},
			},
		},
		{
			name: "IPv4 IGMPv3Query",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						Protocol: protocol.Type_IGMP,
						Data: &protocol.IGMPv3Query{
							GroupAddress:    net.ParseIP("1.2.3.4"),
							NumberOfSources: 1,
							SourceAddresses: []net.IP{net.ParseIP("10.10.0.1")},
						},
					},
				},
			},
			want: &ofctrl.PacketOut{
				IPHeader: &protocol.IPv4{
					Version:  uint8(4),
					Id:       uint16(1090),
					Protocol: protocol.Type_IGMP,
					Length:   uint16(36),
					Checksum: uint16(46743),
					Data: &protocol.IGMPv3Query{
						Checksum:        uint16(61933),
						GroupAddress:    net.ParseIP("1.2.3.4"),
						NumberOfSources: 1,
						SourceAddresses: []net.IP{net.ParseIP("10.10.0.1")},
					},
				},
			},
		},
		{
			name: "IPv4 IGMPv3MembershipReport",
			fields: fields{
				pktOut: &ofctrl.PacketOut{
					IPHeader: &protocol.IPv4{
						Protocol: protocol.Type_IGMP,
						Data: &protocol.IGMPv3MembershipReport{
							NumberOfGroups: 1,
							GroupRecords: []protocol.IGMPv3GroupRecord{
								{
									NumberOfSources:  1,
									MulticastAddress: net.ParseIP("224.0.0.224"),
									SourceAddresses:  []net.IP{net.ParseIP("1.2.3.4")},
								},
							},
						},
					},
				},
			},
			want: &ofctrl.PacketOut{
				IPHeader: &protocol.IPv4{
					Version:  uint8(4),
					Id:       uint16(1090),
					Protocol: protocol.Type_IGMP,
					Length:   uint16(40),
					Checksum: uint16(46739),
					Data: &protocol.IGMPv3MembershipReport{
						Checksum:       uint16(6935),
						NumberOfGroups: 1,
						GroupRecords: []protocol.IGMPv3GroupRecord{
							{
								NumberOfSources:  1,
								MulticastAddress: net.ParseIP("224.0.0.224"),
								SourceAddresses:  []net.IP{net.ParseIP("1.2.3.4")},
							},
						},
					},
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
