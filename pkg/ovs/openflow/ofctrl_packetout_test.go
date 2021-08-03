package openflow

import (
	"net"
	"reflect"
	"testing"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/ofnet/ofctrl"
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
					Checksum: 45409,
				},
				TCPHeader: &protocol.TCP{
					PortSrc:  10000,
					PortDst:  10001,
					HdrLen:   5,
					Checksum: 63286,
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
					Checksum: 45025,
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
					Checksum: 26538,
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
			b := &ofPacketOutBuilder{
				pktOut:  tt.fields.pktOut,
				icmpID:  tt.fields.icmpID,
				icmpSeq: tt.fields.icmpSeq,
			}
			got := b.Done()
			if got == nil {
				if tt.want != nil {
					t.Errorf("Done() = %v, want %v", got, tt.want)
				}
				return
			}
			if got.IPHeader != nil {
				got.IPHeader.Id = 0
			}
			if got.TCPHeader != nil {
				got.TCPHeader.SeqNum = 0
				got.TCPHeader.AckNum = 0
			}
			if !reflect.DeepEqual(got.ICMPHeader, tt.want.ICMPHeader) {
				t.Errorf("Done() = %v, want %v", got.ICMPHeader, tt.want.ICMPHeader)
			}
			if !reflect.DeepEqual(got.TCPHeader, tt.want.TCPHeader) {
				t.Errorf("Done() = %v, want %v", got.TCPHeader, tt.want.TCPHeader)
			}
			if !reflect.DeepEqual(got.UDPHeader, tt.want.UDPHeader) {
				t.Errorf("Done() = %v, want %v", got.UDPHeader, tt.want.UDPHeader)
			}
			if !reflect.DeepEqual(got.IPHeader, tt.want.IPHeader) {
				t.Errorf("Done() = %v, want %v", got.IPHeader, tt.want.IPHeader)
			}
			if !reflect.DeepEqual(got.IPv6Header, tt.want.IPv6Header) {
				t.Errorf("Done() = %v, want %v", got.IPv6Header, tt.want.IPv6Header)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Done() = %v, want %v", got, tt.want)
			}
		})
	}
}
