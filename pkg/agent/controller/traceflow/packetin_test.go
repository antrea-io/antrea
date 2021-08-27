// Copyright 2020 Antrea Authors
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

package traceflow

import (
	"net"
	"reflect"
	"testing"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/agent/openflow"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

func Test_getNetworkPolicyObservation(t *testing.T) {
	type args struct {
		tableID uint8
		ingress bool
	}
	tests := []struct {
		name string
		args args
		want *crdv1alpha1.Observation
	}{
		{
			name: "ingress metric drop",
			args: args{
				tableID: uint8(openflow.IngressMetricTable),
				ingress: true,
			},
			want: &crdv1alpha1.Observation{
				Component:     crdv1alpha1.ComponentNetworkPolicy,
				ComponentInfo: "IngressMetric",
				Action:        crdv1alpha1.ActionDropped,
			},
		},
		{
			name: "ingress accept",
			args: args{
				tableID: uint8(openflow.L2ForwardingOutTable),
				ingress: true,
			},
			want: &crdv1alpha1.Observation{
				Component:     crdv1alpha1.ComponentNetworkPolicy,
				ComponentInfo: "IngressRule",
				Action:        crdv1alpha1.ActionForwarded,
			},
		},
		{
			name: "egress default drop",
			args: args{
				tableID: uint8(openflow.EgressDefaultTable),
				ingress: false,
			},
			want: &crdv1alpha1.Observation{
				Component:     crdv1alpha1.ComponentNetworkPolicy,
				ComponentInfo: "EgressDefaultRule",
				Action:        crdv1alpha1.ActionDropped,
			},
		},
		{
			name: "egress accept",
			args: args{
				tableID: uint8(openflow.L2ForwardingOutTable),
				ingress: false,
			},
			want: &crdv1alpha1.Observation{
				Component:     crdv1alpha1.ComponentNetworkPolicy,
				ComponentInfo: "EgressRule",
				Action:        crdv1alpha1.ActionForwarded,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getNetworkPolicyObservation(tt.args.tableID, tt.args.ingress); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getNetworkPolicyObservation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCapturedPacket(t *testing.T) {
	srcIPv4 := net.ParseIP("10.1.1.11")
	dstIPv4 := net.ParseIP("10.1.1.12")
	srcIPv6 := net.ParseIP("fd12:ab:34:a001::11")
	dstIPv6 := net.ParseIP("fd12:ab:34:a001::12")

	tcpPktIn := protocol.IPv4{Length: 1000, Flags: 1, TTL: 64, NWSrc: srcIPv4, NWDst: dstIPv4, Protocol: protocol.Type_TCP}
	tcp := protocol.TCP{PortSrc: 1080, PortDst: 80, SeqNum: 1234, Code: 2}
	bytes, _ := tcp.MarshalBinary()
	bf := new(util.Buffer)
	bf.UnmarshalBinary(bytes)
	tcpPktIn.Data = bf
	tcpPktCap := crdv1alpha1.Packet{
		SrcIP: tcpPktIn.NWSrc.String(), DstIP: tcpPktIn.NWDst.String(), Length: tcpPktIn.Length,
		IPHeader: crdv1alpha1.IPHeader{Protocol: int32(tcpPktIn.Protocol), TTL: int32(tcpPktIn.TTL), Flags: int32(tcpPktIn.Flags)},
		TransportHeader: crdv1alpha1.TransportHeader{
			TCP: &crdv1alpha1.TCPHeader{SrcPort: int32(tcp.PortSrc), DstPort: int32(tcp.PortDst), Flags: int32(tcp.Code)},
		},
	}

	udpPktIn := protocol.IPv4{Length: 50, Flags: 0, TTL: 128, NWSrc: srcIPv4, NWDst: dstIPv4, Protocol: protocol.Type_UDP}
	udp := protocol.UDP{PortSrc: 1080, PortDst: 80}
	udpPktIn.Data = &udp
	udpPktCap := crdv1alpha1.Packet{
		SrcIP: udpPktIn.NWSrc.String(), DstIP: udpPktIn.NWDst.String(), Length: udpPktIn.Length,
		IPHeader: crdv1alpha1.IPHeader{Protocol: int32(udpPktIn.Protocol), TTL: int32(udpPktIn.TTL), Flags: int32(udpPktIn.Flags)},
		TransportHeader: crdv1alpha1.TransportHeader{
			UDP: &crdv1alpha1.UDPHeader{SrcPort: int32(udp.PortSrc), DstPort: int32(udp.PortDst)},
		},
	}

	icmpv6PktIn := protocol.IPv6{Length: 960, HopLimit: 8, NWSrc: srcIPv6, NWDst: dstIPv6, NextHeader: protocol.Type_IPv6ICMP}
	icmpEchoReq := []uint8{0, 1, 0, 123}
	icmp := protocol.ICMP{Type: 128, Code: 0, Data: icmpEchoReq}
	icmpv6PktIn.Data = &icmp
	nextHdr := int32(icmpv6PktIn.NextHeader)
	icmpv6PktCap := crdv1alpha1.Packet{
		SrcIP: icmpv6PktIn.NWSrc.String(), DstIP: icmpv6PktIn.NWDst.String(), Length: icmpv6PktIn.Length + 40,
		IPv6Header:      &crdv1alpha1.IPv6Header{NextHeader: &nextHdr, HopLimit: int32(icmpv6PktIn.HopLimit)},
		TransportHeader: crdv1alpha1.TransportHeader{ICMP: &crdv1alpha1.ICMPEchoRequestHeader{ID: 1, Sequence: 123}},
	}

	tests := []struct {
		name      string
		pktInData util.Message
		pktCap    *crdv1alpha1.Packet
		isIPv6    bool
	}{
		{"tcp", &tcpPktIn, &tcpPktCap, false},
		{"udp", &udpPktIn, &udpPktCap, false},
		{"icmpv6", &icmpv6PktIn, &icmpv6PktCap, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ethType := uint16(protocol.IPv4_MSG)
			if tt.isIPv6 {
				ethType = uint16(protocol.IPv6_MSG)
			}
			pktIn := ofctrl.PacketIn{Data: protocol.Ethernet{Ethertype: ethType, Data: tt.pktInData}}
			packet := parseCapturedPacket(&pktIn)
			assert.True(t, reflect.DeepEqual(packet, tt.pktCap), "parsed packet does not match the expected")
		})
	}
}
