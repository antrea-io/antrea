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
	"encoding/binary"
	"net"
	"reflect"
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/pointer"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	queriertest "antrea.io/antrea/pkg/querier/testing"
)

var (
	egressName = "dummyEgress"
	egressIP   = "192.168.100.100"
	egressNode = "fakeEgressNode"
)

func prepareMockTables() {
	openflow.InitMockTables(
		map[*openflow.Table]uint8{
			openflow.AntreaPolicyEgressRuleTable:  uint8(5),
			openflow.EgressRuleTable:              uint8(6),
			openflow.EgressDefaultTable:           uint8(7),
			openflow.EgressMetricTable:            uint8(8),
			openflow.AntreaPolicyIngressRuleTable: uint8(12),
			openflow.IngressRuleTable:             uint8(13),
			openflow.IngressDefaultTable:          uint8(14),
			openflow.IngressMetricTable:           uint8(15),
			openflow.OutputTable:                  uint8(17),
		})
}

func Test_getNetworkPolicyObservation(t *testing.T) {
	prepareMockTables()

	type args struct {
		tableID uint8
		ingress bool
	}
	tests := []struct {
		name string
		args args
		want *crdv1beta1.Observation
	}{
		{
			name: "ingress metric drop",
			args: args{
				tableID: openflow.IngressMetricTable.GetID(),
				ingress: true,
			},
			want: &crdv1beta1.Observation{
				Component:     crdv1beta1.ComponentNetworkPolicy,
				ComponentInfo: "IngressMetric",
				Action:        crdv1beta1.ActionDropped,
			},
		},
		{
			name: "ingress accept",
			args: args{
				tableID: openflow.OutputTable.GetID(),
				ingress: true,
			},
			want: &crdv1beta1.Observation{
				Component:     crdv1beta1.ComponentNetworkPolicy,
				ComponentInfo: "IngressRule",
				Action:        crdv1beta1.ActionForwarded,
			},
		},
		{
			name: "egress default drop",
			args: args{
				tableID: openflow.EgressDefaultTable.GetID(),
				ingress: false,
			},
			want: &crdv1beta1.Observation{
				Component:     crdv1beta1.ComponentNetworkPolicy,
				ComponentInfo: "EgressDefaultRule",
				Action:        crdv1beta1.ActionDropped,
			},
		},
		{
			name: "egress accept",
			args: args{
				tableID: openflow.OutputTable.GetID(),
				ingress: false,
			},
			want: &crdv1beta1.Observation{
				Component:     crdv1beta1.ComponentNetworkPolicy,
				ComponentInfo: "EgressRule",
				Action:        crdv1beta1.ActionForwarded,
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
	tcpPktCap := crdv1beta1.Packet{
		SrcIP: tcpPktIn.NWSrc.String(), DstIP: tcpPktIn.NWDst.String(), Length: int32(tcpPktIn.Length),
		IPHeader: &crdv1beta1.IPHeader{Protocol: int32(tcpPktIn.Protocol), TTL: int32(tcpPktIn.TTL), Flags: int32(tcpPktIn.Flags)},
		TransportHeader: crdv1beta1.TransportHeader{
			TCP: &crdv1beta1.TCPHeader{SrcPort: int32(tcp.PortSrc), DstPort: int32(tcp.PortDst), Flags: pointer.Int32(int32(tcp.Code))},
		},
	}

	udpPktIn := protocol.IPv4{Length: 50, Flags: 0, TTL: 128, NWSrc: srcIPv4, NWDst: dstIPv4, Protocol: protocol.Type_UDP}
	udp := protocol.UDP{PortSrc: 1080, PortDst: 80}
	udpPktIn.Data = &udp
	udpPktCap := crdv1beta1.Packet{
		SrcIP: udpPktIn.NWSrc.String(), DstIP: udpPktIn.NWDst.String(), Length: int32(udpPktIn.Length),
		IPHeader: &crdv1beta1.IPHeader{Protocol: int32(udpPktIn.Protocol), TTL: int32(udpPktIn.TTL), Flags: int32(udpPktIn.Flags)},
		TransportHeader: crdv1beta1.TransportHeader{
			UDP: &crdv1beta1.UDPHeader{SrcPort: int32(udp.PortSrc), DstPort: int32(udp.PortDst)},
		},
	}

	icmpv6PktIn := protocol.IPv6{Length: 960, HopLimit: 8, NWSrc: srcIPv6, NWDst: dstIPv6, NextHeader: protocol.Type_IPv6ICMP}
	icmpEchoReq := []uint8{0, 1, 0, 123}
	icmp := protocol.ICMP{Type: 128, Code: 0, Data: icmpEchoReq}
	icmpv6PktIn.Data = &icmp
	nextHdr := int32(icmpv6PktIn.NextHeader)
	icmpv6PktCap := crdv1beta1.Packet{
		SrcIP: icmpv6PktIn.NWSrc.String(), DstIP: icmpv6PktIn.NWDst.String(), Length: int32(icmpv6PktIn.Length) + 40,
		IPv6Header:      &crdv1beta1.IPv6Header{NextHeader: &nextHdr, HopLimit: int32(icmpv6PktIn.HopLimit)},
		TransportHeader: crdv1beta1.TransportHeader{ICMP: &crdv1beta1.ICMPEchoRequestHeader{ID: 1, Sequence: 123}},
	}

	tests := []struct {
		name      string
		pktInData util.Message
		pktCap    *crdv1beta1.Packet
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
			etherPkt := protocol.NewEthernet()
			etherPkt.Ethertype = ethType
			etherPkt.Data = tt.pktInData
			pktBytes, _ := etherPkt.MarshalBinary()
			pktIn := ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{
					Data: util.NewBuffer(pktBytes),
				},
			}
			packet := parseCapturedPacket(&pktIn)
			assert.True(t, reflect.DeepEqual(packet, tt.pktCap), "parsed packet does not match the expected")
		})
	}
}

func getTestPacketBytes(dstIP string) []byte {
	ipPacket := &protocol.IPv4{
		Version:  0x4,
		IHL:      5,
		Protocol: uint8(8),
		DSCP:     1,
		Length:   20,
		NWSrc:    net.IP(pod1IPv4),
		NWDst:    net.IP(dstIP),
	}
	ethernetPkt := protocol.NewEthernet()
	ethernetPkt.HWSrc = pod1MAC
	ethernetPkt.Ethertype = protocol.IPv4_MSG
	ethernetPkt.Data = ipPacket
	pktBytes, _ := ethernetPkt.MarshalBinary()
	return pktBytes
}

func TestParsePacketIn(t *testing.T) {
	xreg0 := make([]byte, 8)
	binary.BigEndian.PutUint32(xreg0[0:4], openflow.RemoteSNATRegMark.GetValue()<<openflow.RemoteSNATRegMark.GetField().GetRange().Offset()) // RemoteSNATRegMark in 32bit reg0
	binary.BigEndian.PutUint32(xreg0[4:8], 2)                                                                                                // outputPort in 32bit reg1
	matchOutPort := &openflow15.MatchField{
		Class: openflow15.OXM_CLASS_PACKET_REGS,
		Field: openflow15.NXM_NX_REG0,
		Value: &openflow15.ByteArrayField{
			Data: xreg0,
		},
	}
	matchPktMark := &openflow15.MatchField{
		Class: openflow15.OXM_CLASS_NXM_1,
		Field: openflow15.NXM_NX_PKT_MARK,
		Value: &openflow15.Uint32Message{
			Data: 1,
		},
	}
	matchTunDst := openflow15.NewTunnelIpv4DstField(net.ParseIP(egressIP), nil)

	conjData := make([]byte, 8)
	binary.BigEndian.PutUint32(conjData[0:4], uint32(1))
	binary.BigEndian.PutUint32(conjData[4:8], uint32(2))
	matchTFEgressConjID := &openflow15.MatchField{
		Class: openflow15.OXM_CLASS_PACKET_REGS,
		Field: uint8(openflow.TFEgressConjIDField.GetRegID() / 2),
		Value: &openflow15.ByteArrayField{
			Data: conjData,
		},
	}
	matchTFIngressConjID := &openflow15.MatchField{
		Class: openflow15.OXM_CLASS_PACKET_REGS,
		Field: uint8(openflow.TFIngressConjIDField.GetRegID() / 2),
		Value: &openflow15.ByteArrayField{
			Data: conjData,
		},
	}
	matchAPConjID := &openflow15.MatchField{
		Class: openflow15.OXM_CLASS_PACKET_REGS,
		Field: uint8(openflow.APConjIDField.GetRegID() / 2),
		Value: &openflow15.ByteArrayField{
			Data: conjData,
		},
	}

	pktBytesPodToIP := getTestPacketBytes(dstIPv4)
	pktBytesPodToPod := getTestPacketBytes(pod2IPv4)

	tests := []struct {
		name               string
		networkConfig      *config.NetworkConfig
		nodeConfig         *config.NodeConfig
		tfState            *traceflowState
		pktIn              *ofctrl.PacketIn
		expectedCalls      func(*queriertest.MockAgentNetworkPolicyInfoQuerier, *queriertest.MockEgressQuerier)
		expectedTf         *crdv1beta1.Traceflow
		expectedNodeResult *crdv1beta1.NodeResult
	}{
		{
			name: "packet at source Node for local Egress",
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: 0,
			},
			nodeConfig: &config.NodeConfig{
				TunnelOFPort: 1,
				GatewayConfig: &config.GatewayConfig{
					OFPort: 2,
				},
			},
			tfState: &traceflowState{
				name:     "traceflow-pod-to-ipv4",
				tag:      1,
				isSender: true,
			},
			pktIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{
					TableId: openflow.OutputTable.GetID(),
					Match: openflow15.Match{
						Fields: []openflow15.MatchField{*matchOutPort, *matchPktMark},
					},
					Data: util.NewBuffer(pktBytesPodToIP),
				},
			},
			expectedCalls: func(npQuerierq *queriertest.MockAgentNetworkPolicyInfoQuerier, egressQuerier *queriertest.MockEgressQuerier) {
				egressQuerier.EXPECT().GetEgress(pod1.Namespace, pod1.Name).Return(egressName, egressIP, egressNode, nil)
			},
			expectedTf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: "traceflow-pod-to-ipv4",
				},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						IP: dstIPv4,
					},
				},
				Status: crdv1beta1.TraceflowStatus{
					Phase:        crdv1beta1.Running,
					DataplaneTag: 1,
				},
			},
			expectedNodeResult: &crdv1beta1.NodeResult{
				Observations: []crdv1beta1.Observation{
					{
						Component: crdv1beta1.ComponentSpoofGuard,
						Action:    crdv1beta1.ActionForwarded,
					},
					{
						Component:  crdv1beta1.ComponentEgress,
						Action:     crdv1beta1.ActionMarkedForSNAT,
						Egress:     egressName,
						EgressIP:   egressIP,
						EgressNode: egressNode,
					},
					{
						Component:     crdv1beta1.ComponentForwarding,
						ComponentInfo: openflow.OutputTable.GetName(),
						Action:        crdv1beta1.ActionForwardedOutOfOverlay,
					},
				},
			},
		},
		{
			name: "packet at source Node for remote Egress",
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: 0,
			},
			nodeConfig: &config.NodeConfig{
				TunnelOFPort: 2,
				GatewayConfig: &config.GatewayConfig{
					OFPort: 1,
				},
			},
			tfState: &traceflowState{
				name:     "traceflow-pod-to-ipv4",
				tag:      1,
				isSender: true,
			},
			pktIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{
					TableId: openflow.OutputTable.GetID(),
					Match: openflow15.Match{
						Fields: []openflow15.MatchField{*matchTunDst, *matchOutPort},
					},
					Data: util.NewBuffer(pktBytesPodToIP),
				},
			},
			expectedCalls: func(npQuerierq *queriertest.MockAgentNetworkPolicyInfoQuerier, egressQuerier *queriertest.MockEgressQuerier) {
				egressQuerier.EXPECT().GetEgress(pod1.Namespace, pod1.Name).Return(egressName, egressIP, egressNode, nil)
			},
			expectedTf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: "traceflow-pod-to-ipv4",
				},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						IP: dstIPv4,
					},
				},
				Status: crdv1beta1.TraceflowStatus{
					Phase:        crdv1beta1.Running,
					DataplaneTag: 1,
				},
			},
			expectedNodeResult: &crdv1beta1.NodeResult{
				Observations: []crdv1beta1.Observation{
					{
						Component: crdv1beta1.ComponentSpoofGuard,
						Action:    crdv1beta1.ActionForwarded,
					},
					{
						Component:  crdv1beta1.ComponentEgress,
						Action:     crdv1beta1.ActionForwardedToEgressNode,
						Egress:     egressName,
						EgressIP:   egressIP,
						EgressNode: egressNode,
					},
					{
						Component:     crdv1beta1.ComponentForwarding,
						ComponentInfo: openflow.OutputTable.GetName(),
						Action:        crdv1beta1.ActionForwarded,
						TunnelDstIP:   egressIP,
					},
				},
			},
		},
		{
			name: "packet at remote Node for remote Egress",
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: 0,
			},
			nodeConfig: &config.NodeConfig{
				TunnelOFPort: 1,
				GatewayConfig: &config.GatewayConfig{
					OFPort: 2,
				},
			},
			tfState: &traceflowState{
				name: "traceflow-pod-to-ipv4",
				tag:  1,
			},
			pktIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{
					TableId: openflow.OutputTable.GetID(),
					Match: openflow15.Match{
						Fields: []openflow15.MatchField{*matchOutPort, *matchTunDst, *matchPktMark},
					},
					Data: util.NewBuffer(pktBytesPodToIP),
				},
			},
			expectedCalls: func(npQuerierq *queriertest.MockAgentNetworkPolicyInfoQuerier, egressQuerier *queriertest.MockEgressQuerier) {
				egressQuerier.EXPECT().GetEgressIPByMark(uint32(1)).Return(egressIP, nil)
			},
			expectedTf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: "traceflow-pod-to-ipv4",
				},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						IP: dstIPv4,
					},
				},
				Status: crdv1beta1.TraceflowStatus{
					Phase:        crdv1beta1.Running,
					DataplaneTag: 1,
				},
			},
			expectedNodeResult: &crdv1beta1.NodeResult{
				Observations: []crdv1beta1.Observation{
					{
						Component: crdv1beta1.ComponentForwarding,
						Action:    crdv1beta1.ActionReceived,
					},
					{
						Component: crdv1beta1.ComponentEgress,
						Action:    crdv1beta1.ActionMarkedForSNAT,
						EgressIP:  egressIP,
					},
					{
						Component:     crdv1beta1.ComponentForwarding,
						ComponentInfo: openflow.OutputTable.GetName(),
						Action:        crdv1beta1.ActionForwardedOutOfOverlay,
					},
				},
			},
		},
		{
			name:       "packet at source Node forwarded by acnp egress rule",
			nodeConfig: &config.NodeConfig{},
			tfState: &traceflowState{
				name:     "traceflow-pod-to-pod",
				tag:      1,
				isSender: true,
			},
			pktIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{
					TableId: openflow.EgressRuleTable.GetID(),
					Match: openflow15.Match{
						Fields: []openflow15.MatchField{*matchTFEgressConjID},
					},
					Data: util.NewBuffer(pktBytesPodToPod),
				},
			},
			expectedCalls: func(npQuerier *queriertest.MockAgentNetworkPolicyInfoQuerier, egressQuerier *queriertest.MockEgressQuerier) {
				npQuerier.EXPECT().GetNetworkPolicyByRuleFlowID(uint32(2)).Return(
					&v1beta2.NetworkPolicyReference{
						Type: v1beta2.AntreaClusterNetworkPolicy,
						Name: "acnp-1",
					},
				)
				npQuerier.EXPECT().GetRuleByFlowID(uint32(2)).Return(
					&types.PolicyRule{
						Name: "egress-allow-rule",
					},
				)
			},
			expectedTf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: "traceflow-pod-to-pod",
				},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
				},
				Status: crdv1beta1.TraceflowStatus{
					Phase:        crdv1beta1.Running,
					DataplaneTag: 1,
				},
			},
			expectedNodeResult: &crdv1beta1.NodeResult{
				Observations: []crdv1beta1.Observation{
					{
						Component: crdv1beta1.ComponentSpoofGuard,
						Action:    crdv1beta1.ActionForwarded,
					},
					{
						Component:         crdv1beta1.ComponentNetworkPolicy,
						ComponentInfo:     openflow.EgressRuleTable.GetName(),
						Action:            crdv1beta1.ActionForwarded,
						NetworkPolicy:     string(v1beta2.AntreaClusterNetworkPolicy) + ":acnp-1",
						NetworkPolicyRule: "egress-allow-rule",
					},
				},
			},
		},
		{
			name:       "packet at destination Node forwarded by acnp ingress rule",
			nodeConfig: &config.NodeConfig{},
			tfState: &traceflowState{
				name: "traceflow-pod-to-pod",
				tag:  1,
			},
			pktIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{
					TableId: openflow.IngressRuleTable.GetID(),
					Match: openflow15.Match{
						Fields: []openflow15.MatchField{*matchTFIngressConjID},
					},
					Data: util.NewBuffer(pktBytesPodToPod),
				},
			},
			expectedCalls: func(npQuerier *queriertest.MockAgentNetworkPolicyInfoQuerier, egressQuerier *queriertest.MockEgressQuerier) {
				npQuerier.EXPECT().GetNetworkPolicyByRuleFlowID(uint32(1)).Return(
					&v1beta2.NetworkPolicyReference{
						Type: v1beta2.AntreaClusterNetworkPolicy,
						Name: "acnp-2",
					},
				)
				npQuerier.EXPECT().GetRuleByFlowID(uint32(1)).Return(
					&types.PolicyRule{
						Name: "ingress-allow-rule",
					},
				)
			},
			expectedTf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: "traceflow-pod-to-pod",
				},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
				},
				Status: crdv1beta1.TraceflowStatus{
					Phase:        crdv1beta1.Running,
					DataplaneTag: 1,
				},
			},
			expectedNodeResult: &crdv1beta1.NodeResult{
				Observations: []crdv1beta1.Observation{
					{
						Component: crdv1beta1.ComponentForwarding,
						Action:    crdv1beta1.ActionReceived,
					},
					{
						Component:         crdv1beta1.ComponentNetworkPolicy,
						ComponentInfo:     openflow.IngressRuleTable.GetName(),
						Action:            crdv1beta1.ActionForwarded,
						NetworkPolicy:     string(v1beta2.AntreaClusterNetworkPolicy) + ":acnp-2",
						NetworkPolicyRule: "ingress-allow-rule",
					},
				},
			},
		},
		{
			name:       "packet at source Node dropped by acnp egress rule",
			nodeConfig: &config.NodeConfig{},
			tfState: &traceflowState{
				name:     "traceflow-pod-to-pod",
				tag:      1,
				isSender: true,
			},
			pktIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{
					TableId: openflow.EgressMetricTable.GetID(),
					Match: openflow15.Match{
						Fields: []openflow15.MatchField{*matchAPConjID},
					},
					Data: util.NewBuffer(pktBytesPodToPod),
				},
			},
			expectedCalls: func(npQuerier *queriertest.MockAgentNetworkPolicyInfoQuerier, egressQuerier *queriertest.MockEgressQuerier) {
				npQuerier.EXPECT().GetRuleByFlowID(uint32(2)).Return(
					&types.PolicyRule{
						Name: "egress-drop-rule",
						PolicyRef: &v1beta2.NetworkPolicyReference{
							Type: v1beta2.AntreaClusterNetworkPolicy,
							Name: "acnp-3",
						},
					},
				)
			},
			expectedTf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: "traceflow-pod-to-pod",
				},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
				},
				Status: crdv1beta1.TraceflowStatus{
					Phase:        crdv1beta1.Running,
					DataplaneTag: 1,
				},
			},
			expectedNodeResult: &crdv1beta1.NodeResult{
				Observations: []crdv1beta1.Observation{
					{
						Component: crdv1beta1.ComponentSpoofGuard,
						Action:    crdv1beta1.ActionForwarded,
					},
					{
						Component:         crdv1beta1.ComponentNetworkPolicy,
						ComponentInfo:     openflow.EgressMetricTable.GetName(),
						Action:            crdv1beta1.ActionDropped,
						NetworkPolicy:     string(v1beta2.AntreaClusterNetworkPolicy) + ":acnp-3",
						NetworkPolicyRule: "egress-drop-rule",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tfc := newFakeTraceflowController(t, []runtime.Object{tt.expectedTf}, tt.networkConfig, tt.nodeConfig)
			stopCh := make(chan struct{})
			defer close(stopCh)
			tfc.crdInformerFactory.Start(stopCh)
			tfc.crdInformerFactory.WaitForCacheSync(stopCh)
			tfc.runningTraceflows[tt.expectedTf.Status.DataplaneTag] = tt.tfState
			tt.expectedCalls(tfc.networkPolicyQuerier, tfc.egressQuerier)

			tf, nodeResult, _, err := tfc.parsePacketIn(tt.pktIn)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedNodeResult.Observations, nodeResult.Observations)
			assert.Equal(t, tt.expectedTf, tf)
		})
	}
}

func TestParsePacketInLiveDuplicates(t *testing.T) {
	networkConfig := &config.NetworkConfig{
		TrafficEncapMode: 0,
	}
	nodeConfig := &config.NodeConfig{
		TunnelOFPort: 1,
		GatewayConfig: &config.GatewayConfig{
			OFPort: 2,
		},
	}
	tfState := &traceflowState{
		name:           "traceflow-pod-to-ipv4",
		tag:            1,
		isSender:       true,
		liveTraffic:    true,
		receivedPacket: true, // assume we have already received a packet
	}
	pktIn := &ofctrl.PacketIn{
		PacketIn: &openflow15.PacketIn{
			TableId: openflow.OutputTable.GetID(),
			Data:    util.NewBuffer(getTestPacketBytes(dstIPv4)),
		},
	}

	tfc := newFakeTraceflowController(t, nil, networkConfig, nodeConfig)
	tfc.runningTraceflows[tfState.tag] = tfState

	_, _, _, err := tfc.parsePacketIn(pktIn)
	assert.ErrorIs(t, err, skipTraceflowUpdateErr)
}
