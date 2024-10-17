// Copyright 2024 Antrea Authors
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

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featurePacketCapture struct {
	cookieAllocator cookie.Allocator
	cachedFlows     *flowCategoryCache
	ipProtocols     []binding.Protocol
	networkConfig   *config.NetworkConfig
	enableProxy     bool
	tunnelPort      uint32
	gatewayPort     uint32
	gatewayIPs      map[binding.Protocol]net.IP
}

func (f *featurePacketCapture) getFeatureName() string {
	return "PacketCapture"
}

func newFeaturePacketCapture(cookieAllocator cookie.Allocator,
	ipProtocols []binding.Protocol,
	enableProxy bool,
	networkConfig *config.NetworkConfig,
	nodeConfig *config.NodeConfig) *featurePacketCapture {
	gatewayIPs := make(map[binding.Protocol]net.IP)
	for _, ipProtocol := range ipProtocols {
		if ipProtocol == binding.ProtocolIP {
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv4
		} else if ipProtocol == binding.ProtocolIPv6 {
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv6
		}

	}
	return &featurePacketCapture{
		cachedFlows:     newFlowCategoryCache(),
		cookieAllocator: cookieAllocator,
		ipProtocols:     ipProtocols,
		networkConfig:   networkConfig,
		enableProxy:     enableProxy,
		tunnelPort:      nodeConfig.TunnelOFPort,
		gatewayPort:     nodeConfig.GatewayConfig.OFPort,
		gatewayIPs:      gatewayIPs,
	}
}

func (f *featurePacketCapture) initFlows() []*openflow15.FlowMod {
	return []*openflow15.FlowMod{}
}

func (f *featurePacketCapture) replayFlows() []*openflow15.FlowMod {
	return []*openflow15.FlowMod{}
}

func (f *featurePacketCapture) initGroups() []binding.OFEntry {
	return nil
}

func (f *featurePacketCapture) replayGroups() []binding.OFEntry {
	return nil
}

func (f *featurePacketCapture) replayMeters() []binding.OFEntry {
	return nil
}

// genFlows generates flows for packet capture. dataplaneTag is used as a mark for the target flow.
func (f *featurePacketCapture) genFlows(dataplaneTag uint8,
	ovsMetersAreSupported,
	receiverOnly bool,
	packet *binding.Packet,
	endpointPackets []binding.Packet,
	ofPort uint32,
	timeout uint16) []binding.Flow {
	cookieID := f.cookieAllocator.Request(cookie.PacketCapture).Raw()
	var flows []binding.Flow
	tag := uint32(dataplaneTag)
	var flowBuilder binding.FlowBuilder
	if !receiverOnly {
		// if not receiverOnly, ofPort is inPort
		if endpointPackets == nil {
			flowBuilder = ConntrackStateTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchInPort(ofPort).
				MatchCTStateTrk(true).
				Action().LoadToRegField(PacketCaptureMark, tag).
				SetHardTimeout(timeout).
				Action().GotoStage(stagePreRouting)
			if packet.DestinationIP != nil {
				flowBuilder = flowBuilder.MatchDstIP(packet.DestinationIP)
			}
		} else {
			// handle pod -> svc case:
			// generate flows to endpoints.
			for _, epPacket := range endpointPackets {
				tmpFlowBuilder := ConntrackStateTable.ofTable.BuildFlow(priorityHigh).
					Cookie(cookieID).
					MatchInPort(ofPort).
					MatchCTStateTrk(true).
					Action().LoadRegMark(RewriteMACRegMark).
					Action().LoadToRegField(PacketCaptureMark, tag).
					SetHardTimeout(timeout).
					Action().GotoStage(stageEgressSecurity)
				tmpFlowBuilder.MatchDstIP(epPacket.DestinationIP)
				flow := matchTransportHeader(packet, tmpFlowBuilder, endpointPackets).Done()
				flows = append(flows, flow)
			}

			// capture the first tracked packet for svc.
			for _, ipProtocol := range f.ipProtocols {
				tmpFlowBuilder := ConntrackStateTable.ofTable.BuildFlow(priorityHigh).
					Cookie(cookieID).
					MatchInPort(ofPort).
					MatchProtocol(ipProtocol).
					MatchCTStateNew(true).
					MatchCTStateTrk(true).
					Action().LoadRegMark(RewriteMACRegMark).
					Action().LoadToRegField(PacketCaptureMark, tag).
					SetHardTimeout(timeout).
					Action().GotoStage(stagePreRouting)
				tmpFlowBuilder.MatchDstIP(packet.DestinationIP)
				tmpFlowBuilder = matchTransportHeader(packet, tmpFlowBuilder, nil)
				flows = append(flows, tmpFlowBuilder.Done())
			}

		}
	} else {
		flowBuilder = L2ForwardingCalcTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchCTStateTrk(true).
			MatchDstMAC(packet.DestinationMAC).
			Action().LoadToRegField(TargetOFPortField, ofPort).
			Action().LoadRegMark(OutputToOFPortRegMark).
			Action().LoadToRegField(PacketCaptureMark, tag).
			SetHardTimeout(timeout).
			Action().GotoStage(stageIngressSecurity)
		if packet.SourceIP != nil {
			flowBuilder = flowBuilder.MatchSrcIP(packet.SourceIP)
		}
	}

	if flowBuilder != nil {
		flow := matchTransportHeader(packet, flowBuilder, nil).Done()
		flows = append(flows, flow)
	}

	output := func(fb binding.FlowBuilder) binding.FlowBuilder {
		return fb.Action().OutputToRegField(TargetOFPortField)
	}

	sendToController := func(fb binding.FlowBuilder) binding.FlowBuilder {
		if ovsMetersAreSupported {
			fb = fb.Action().Meter(PacketInMeterIDTF)
		}
		fb = fb.Action().SendToController([]byte{uint8(PacketInCategoryPacketCapture)}, false)
		return fb
	}

	// This generates PacketCapture specific flows that outputs capture
	// non-hairpin packets to OVS port and Antrea Agent after
	// L2 forwarding calculation.
	for _, ipProtocol := range f.ipProtocols {
		if f.networkConfig.TrafficEncapMode.SupportsEncap() {
			// SendToController and Output if output port is tunnel port.
			fb := OutputTable.ofTable.BuildFlow(priorityNormal+3).
				Cookie(cookieID).
				MatchRegFieldWithValue(TargetOFPortField, f.tunnelPort).
				MatchProtocol(ipProtocol).
				MatchRegMark(OutputToOFPortRegMark).
				MatchRegFieldWithValue(PacketCaptureMark, tag).
				SetHardTimeout(timeout).
				Action().OutputToRegField(TargetOFPortField)
			fb = sendToController(fb)
			flows = append(flows, fb.Done())
			// For injected packets, only SendToController if output port is local gateway. In encapMode, a PacketCapture
			// packet going out of the gateway port (i.e. exiting the overlay) essentially means that the PacketCapture
			// request is complete.
			fb = OutputTable.ofTable.BuildFlow(priorityNormal+2).
				Cookie(cookieID).
				MatchRegFieldWithValue(TargetOFPortField, f.gatewayPort).
				MatchProtocol(ipProtocol).
				MatchRegMark(OutputToOFPortRegMark).
				MatchRegFieldWithValue(PacketCaptureMark, tag).
				SetHardTimeout(timeout)
			fb = sendToController(fb)
			fb = output(fb)
			flows = append(flows, fb.Done())
		} else {
			// SendToController and Output if output port is local gateway. Unlike in encapMode, inter-Node Pod-to-Pod
			// traffic is expected to go out of the gateway port on the way to its destination.
			fb := OutputTable.ofTable.BuildFlow(priorityNormal+2).
				Cookie(cookieID).
				MatchRegFieldWithValue(TargetOFPortField, f.gatewayPort).
				MatchProtocol(ipProtocol).
				MatchRegMark(OutputToOFPortRegMark).
				MatchRegFieldWithValue(PacketCaptureMark, tag).
				SetHardTimeout(timeout).
				Action().OutputToRegField(TargetOFPortField)
			fb = sendToController(fb)
			flows = append(flows, fb.Done())
		}

		gatewayIP := f.gatewayIPs[ipProtocol]
		if gatewayIP != nil {
			fb := OutputTable.ofTable.BuildFlow(priorityNormal+3).
				Cookie(cookieID).
				MatchRegFieldWithValue(TargetOFPortField, f.gatewayPort).
				MatchProtocol(ipProtocol).
				MatchDstIP(gatewayIP).
				MatchRegMark(OutputToOFPortRegMark).
				MatchRegFieldWithValue(PacketCaptureMark, tag).
				SetHardTimeout(timeout)
			fb = sendToController(fb)
			fb = output(fb)
			flows = append(flows, fb.Done())
		}

		fb := OutputTable.ofTable.BuildFlow(priorityNormal+2).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchRegMark(OutputToOFPortRegMark).
			MatchRegFieldWithValue(PacketCaptureMark, tag).
			SetHardTimeout(timeout)
		fb = sendToController(fb)
		fb = output(fb)
		flows = append(flows, fb.Done())
	}

	// This generates PacketCapture specific flows that outputs hairpin PacketCapture packets to OVS port and Antrea Agent after
	// L2forwarding calculation.
	for _, ipProtocol := range f.ipProtocols {
		if f.enableProxy {
			fb := OutputTable.ofTable.BuildFlow(priorityHigh+2).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTMark(HairpinCTMark).
				MatchRegFieldWithValue(PacketCaptureMark, uint32(dataplaneTag)).
				SetHardTimeout(timeout)
			fb = sendToController(fb)
			fb = fb.Action().OutputToRegField(TargetOFPortField)
			flows = append(flows, fb.Done())
		}
	}

	return flows
}

func matchTransportHeader(packet *binding.Packet, flowBuilder binding.FlowBuilder, endpointPackets []binding.Packet) binding.FlowBuilder {
	// Match transport header
	switch packet.IPProto {
	case protocol.Type_ICMP:
		flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolICMP)
	case protocol.Type_IPv6ICMP:
		flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolICMPv6)
	case protocol.Type_TCP:
		if packet.IsIPv6 {
			flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolTCPv6)
		} else {
			flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolTCP)
		}
	case protocol.Type_UDP:
		if packet.IsIPv6 {
			flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolUDPv6)
		} else {
			flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolUDP)
		}
	default:
		flowBuilder = flowBuilder.MatchIPProtocolValue(packet.IsIPv6, packet.IPProto)
	}
	if packet.IPProto == protocol.Type_TCP || packet.IPProto == protocol.Type_UDP {
		if endpointPackets != nil && endpointPackets[0].DestinationPort != 0 {
			flowBuilder = flowBuilder.MatchDstPort(endpointPackets[0].DestinationPort, nil)
		} else if packet.DestinationPort != 0 {
			flowBuilder = flowBuilder.MatchDstPort(packet.DestinationPort, nil)
		}
		if packet.SourcePort != 0 {
			flowBuilder = flowBuilder.MatchSrcPort(packet.SourcePort, nil)
		}
	}

	return flowBuilder
}
