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

	"antrea.io/libOpenflow/protocol"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

type featureTraceflow struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol

	tfFlowCache *flowCategoryCache

	gatewayIPs            map[binding.Protocol]net.IP
	ovsMetersAreSupported bool
	enableProxy           bool
	enableAntreaPolicy    bool
	supportEncap          bool
}

func (c *featureTraceflow) getFeatureID() featureID {
	return Traceflow
}

func newFeatureTraceflow(cookieAllocator cookie.Allocator,
	ipProtocols []binding.Protocol,
	ovsDatapathType ovsconfig.OVSDatapathType,
	nodeConfig *config.NodeConfig,
	enableProxy,
	enableAntreaPolicy,
	supportEncap bool) feature {
	gatewayIPs := make(map[binding.Protocol]net.IP)
	for _, ipProtocol := range ipProtocols {
		if ipProtocol == binding.ProtocolIP && nodeConfig.GatewayConfig.IPv4 != nil {
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv4
		} else if ipProtocol == binding.ProtocolIPv6 && nodeConfig.GatewayConfig.IPv6 != nil {
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv6
		}
	}

	return &featureTraceflow{
		cookieAllocator:       cookieAllocator,
		ipProtocols:           ipProtocols,
		tfFlowCache:           newFlowCategoryCache(),
		ovsMetersAreSupported: ovsMetersAreSupported(ovsDatapathType),
		enableProxy:           enableProxy,
		enableAntreaPolicy:    enableAntreaPolicy,
		supportEncap:          supportEncap,
	}
}

// For ConntrackStateTable, ingressEntryTable.
// TODO: Use DuplicateToBuilder or integrate this function into original one to avoid unexpected
// difference.
// traceflowConnectionTrackFlows generates Traceflow specific flows in the
// connectionTrackStateTable or L2ForwardingCalcTable.  When packet is not
// provided, the flows bypass the drop flow in conntrackStateFlow to avoid
// unexpected drop of the injected Traceflow packet, and to drop any Traceflow
// packet that has ct_state +rpl, which may happen when the Traceflow request
// destination is the Node's IP.
// When packet is provided, a flow is added to mark - the first packet of the
// first connection that matches the provided packet - as the Traceflow packet.
// The flow is added in connectionTrackStateTable when receiverOnly is false and
// it also matches in_port to be the provided ofPort (the sender Pod); otherwise
// when receiverOnly is true, the flow is added into L2ForwardingCalcTable and
// matches the destination MAC (the receiver Pod MAC).
func (c *featureTraceflow) traceflowConnectionTrackFlows(category cookie.Category, dataplaneTag uint8, receiverOnly bool, packet *binding.Packet, ofPort uint32, timeout uint16) []binding.Flow {
	var flows []binding.Flow
	if packet == nil {
		for _, ipProtocol := range c.ipProtocols {
			flowBuilder := ConntrackStateTable.ofTable.BuildFlow(priorityLow + 1).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout)

			if c.enableProxy {
				flowBuilder = flowBuilder.
					Action().ResubmitToTables(SessionAffinityTable.ofTable.GetID(), ServiceLBTable.ofTable.GetID())
			} else {
				flowBuilder = flowBuilder.
					Action().ResubmitToTables(ConntrackStateTable.ofTable.GetNext())
			}
			flows = append(flows, flowBuilder.Done())

			flows = append(flows, ConntrackStateTable.ofTable.BuildFlow(priorityLow+2).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchIPDSCP(dataplaneTag).
				MatchCTStateTrk(true).MatchCTStateRpl(true).
				SetHardTimeout(timeout).
				Action().Drop().
				Done())
		}
	} else {
		var flowBuilder binding.FlowBuilder
		if !receiverOnly {
			flowBuilder = ConntrackStateTable.ofTable.BuildFlow(priorityLow).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchInPort(ofPort).
				Action().LoadIPDSCP(dataplaneTag)
			if packet.DestinationIP != nil {
				flowBuilder = flowBuilder.MatchDstIP(packet.DestinationIP)
			}
			if c.enableProxy {
				flowBuilder = flowBuilder.
					Action().ResubmitToTables(SessionAffinityTable.ofTable.GetID(), ServiceLBTable.ofTable.GetID())
			} else {
				flowBuilder = flowBuilder.
					Action().ResubmitToTables(ConntrackStateTable.ofTable.GetNext())
			}
		} else {
			var nextTable uint8
			if c.enableAntreaPolicy {
				nextTable = AntreaPolicyIngressRuleTable.GetID()
			} else {
				nextTable = IngressRuleTable.GetID()
			}
			flowBuilder = L2ForwardingCalcTable.ofTable.BuildFlow(priorityHigh).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchDstMAC(packet.DestinationMAC).
				Action().LoadToRegField(TargetOFPortField, ofPort).
				Action().LoadRegMark(OFPortFoundRegMark).
				Action().LoadIPDSCP(dataplaneTag).
				Action().GotoTable(nextTable)
			if packet.SourceIP != nil {
				flowBuilder = flowBuilder.MatchSrcIP(packet.SourceIP)
			}
		}

		flowBuilder = flowBuilder.MatchCTStateNew(true).MatchCTStateTrk(true).
			SetHardTimeout(timeout)

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
			if packet.DestinationPort != 0 {
				flowBuilder = flowBuilder.MatchDstPort(packet.DestinationPort, nil)
			}
			if packet.SourcePort != 0 {
				flowBuilder = flowBuilder.MatchSrcPort(packet.SourcePort, nil)
			}
		}
		flows = []binding.Flow{flowBuilder.Done()}
	}
	return flows
}

func (c *featureTraceflow) traceflowNetworkPolicyFlows(category cookie.Category, featureNetworkPolicy *featureNetworkPolicy, dataplaneTag uint8, timeout uint16) []binding.Flow {
	var flows []binding.Flow
	featureNetworkPolicy.conjMatchFlowLock.Lock()
	defer featureNetworkPolicy.conjMatchFlowLock.Unlock()
	// Copy default drop rules.
	for _, ctx := range featureNetworkPolicy.globalConjMatchFlowCache {
		if ctx.dropFlow != nil {
			copyFlowBuilder := ctx.dropFlow.CopyToBuilder(priorityNormal+2, false)
			if ctx.dropFlow.FlowProtocol() == "" {
				copyFlowBuilderIPv6 := ctx.dropFlow.CopyToBuilder(priorityNormal+2, false)
				copyFlowBuilderIPv6 = copyFlowBuilderIPv6.MatchProtocol(binding.ProtocolIPv6)
				if c.ovsMetersAreSupported {
					copyFlowBuilderIPv6 = copyFlowBuilderIPv6.Action().Meter(PacketInMeterIDTF)
				}
				flows = append(flows, copyFlowBuilderIPv6.MatchIPDSCP(dataplaneTag).
					Cookie(c.cookieAllocator.Request(category).Raw()).
					SetHardTimeout(timeout).
					Action().SendToController(uint8(PacketInReasonTF)).
					Done())
				copyFlowBuilder = copyFlowBuilder.MatchProtocol(binding.ProtocolIP)
			}
			if c.ovsMetersAreSupported {
				copyFlowBuilder = copyFlowBuilder.Action().Meter(PacketInMeterIDTF)
			}
			flows = append(flows, copyFlowBuilder.MatchIPDSCP(dataplaneTag).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				SetHardTimeout(timeout).
				Action().SendToController(uint8(PacketInReasonTF)).
				Done())
		}
	}
	// Copy Antrea NetworkPolicy drop rules.
	for _, conj := range featureNetworkPolicy.policyCache.List() {
		for _, flow := range conj.(*policyRuleConjunction).metricFlows {
			if flow.IsDropFlow() {
				copyFlowBuilder := flow.CopyToBuilder(priorityNormal+2, false)
				// Generate both IPv4 and IPv6 flows if the original drop flow doesn't match IP/IPv6.
				// DSCP field is in IP/IPv6 headers so IP/IPv6 match is required in a flow.
				if flow.FlowProtocol() == "" {
					copyFlowBuilderIPv6 := flow.CopyToBuilder(priorityNormal+2, false)
					copyFlowBuilderIPv6 = copyFlowBuilderIPv6.MatchProtocol(binding.ProtocolIPv6)
					if c.ovsMetersAreSupported {
						copyFlowBuilderIPv6 = copyFlowBuilderIPv6.Action().Meter(PacketInMeterIDTF)
					}
					flows = append(flows, copyFlowBuilderIPv6.MatchIPDSCP(dataplaneTag).
						SetHardTimeout(timeout).
						Cookie(c.cookieAllocator.Request(category).Raw()).
						Action().SendToController(uint8(PacketInReasonTF)).
						Done())
					copyFlowBuilder = copyFlowBuilder.MatchProtocol(binding.ProtocolIP)
				}
				if c.ovsMetersAreSupported {
					copyFlowBuilder = copyFlowBuilder.Action().Meter(PacketInMeterIDTF)
				}
				flows = append(flows, copyFlowBuilder.MatchIPDSCP(dataplaneTag).
					SetHardTimeout(timeout).
					Cookie(c.cookieAllocator.Request(category).Raw()).
					Action().SendToController(uint8(PacketInReasonTF)).
					Done())
			}
		}
	}
	return flows
}

// For L2ForwardingOutTable.
// traceflowL2ForwardOutputFlows generates Traceflow specific flows that outputs traceflow packets
// to OVS port and Antrea Agent after L2forwarding calculation.
func (c *featureTraceflow) traceflowL2ForwardOutputFlows(category cookie.Category, dataplaneTag uint8, liveTraffic, droppedOnly bool, timeout uint16) []binding.Flow {
	var flows []binding.Flow
	for _, ipProtocol := range c.ipProtocols {
		if c.supportEncap {
			// SendToController and Output if output port is tunnel port.
			fb1 := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+3).
				MatchRegFieldWithValue(TargetOFPortField, config.DefaultTunOFPort).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				MatchProtocol(ipProtocol).
				MatchRegMark(OFPortFoundRegMark).
				Action().OutputToRegField(TargetOFPortField).
				Cookie(c.cookieAllocator.Request(category).Raw())
			// For injected packets, only SendToController if output port is local
			// gateway. In encapMode, a Traceflow packet going out of the gateway
			// port (i.e. exiting the overlay) essentially means that the Traceflow
			// request is complete.
			fb2 := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+2).
				MatchRegFieldWithValue(TargetOFPortField, config.HostGatewayOFPort).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				MatchProtocol(ipProtocol).
				MatchRegMark(OFPortFoundRegMark).
				Cookie(c.cookieAllocator.Request(category).Raw())

			// Do not send to controller if captures only dropped packet.
			if !droppedOnly {
				if c.ovsMetersAreSupported {
					fb1 = fb1.Action().Meter(PacketInMeterIDTF)
					fb2 = fb2.Action().Meter(PacketInMeterIDTF)
				}
				fb1 = fb1.Action().SendToController(uint8(PacketInReasonTF))
				fb2 = fb2.Action().SendToController(uint8(PacketInReasonTF))
			}
			if liveTraffic {
				// Clear the loaded DSCP bits before output.
				fb2 = fb2.Action().LoadIPDSCP(0).
					Action().OutputToRegField(TargetOFPortField)
			}
			flows = append(flows, fb1.Done(), fb2.Done())
		} else {
			// SendToController and Output if output port is local gateway. Unlike in
			// encapMode, inter-Node Pod-to-Pod traffic is expected to go out of the
			// gateway port on the way to its destination.
			fb1 := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+2).
				MatchRegFieldWithValue(TargetOFPortField, config.HostGatewayOFPort).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				MatchProtocol(ipProtocol).
				MatchRegMark(OFPortFoundRegMark).
				Action().OutputToRegField(TargetOFPortField).
				Cookie(c.cookieAllocator.Request(category).Raw())
			if !droppedOnly {
				if c.ovsMetersAreSupported {
					fb1 = fb1.Action().Meter(PacketInMeterIDTF)
				}
				fb1 = fb1.Action().SendToController(uint8(PacketInReasonTF))
			}
			flows = append(flows, fb1.Done())
		}
		// Only SendToController if output port is local gateway and destination IP is gateway.
		gatewayIP := c.gatewayIPs[ipProtocol]
		if gatewayIP != nil {
			fb := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+3).
				MatchRegFieldWithValue(TargetOFPortField, config.HostGatewayOFPort).
				MatchDstIP(gatewayIP).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				MatchProtocol(ipProtocol).
				MatchRegMark(OFPortFoundRegMark).
				Cookie(c.cookieAllocator.Request(category).Raw())
			if !droppedOnly {
				if c.ovsMetersAreSupported {
					fb = fb.Action().Meter(PacketInMeterIDTF)
				}
				fb = fb.Action().SendToController(uint8(PacketInReasonTF))
			}
			if liveTraffic {
				fb = fb.Action().LoadIPDSCP(0).
					Action().OutputToRegField(TargetOFPortField)
			}
			flows = append(flows, fb.Done())
		}
		// Only SendToController if output port is Pod port.
		fb := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal + 2).
			MatchIPDSCP(dataplaneTag).
			SetHardTimeout(timeout).
			MatchProtocol(ipProtocol).
			MatchRegMark(OFPortFoundRegMark).
			Cookie(c.cookieAllocator.Request(category).Raw())
		if !droppedOnly {
			if c.ovsMetersAreSupported {
				fb = fb.Action().Meter(PacketInMeterIDTF)
			}
			fb = fb.Action().SendToController(uint8(PacketInReasonTF))
		}
		if liveTraffic {
			fb = fb.Action().LoadIPDSCP(0).
				Action().OutputToRegField(TargetOFPortField)
		}
		flows = append(flows, fb.Done())
		if c.enableProxy {
			// Only SendToController for hairpin traffic.
			// This flow must have higher priority than the one installed by l2ForwardOutputServiceHairpinFlow
			fbHairpin := L2ForwardingOutTable.ofTable.BuildFlow(priorityHigh + 2).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				MatchProtocol(ipProtocol).
				MatchRegMark(HairpinRegMark).
				Cookie(c.cookieAllocator.Request(cookie.Service).Raw())
			if !droppedOnly {
				if c.ovsMetersAreSupported {
					fbHairpin = fbHairpin.Action().Meter(PacketInMeterIDTF)
				}
				fbHairpin = fbHairpin.Action().SendToController(uint8(PacketInReasonTF))
			}
			if liveTraffic {
				fbHairpin = fbHairpin.Action().LoadIPDSCP(0).
					Action().OutputInPort()
			}
			flows = append(flows, fbHairpin.Done())
		}
	}
	return flows
}
