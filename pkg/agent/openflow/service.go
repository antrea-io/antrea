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
	"encoding/binary"
	"net"
	"sync"

	v1 "k8s.io/api/core/v1"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/third_party/proxy"
)

type featureService struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol
	bridge          binding.Bridge

	serviceFlowCache    *flowCategoryCache
	defaultServiceFlows []binding.Flow
	groupCache          sync.Map

	gatewayIPs  map[binding.Protocol]net.IP
	virtualIPs  map[binding.Protocol]net.IP
	dnatCtZones map[binding.Protocol]int
	snatCtZones map[binding.Protocol]int
	gatewayMAC  net.HardwareAddr

	enableProxy bool
	proxyAll    bool
}

func (c *featureService) getFeatureID() featureID {
	return Service
}

func newFeatureService(
	cookieAllocator cookie.Allocator,
	ipProtocols []binding.Protocol,
	nodeConfig *config.NodeConfig,
	bridge binding.Bridge,
	enableProxy,
	proxyAll bool) feature {
	gatewayIPs := make(map[binding.Protocol]net.IP)
	virtualIPs := make(map[binding.Protocol]net.IP)
	dnatCtZones := make(map[binding.Protocol]int)
	snatCtZones := make(map[binding.Protocol]int)
	for _, ipProtocol := range ipProtocols {
		if ipProtocol == binding.ProtocolIP {
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv4
			virtualIPs[ipProtocol] = config.VirtualServiceIPv4
			dnatCtZones[ipProtocol] = CtZone
			snatCtZones[ipProtocol] = SNATCtZone
		} else if ipProtocol == binding.ProtocolIPv6 {
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv6
			virtualIPs[ipProtocol] = config.VirtualServiceIPv6
			dnatCtZones[ipProtocol] = CtZoneV6
			snatCtZones[ipProtocol] = SNATCtZoneV6
		}
	}

	return &featureService{
		cookieAllocator:  cookieAllocator,
		ipProtocols:      ipProtocols,
		bridge:           bridge,
		serviceFlowCache: newFlowCategoryCache(),
		groupCache:       sync.Map{},
		gatewayIPs:       gatewayIPs,
		virtualIPs:       virtualIPs,
		dnatCtZones:      dnatCtZones,
		snatCtZones:      snatCtZones,
		gatewayMAC:       nodeConfig.GatewayConfig.MAC,
		enableProxy:      enableProxy,
		proxyAll:         proxyAll,
	}
}

// For UplinkTable.
// loadBalancerServiceFromOutsideFlow generates the flow to forward LoadBalancer service traffic from outside node
// to gateway. kube-proxy will then handle the traffic.
// This flow is for Windows Node only.
func (c *featureService) loadBalancerServiceFromOutsideFlow(svcIP net.IP, svcPort uint16, protocol binding.Protocol) binding.Flow {
	return UplinkTable.ofTable.BuildFlow(priorityHigh).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		MatchProtocol(protocol).
		MatchDstPort(svcPort, nil).
		MatchRegMark(FromUplinkRegMark).
		MatchDstIP(svcIP).
		Action().Output(config.HostGatewayOFPort).
		Done()
}

// Stage: ValidationStage
// Tables: ConntrackTable
// New added
// conntrackFlows generates the flows to load HairpinRegMark for reply packets of SNATTed hairpin connections after passing
// SNAT ct zone.
func (c *featureService) conntrackFlows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, ipProtocol := range c.ipProtocols {
		flows = append(flows,
			ConntrackTable.ofTable.BuildFlow(priorityHigh).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchCTMark(HairpinCTMark).
				Action().LoadRegMark(HairpinRegMark).
				Action().CT(false, ConntrackTable.ofTable.GetNext(), c.dnatCtZones[ipProtocol]).
				NAT().
				CTDone().
				Done(),
		)
	}
	return flows
}

// Stage: ValidationStage
// Tables: ConntrackStateTable
// Refactored from:
//   - part of `func (c *client) connectionTrackFlows(category cookie.Category) []binding.Flow`
// conntrackStateFlow generates the flow to match the first packet of Service connections.
func (c *featureService) conntrackStateFlow(category cookie.Category) binding.Flow {
	// Replace the default flow with multiple resubmits actions.
	targetTables := []uint8{SessionAffinityTable.ofTable.GetID(), ServiceLBTable.ofTable.GetID()}
	if c.proxyAll {
		targetTables = append([]uint8{NodePortProbeTable.ofTable.GetID()}, targetTables...)
	}
	return ConntrackStateTable.ofTable.BuildFlow(priorityMiss).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Action().ResubmitToTables(targetTables...).
		Done()
}

// Stage: ValidationStage
// Tables: ConntrackStateTable
// Refactored from:
//   - `func (c *client) serviceLBBypassFlows(ipProtocol binding.Protocol) []binding`
// serviceLBBypassFlows makes packets that belong to a tracked connection bypass service LB tables and enter
// EgressSecurityStage directly.
func (c *featureService) serviceLBBypassFlows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, ipProtocol := range c.ipProtocols {
		flows = append(flows,
			// Tracked connections with the ServiceCTMark (load-balanced by AntreaProxy) receive the macRewriteMark and are
			// sent to egressRuleTable.
			ConntrackStateTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchCTMark(ServiceCTMark).
				MatchCTStateNew(false).
				MatchCTStateTrk(true).
				Action().LoadRegMark(RewriteMACRegMark).
				Action().GotoStage(binding.EgressSecurityStage).
				Done(),
			// Tracked connections without the ServiceCTMark are sent to egressRuleTable directly. This is meant to match
			// connections which were load-balanced by kube-proxy before AntreaProxy got enabled.
			ConntrackStateTable.ofTable.BuildFlow(priorityLow).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(false).
				MatchCTStateTrk(true).
				Action().GotoStage(binding.EgressSecurityStage).
				Done(),
		)
	}
	return flows
}

// Stage: ValidationStage
// Tables: NodePortProbeTable
// Refactored from:
//   - `func (c *client) serviceClassifierFlows(nodePortAddresses []net.IP, ipProtocol binding.Protocol) []binding.Flow`
// nodePortProbeFlows generate the flows to match the first packet of Service NodePort and set a bit of a register
// to mark the Service type as NodePort.
func (c *featureService) nodePortProbeFlows(category cookie.Category, nodePortAddresses []net.IP, ipProtocol binding.Protocol) []binding.Flow {
	// Generate flows for every NodePort IP address. The flows are used to match the first packet of Service NodePort from
	// Pod.
	var flows []binding.Flow
	for i := range nodePortAddresses {
		flows = append(flows,
			NodePortProbeTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchDstIP(nodePortAddresses[i]).
				Action().LoadRegMark(ToNodePortAddressRegMark).
				Done())
	}
	// Generate flow for the virtual IP. The flow is used to match the first packet of Service NodePort from Antrea gateway,
	// because the destination IP of the packet has already performed DNAT with the virtual IP on host.
	flows = append(flows,
		NodePortProbeTable.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchDstIP(c.virtualIPs[ipProtocol]).
			Action().LoadRegMark(ToNodePortAddressRegMark).
			Done())

	return flows
}

// Stage: PreRoutingStage
// Tables: ServiceLBTable
// Refactored from:
//   - `func (c *client) serviceLBFlow(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol,
//      withSessionAffinity, nodeLocalExternal bool, svcType v1.ServiceType) binding.Flow`
// serviceLBFlow generates the flow which uses the specific group to do Endpoint selection.
func (c *featureService) serviceLBFlow(
	category cookie.Category,
	groupID binding.GroupIDType,
	svcIP net.IP,
	svcPort uint16,
	protocol binding.Protocol,
	withSessionAffinity,
	nodeLocalExternal bool,
	serviceType v1.ServiceType) binding.Flow {
	var lbResultMark *binding.RegMark
	if withSessionAffinity {
		lbResultMark = EpToLearnRegMark
	} else {
		lbResultMark = EpSelectedRegMark
	}
	var flowBuilder binding.FlowBuilder
	if serviceType == v1.ServiceTypeNodePort {
		// If externalTrafficPolicy of NodePort is Cluster, the first packet of NodePort requires SNAT, so nodeLocalExternal
		// will be false, and ServiceNeedSNATRegMark will be set. If externalTrafficPolicy of NodePort is Local, the first
		// packet of NodePort doesn't require SNAT, ServiceNeedSNATRegMark won't be set.
		unionVal := (ToNodePortAddressRegMark.GetValue() << ServiceEPStateField.GetRange().Length()) + EpToSelectRegMark.GetValue()
		flowBuilder = ServiceLBTable.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(protocol).
			MatchRegFieldWithValue(NodePortUnionField, unionVal).
			MatchDstPort(svcPort, nil).
			Action().LoadRegMark(lbResultMark).
			Action().LoadRegMark(RewriteMACRegMark)
		if !nodeLocalExternal {
			flowBuilder = flowBuilder.Action().LoadRegMark(RequireSNATRegMark)
		}
	} else {
		// If Service type is LoadBalancer, as above NodePort.
		flowBuilder = ServiceLBTable.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(protocol).
			MatchDstPort(svcPort, nil).
			MatchDstIP(svcIP).
			MatchRegMark(EpToSelectRegMark).
			Action().LoadRegMark(lbResultMark).
			Action().LoadRegMark(RewriteMACRegMark)
		if serviceType == v1.ServiceTypeLoadBalancer && !nodeLocalExternal {
			flowBuilder = flowBuilder.Action().LoadRegMark(RequireSNATRegMark)
		}
	}
	return flowBuilder.Action().Group(groupID).Done()
}

// Stage: PreRoutingStage
// Tables: SessionAffinityTable
// Refactored from:
//   - `func (c *client) serviceLearnFlow(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol,
//      affinityTimeout uint16, nodeLocalExternal bool, svcType v1.ServiceType) binding.Flow`
// serviceLearnFlow generates the flow with learn action which adds new flows in SessionAffinityTable according to the
// Endpoint selection decision.
func (c *featureService) serviceLearnFlow(
	category cookie.Category,
	groupID binding.GroupIDType,
	svcIP net.IP,
	svcPort uint16,
	protocol binding.Protocol,
	affinityTimeout uint16,
	nodeLocalExternal bool,
	serviceType v1.ServiceType) binding.Flow {
	// Using unique cookie ID here to avoid learned flow cascade deletion.
	cookieID := c.cookieAllocator.RequestWithObjectID(category, uint32(groupID)).Raw()
	var flowBuilder binding.FlowBuilder
	if serviceType == v1.ServiceTypeNodePort {
		unionVal := (ToNodePortAddressRegMark.GetValue() << ServiceEPStateField.GetRange().Length()) + EpToLearnRegMark.GetValue()
		flowBuilder = ServiceLBTable.ofTable.BuildFlow(priorityLow).
			Cookie(cookieID).
			MatchProtocol(protocol).
			MatchRegFieldWithValue(NodePortUnionField, unionVal).
			MatchDstPort(svcPort, nil)
	} else {
		flowBuilder = ServiceLBTable.ofTable.BuildFlow(priorityLow).
			Cookie(cookieID).
			MatchProtocol(protocol).
			MatchRegMark(EpToLearnRegMark).
			MatchDstIP(svcIP).
			MatchDstPort(svcPort, nil)
	}

	// affinityTimeout is used as the OpenFlow "hard timeout": learned flow will be removed from
	// OVS after that time regarding of whether traffic is still hitting the flow. This is the
	// desired behavior based on the K8s spec. Note that existing connections will keep going to
	// the same endpoint because of connection tracking; and that is also the desired behavior.
	learnFlowBuilderLearnAction := flowBuilder.
		Action().Learn(SessionAffinityTable.ofTable.GetID(), priorityNormal, 0, affinityTimeout, cookieID).
		DeleteLearned()
	switch protocol {
	case binding.ProtocolTCP:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedTCPDstPort()
	case binding.ProtocolUDP:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedUDPDstPort()
	case binding.ProtocolSCTP:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedSCTPDstPort()
	case binding.ProtocolTCPv6:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedTCPv6DstPort()
	case binding.ProtocolUDPv6:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedUDPv6DstPort()
	case binding.ProtocolSCTPv6:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedSCTPv6DstPort()
	}
	// If externalTrafficPolicy of NodePort/LoadBalancer is Cluster, the learned flow which
	// is used to match the first packet of NodePort/LoadBalancer also requires SNAT.
	if (serviceType == v1.ServiceTypeNodePort || serviceType == v1.ServiceTypeLoadBalancer) && !nodeLocalExternal {
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.LoadRegMark(RequireSNATRegMark)
	}

	ipProtocol := getIPProtocol(svcIP)
	if ipProtocol == binding.ProtocolIP {
		return learnFlowBuilderLearnAction.
			MatchLearnedDstIP().
			MatchLearnedSrcIP().
			LoadFieldToField(EndpointIPField, EndpointIPField).
			LoadFieldToField(EndpointPortField, EndpointPortField).
			LoadRegMark(EpSelectedRegMark).
			LoadRegMark(RewriteMACRegMark).
			Done().
			Action().LoadRegMark(EpSelectedRegMark).
			Action().ResubmitToTables(EndpointDNATTable.ofTable.GetID()).
			Done()
	} else if ipProtocol == binding.ProtocolIPv6 {
		return learnFlowBuilderLearnAction.
			MatchLearnedDstIPv6().
			MatchLearnedSrcIPv6().
			LoadXXRegToXXReg(EndpointIP6Field, EndpointIP6Field).
			LoadFieldToField(EndpointPortField, EndpointPortField).
			LoadRegMark(EpSelectedRegMark).
			LoadRegMark(RewriteMACRegMark).
			Done().
			Action().LoadRegMark(EpSelectedRegMark).
			Action().NextTable().
			Done()
	}
	return nil
}

// Stage: PreRoutingStage
// Tables: SessionAffinityTable
// Refactored from:
//   - `func (c *client) serviceNeedLBFlow() binding.Flow`
// serviceNeedLBFlow generates flows to mark packets as LB needed.
func (c *featureService) serviceNeedLBFlow(category cookie.Category) binding.Flow {
	return SessionAffinityTable.ofTable.BuildFlow(priorityMiss).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Action().LoadRegMark(EpToSelectRegMark).
		Done()
}

// Stage: PreRoutingStage
// Tables: EndpointDNATTable
// Refactored from:
//   - `func (c *client) endpointDNATFlow(endpointIP net.IP, endpointPort uint16, protocol binding.Protocol) binding.Flow`
// endpointDNATFlow generates the flow which transforms the Service Cluster IP to the Endpoint IP according to the
// Endpoint selection decision which is stored in regs.
func (c *featureService) endpointDNATFlow(category cookie.Category, endpointIP net.IP, endpointPort uint16, protocol binding.Protocol) binding.Flow {
	unionVal := (EpSelectedRegMark.GetValue() << EndpointPortField.GetRange().Length()) + uint32(endpointPort)
	flowBuilder := EndpointDNATTable.ofTable.BuildFlow(priorityNormal).
		MatchProtocol(protocol).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchRegFieldWithValue(EpUnionField, unionVal)
	ipProtocol := getIPProtocol(endpointIP)

	if ipProtocol == binding.ProtocolIP {
		ipVal := binary.BigEndian.Uint32(endpointIP.To4())
		flowBuilder = flowBuilder.MatchRegFieldWithValue(EndpointIPField, ipVal)
	} else {
		ipVal := []byte(endpointIP)
		flowBuilder = flowBuilder.MatchXXReg(EndpointIP6Field.GetRegID(), ipVal)
	}

	return flowBuilder.Action().
		CT(true, EndpointDNATTable.ofTable.GetNext(), c.dnatCtZones[ipProtocol]).
		DNAT(
			&binding.IPRange{StartIP: endpointIP, EndIP: endpointIP},
			&binding.PortRange{StartPort: endpointPort, EndPort: endpointPort},
		).
		LoadToCtMark(ServiceCTMark).
		CTDone().
		Done()
}

// Stage: PreRoutingStage
// Tables: EndpointDNATTable
// Refactored from:
//   - `func (c *client) sessionAffinityReselectFlow() binding.Flow`
// sessionAffinityReselectFlow generates the flow which resubmits the service accessing packet back to ServiceLBTable
// if there is no endpointDNAT flow matched. This case will occur if an Endpoint is removed and is the learned Endpoint
// selection of the Service.
func (c *featureService) sessionAffinityReselectFlow(category cookie.Category) binding.Flow {
	return EndpointDNATTable.ofTable.BuildFlow(priorityLow).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchRegMark(EpSelectedRegMark).
		Action().LoadRegMark(EpToSelectRegMark).
		Action().ResubmitToTables(ServiceLBTable.ofTable.GetID()).
		Done()
}

// Stage: PreRoutingStage
// Service group
// Refactored from:
//   - `func (c *client) serviceEndpointGroup(groupID binding.GroupIDType, withSessionAffinity bool, endpoints ...proxy.Endpoint)
//      binding.Group`
// serviceEndpointGroup creates/modifies the group/buckets of Endpoints. If the withSessionAffinity is true, then buckets
// will resubmit packets back to ServiceLBTable to trigger the learn flow, the learn flow will then send packets to
// EndpointDNATTable. Otherwise, buckets will resubmit packets to EndpointDNATTable directly.
func (c *featureService) serviceEndpointGroup(groupID binding.GroupIDType, withSessionAffinity bool, endpoints ...proxy.Endpoint) binding.Group {
	group := c.bridge.CreateGroup(groupID).ResetBuckets()
	var resubmitTableID uint8
	if withSessionAffinity {
		resubmitTableID = ServiceLBTable.ofTable.GetID()
	} else {
		resubmitTableID = EndpointDNATTable.ofTable.GetID()
	}
	for _, endpoint := range endpoints {
		endpointPort, _ := endpoint.Port()
		endpointIP := net.ParseIP(endpoint.IP())
		portVal := portToUint16(endpointPort)
		ipProtocol := getIPProtocol(endpointIP)

		if ipProtocol == binding.ProtocolIP {
			ipVal := binary.BigEndian.Uint32(endpointIP.To4())
			group = group.Bucket().Weight(100).
				LoadToRegField(EndpointIPField, ipVal).
				LoadToRegField(EndpointPortField, uint32(portVal)).
				ResubmitToTable(resubmitTableID).
				Done()
		} else if ipProtocol == binding.ProtocolIPv6 {
			ipVal := []byte(endpointIP)
			group = group.Bucket().Weight(100).
				LoadXXReg(EndpointIP6Field.GetRegID(), ipVal).
				LoadToRegField(EndpointPortField, uint32(portVal)).
				ResubmitToTable(resubmitTableID).
				Done()
		}
	}
	return group
}

// Stage: PreRoutingStage
// Tables: DNATTable
// Requirements: AntreaProxy is disabled
// Refactored from:
//   - `func (c *client) serviceCIDRDNATFlows(serviceCIDRs []*net.IPNet) []binding.Flow`
// serviceCIDRDNATFlows generates flows to match dst IP in service CIDR and output to host gateway interface directly.
func (c *featureService) serviceCIDRDNATFlows(category cookie.Category, serviceCIDRs []*net.IPNet) []binding.Flow {
	var flows []binding.Flow
	for _, serviceCIDR := range serviceCIDRs {
		if serviceCIDR != nil {
			ipProtocol := getIPProtocol(serviceCIDR.IP)
			flows = append(flows, DNATTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchDstIPNet(*serviceCIDR).
				Action().LoadToRegField(TargetOFPortField, config.HostGatewayOFPort).
				Action().LoadRegMark(OFPortFoundRegMark).
				Action().GotoStage(binding.ConntrackStage).
				Done())
		}
	}
	return flows
}

// Stage: RoutingStage
// Tables: L3ForwardingTable
// New added
// l3FwdDefaultFlowViaGW generates the default L3 forward flows to forward packets which are not match by other flows
// to pass through Antrea gateway.
func (c *featureService) l3FwdDefaultFlowViaGW(category cookie.Category) binding.Flow {
	// When client is from Node or remote, Endpoint is on host network, the connection is hairpin. The destination MAC of
	// the packets should be rewritten with Antrea gateway's MAC. HairpinRegMark should be also set.
	return L3ForwardingTable.ofTable.BuildFlow(priorityLow).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchCTMark(ServiceCTMark).
		MatchRegMark(NotAntreaFlexibleIPAMRegMark).
		Action().SetDstMAC(c.gatewayMAC).
		Action().LoadRegMark(ToGatewayRegMark).
		Action().NextTable().
		Done()
}

// Stage: RoutingStage
// Tables: ServiceHairpinMarkTable
// New added
// intraClusterHairpinFlow generates the flows to match request packets of hairpin Service connections inside the Cluster.
func (c *featureService) intraClusterHairpinFlow(category cookie.Category, endpoint net.IP) binding.Flow {
	ipProtocol := getIPProtocol(endpoint)
	return ServiceHairpinMarkTable.ofTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchProtocol(ipProtocol).
		MatchSrcIP(endpoint).
		MatchDstIP(endpoint).
		Action().LoadRegMark(HairpinRegMark).
		Action().LoadRegMark(SNATWithGatewayIP).
		Action().LoadRegMark(NotRequireSNATRegMark).
		Action().NextTable().
		Done()
}

// Stage: RoutingStage
// Tables: ServiceHairpinMarkTable
// New added
// externalClusterHairpinFlow generate the flow to match packets of hairpin Service connections outside the Cluster.
func (c *featureService) externalClusterHairpinFlow(category cookie.Category) binding.Flow {
	return ServiceHairpinMarkTable.ofTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchRegMark(GatewayHairpinRegMark).
		Action().LoadRegMark(HairpinRegMark).
		Action().LoadRegMark(SNATWithVirtualIP).
		Action().NextTable().
		Done()
}

// Stage: PreRoutingStage
// Tables: SNATConntrackTable
// Stage: PostRoutingStage
// Tables: SNATConntrackCommitTable
// Refactored from:
//   - part of `func (c *client) connectionTrackFlows(category cookie.Category) []binding.Flow`
// snatConntrackFlows generates the flows related to SNAT ct zone.
func (c *featureService) snatConntrackFlows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, ipProtocol := range c.ipProtocols {
		flows = append(flows,
			// This flow is used to maintain SNAT conntrack for Service traffic.
			SNATConntrackTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				Action().CT(false, SNATConntrackTable.ofTable.GetNext(), c.snatCtZones[ipProtocol]).
				NAT().
				CTDone().
				Done(),

			// This flow is used to mark the first packet of hairpin Service packet from status 'NotRequireSNATRegMark'
			// to status 'CTMarkedSNATRegMark'.
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(HairpinRegMark).
				MatchRegMark(NotRequireSNATRegMark).
				Action().LoadRegMark(CTMarkedSNATRegMark).
				Action().CT(true, SNATConntrackCommitTable.ofTable.GetID(), c.dnatCtZones[ipProtocol]).
				LoadToCtMark(ServiceSNATCTMark).
				CTDone().
				Done(),
			// This flow is used to mark the first packet of Service packet from Antrea gateway from 'RequireSNATRegMark'
			// to status 'CTMarkedSNATRegMark'.
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityLow).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(FromGatewayRegMark).
				MatchRegMark(RequireSNATRegMark).
				Action().LoadRegMark(CTMarkedSNATRegMark).
				Action().CT(true, SNATConntrackCommitTable.ofTable.GetID(), c.dnatCtZones[ipProtocol]).
				LoadToCtMark(ServiceSNATCTMark).
				CTDone().
				Done(),
			// SNAT flows.
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(HairpinSNATWithVirtualIP).
				MatchRegMark(CTMarkedSNATRegMark).
				Action().CT(true, SNATConntrackCommitTable.ofTable.GetNext(), c.snatCtZones[ipProtocol]).
				SNAT(&binding.IPRange{StartIP: c.virtualIPs[ipProtocol], EndIP: c.virtualIPs[ipProtocol]}, nil).
				LoadToCtMark(UnionHairpinServiceCTMark).
				CTDone().
				Done(),
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(HairpinSNATWithGatewayIP).
				MatchRegMark(CTMarkedSNATRegMark).
				Action().CT(true, SNATConntrackCommitTable.ofTable.GetNext(), c.snatCtZones[ipProtocol]).
				SNAT(&binding.IPRange{StartIP: c.gatewayIPs[ipProtocol], EndIP: c.gatewayIPs[ipProtocol]}, nil).
				LoadToCtMark(UnionHairpinServiceCTMark).
				CTDone().
				Done(),
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityLow).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(FromGatewayRegMark).
				MatchRegMark(CTMarkedSNATRegMark).
				Action().CT(true, SNATConntrackCommitTable.ofTable.GetNext(), c.snatCtZones[ipProtocol]).
				SNAT(&binding.IPRange{StartIP: c.gatewayIPs[ipProtocol], EndIP: c.gatewayIPs[ipProtocol]}, nil).
				LoadToCtMark(ServiceCTMark).
				CTDone().
				Done(),
			// This flow is used to match the consequent request packets of Service traffic whose first request packet has been committed
			// and performed SNAT. For example:
			/*
				* 192.168.77.1 is the IP address of client.
				* 192.168.77.100 is the IP address of k8s node.
				* 30001 is a NodePort port.
				* 10.10.0.1 is the IP address of Antrea gateway.
				* 10.10.0.3 is the Endpoint of NodePort Service.

				* pkt 1 (request)
					* client                     192.168.77.1:12345->192.168.77.100:30001
					* ct zone SNAT 65521         192.168.77.1:12345->192.168.77.100:30001
					* ct zone DNAT 65520         192.168.77.1:12345->192.168.77.100:30001
					* ct commit DNAT zone 65520  192.168.77.1:12345->192.168.77.100:30001  =>  192.168.77.1:12345->10.10.0.3:80
					* ct commit SNAT zone 65521  192.168.77.1:12345->10.10.0.3:80          =>  10.10.0.1:12345->10.10.0.3:80
					* output
				  * pkt 2 (response)
					* Pod                         10.10.0.3:80->10.10.0.1:12345
					* ct zone SNAT 65521          10.10.0.3:80->10.10.0.1:12345            =>  10.10.0.3:80->192.168.77.1:12345
					* ct zone DNAT 65520          10.10.0.3:80->192.168.77.1:12345         =>  192.168.77.1:30001->192.168.77.1:12345
					* output
				  * pkt 3 (request)
					* client                     192.168.77.1:12345->192.168.77.100:30001
					* ct zone SNAT 65521         192.168.77.1:12345->192.168.77.100:30001
					* ct zone DNAT 65520         192.168.77.1:12345->10.10.0.3:80
					* ct zone SNAT 65521         192.168.77.1:12345->10.10.0.3:80          =>  10.10.0.1:12345->10.10.0.3:80
					* output
				  * pkt ...

				The source IP address of pkt 3 cannot be transformed through zone 65521 as there is no connection track about
				192.168.77.1:12345<->192.168.77.100:30001, and the source IP is still 192.168.77.100.
				Before output, pkt 3 needs SNAT, but the connection has been committed. The flow is for pkt 3 to perform SNAT.
			*/
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchCTMark(ServiceSNATCTMark).
				MatchCTStateNew(false).
				MatchCTStateTrk(true).
				MatchCTStateRpl(false).
				Action().CT(false, SNATConntrackCommitTable.ofTable.GetNext(), c.snatCtZones[ipProtocol]).
				NAT().
				CTDone().
				Done(),
		)
	}
	return flows
}

// Stage: ConntrackStage
// Table: ConntrackCommitTable
// New added
// serviceBypassConntrackFlows generates the flows which are used to bypass ConntrackStage for Service traffic.
func (c *featureService) serviceBypassConntrackFlows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, ipProtocol := range c.ipProtocols {
		flows = append(flows,
			ConntrackCommitTable.ofTable.BuildFlow(priorityHigh).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchCTMark(ServiceCTMark).
				Action().GotoStage(binding.OutputStage).
				Done())
	}
	return flows
}

// Stage: OutputStage
// Tables: l2ForwardOutputFlow
// Refactored from:
//   - part of `func (c *client) l2ForwardOutputFlows(category cookie.Category) []binding.Flow`
// l2ForwardOutputServiceHairpinFlow uses in_port action for Service hairpin packets to avoid packets from being dropped
// by OVS.
func (c *featureService) l2ForwardOutputServiceHairpinFlow(category cookie.Category) binding.Flow {
	return L2ForwardingOutTable.ofTable.BuildFlow(priorityHigh).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchRegMark(HairpinRegMark).
		Action().OutputInPort().
		Done()
}

func (c *featureService) initialize(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	if c.enableProxy {
		flows = append(flows, c.conntrackFlows(category)...)
		flows = append(flows, c.conntrackStateFlow(category))
		flows = append(flows, c.l3FwdDefaultFlowViaGW(category))
		flows = append(flows, c.snatConntrackFlows(category)...)
		flows = append(flows, c.externalClusterHairpinFlow(category))
		flows = append(flows, c.serviceBypassConntrackFlows(category)...)
	}
	return flows
}
