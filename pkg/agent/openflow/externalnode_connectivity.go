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

package openflow

import (
	"net"

	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

const (
	policyBypassFlowsKey = "policyBypassFlows"
)

type featureExternalNodeConnectivity struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol
	ctZones         map[binding.Protocol]int
	category        cookie.Category

	uplinkFlowCache *flowCategoryCache
}

func (f *featureExternalNodeConnectivity) getFeatureName() string {
	return "ExternalNodeConnectivity"
}

func newFeatureExternalNodeConnectivity(
	cookieAllocator cookie.Allocator,
	ipProtocols []binding.Protocol) *featureExternalNodeConnectivity {
	ctZones := make(map[binding.Protocol]int)
	for _, ipProtocol := range ipProtocols {
		if ipProtocol == binding.ProtocolIP {
			ctZones[ipProtocol] = CtZone
		} else if ipProtocol == binding.ProtocolIPv6 {
			ctZones[ipProtocol] = CtZoneV6
		}
	}

	return &featureExternalNodeConnectivity{
		cookieAllocator: cookieAllocator,
		ipProtocols:     ipProtocols,
		uplinkFlowCache: newFlowCategoryCache(),
		ctZones:         ctZones,
		category:        cookie.ExternalNodeConnectivity,
	}
}

func (f *featureExternalNodeConnectivity) vmUplinkFlows(hostOFPort, uplinkOFPort uint32) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	return []binding.Flow{
		// Set the output port number with the uplink port if the IP packet enters OVS from the
		// paired host internal port, and then enforce the packet to go through the IP pipeline.
		L2ForwardingCalcTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(binding.ProtocolIP).
			MatchInPort(hostOFPort).
			Action().LoadRegMark(OFPortFoundRegMark).
			Action().LoadToRegField(TargetOFPortField, uplinkOFPort).
			Action().NextTable().
			Done(),
		// Set the output port number with the paired host internal port if the IP packet enters the OVS from
		// the uplink port, and then enforce the packet to go through the IP pipeline.
		L2ForwardingCalcTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchInPort(uplinkOFPort).
			MatchProtocol(binding.ProtocolIP).
			Action().LoadRegMark(OFPortFoundRegMark).
			Action().LoadToRegField(TargetOFPortField, hostOFPort).
			Action().NextTable().
			Done(),
		// Output the packet to the uplink port if it is not using IP protocol, and enters OVS from the
		// paired host internal port.
		NonIPTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchInPort(hostOFPort).
			Action().Output(uplinkOFPort).
			Done(),
		// Output the packet to the uplink port if it is not using IP protocol, and enters OVS from the
		// paired host internal port.
		NonIPTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchInPort(uplinkOFPort).
			Action().Output(hostOFPort).
			Done(),
	}
}

func (f *featureExternalNodeConnectivity) initFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	flows := []binding.Flow{
		L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchRegMark(OFPortFoundRegMark).
			Action().OutputToRegField(TargetOFPortField).
			Done(),
	}
	for _, ipProtocol := range f.ipProtocols {
		ctZone := f.ctZones[ipProtocol]
		flows = append(flows,
			// This generates the flow to maintain tracked connections in CT zone.
			ConntrackTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				Action().CT(false, ConntrackTable.ofTable.GetNext(), ctZone, nil).
				CTDone().
				Done(),
			ConntrackStateTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateInv(true).
				MatchCTStateTrk(true).
				Action().Drop().
				Done(),
			ConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				Action().CT(true, ConntrackCommitTable.GetNext(), ctZone, nil).CTDone().
				Done(),
		)
	}

	return flows
}

func (f *featureExternalNodeConnectivity) replayFlows() []binding.Flow {
	var flows []binding.Flow
	rangeFunc := func(key, value interface{}) bool {
		cachedFlows := value.([]binding.Flow)
		for _, flow := range cachedFlows {
			flow.Reset()
			flows = append(flows, flow)
		}
		return true
	}
	f.uplinkFlowCache.Range(rangeFunc)
	return flows
}

func (f *featureExternalNodeConnectivity) policyBypassFlow(protocol binding.Protocol, ipnet *net.IPNet, ip net.IP, port uint16, isIngress bool) binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flowBuilder binding.FlowBuilder
	var nextTable *Table
	if isIngress {
		flowBuilder = IngressSecurityClassifierTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(protocol).
			MatchCTStateNew(true).
			MatchCTStateTrk(true)
		if ipnet != nil {
			flowBuilder.MatchSrcIPNet(*ipnet)
		}
		if ip != nil {
			flowBuilder.MatchSrcIP(ip)
		}
		nextTable = IngressMetricTable
	} else {
		flowBuilder = EgressSecurityClassifierTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(protocol).
			MatchCTStateNew(true).
			MatchCTStateTrk(true)
		if ipnet != nil {
			flowBuilder.MatchDstIPNet(*ipnet)
		}
		if ip != nil {
			flowBuilder.MatchDstIP(ip)
		}
		nextTable = EgressMetricTable
	}
	return flowBuilder.MatchDstPort(port, nil).
		Action().GotoTable(nextTable.ofTable.GetID()).
		Done()
}

func (f *featureExternalNodeConnectivity) addPolicyBypassFlows(flow binding.Flow) error {
	var allFlows []binding.Flow
	obj, ok := f.uplinkFlowCache.Load(policyBypassFlowsKey)
	if !ok {
		allFlows = []binding.Flow{flow}
	} else {
		existingFlows := obj.([]binding.Flow)
		allFlows = append(existingFlows, flow)
	}
	f.uplinkFlowCache.Store(policyBypassFlowsKey, allFlows)
	return nil
}

func (c *client) InstallVMUplinkFlows(hostIFName string, hostPort int32, uplinkPort int32) error {
	flows := c.featureExternalNodeConnectivity.vmUplinkFlows(uint32(hostPort), uint32(uplinkPort))
	return c.addFlows(c.featureExternalNodeConnectivity.uplinkFlowCache, hostIFName, flows)
}

func (c *client) UninstallVMUplinkFlows(hostIFName string) error {
	return c.deleteFlows(c.featureExternalNodeConnectivity.uplinkFlowCache, hostIFName)
}

func (c *client) InstallPolicyBypassFlows(protocol binding.Protocol, ipnet *net.IPNet, ip net.IP, port uint16, isIngress bool) error {
	flow := c.featureExternalNodeConnectivity.policyBypassFlow(protocol, ipnet, ip, port, isIngress)
	if err := c.ofEntryOperations.Add(flow); err != nil {
		return err
	}
	return c.featureExternalNodeConnectivity.addPolicyBypassFlows(flow)
}

// nonIPPipelineClassifyFlow generates a flow in PipelineClassifierTable to resubmit packets not using IP protocols to
// pipelineNonIP.
func nonIPPipelineClassifyFlow(cookieID uint64, pipeline binding.Pipeline) binding.Flow {
	targetTable := pipeline.GetFirstTable()
	return PipelineRootClassifierTable.ofTable.BuildFlow(priorityLow).
		Cookie(cookieID).
		Action().GotoTable(targetTable.GetID()).
		Done()
}
