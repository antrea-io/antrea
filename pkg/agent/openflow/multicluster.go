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

// GlobalVirtualMACForMulticluster is a vritual MAC which will be used only
// for cross-cluster traffic to distinguish in-cluster traffic.
var GlobalVirtualMACForMulticluster, _ = net.ParseMAC("aa:bb:cc:dd:ee:f0")

type featureMulticluster struct {
	cookieAllocator cookie.Allocator
	cachedFlows     *flowCategoryCache
	category        cookie.Category
	ipProtocols     []binding.Protocol
	snatCtZones     map[binding.Protocol]int
}

func (f *featureMulticluster) getFeatureName() string {
	return "Multicluster"
}

func newFeatureMulticluster(cookieAllocator cookie.Allocator, ipProtocols []binding.Protocol) *featureMulticluster {
	snatCtZones := make(map[binding.Protocol]int)
	snatCtZones[ipProtocols[0]] = MCSNATCtZone
	return &featureMulticluster{
		cookieAllocator: cookieAllocator,
		cachedFlows:     newFlowCategoryCache(),
		category:        cookie.Multicluster,
		ipProtocols:     ipProtocols,
		snatCtZones:     snatCtZones,
	}
}

func (f *featureMulticluster) initFlows() []binding.Flow {
	return []binding.Flow{}
}

func (f *featureMulticluster) replayFlows() []binding.Flow {
	return getCachedFlows(f.cachedFlows)
}

func (f *featureMulticluster) l3FwdFlowToGatewayNodeViaTun(
	localGatewayMAC net.HardwareAddr,
	peerServiceCIDR net.IPNet,
	tunnelPeer net.IP,
	remoteGatewayIP net.IP) []binding.Flow {
	ipProtocol := getIPProtocol(peerServiceCIDR.IP)
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	flows = append(flows,
		// This generates the flow to forward cross-cluster request packets based
		// on Service ClusterIP range.
		L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchDstIPNet(peerServiceCIDR).
			Action().SetSrcMAC(localGatewayMAC).  // Rewrite src MAC to local gateway MAC.
			Action().SetDstMAC(GlobalVirtualMAC). // Rewrite dst MAC to virtual MAC.
			Action().SetTunnelDst(tunnelPeer).    // Flow based tunnel. Set tunnel destination.
			Action().LoadRegMark(ToTunnelRegMark).
			Action().GotoTable(L3DecTTLTable.GetID()).
			Done(),
		// This generates the flow to forward cross-cluster reply traffic based
		// on Gateway IP.
		L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchCTStateRpl(true).
			MatchCTStateTrk(true).
			MatchDstIP(remoteGatewayIP).
			Action().SetSrcMAC(localGatewayMAC).
			Action().SetDstMAC(GlobalVirtualMACForMulticluster).
			Action().SetTunnelDst(tunnelPeer). // Flow based tunnel. Set tunnel destination.
			Action().LoadRegMark(ToTunnelRegMark).
			Action().GotoTable(L3DecTTLTable.GetID()).
			Done(),
	)
	return flows
}

func (f *featureMulticluster) l3FwdFlowToRemoteGatewayViaTun(
	localGatewayMAC net.HardwareAddr,
	peerServiceCIDR net.IPNet,
	tunnelPeer net.IP,
	remoteGatewayIP net.IP) []binding.Flow {
	ipProtocol := getIPProtocol(remoteGatewayIP)
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	flows = append(flows,
		// This generates the flow to forward cross-cluster request packets based
		// on Service ClusterIP range.
		L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchDstIPNet(peerServiceCIDR).
			Action().SetSrcMAC(localGatewayMAC).                 // Rewrite src MAC to local gateway MAC.
			Action().SetDstMAC(GlobalVirtualMACForMulticluster). // Rewrite dst MAC to virtual Multi-cluster MAC.
			Action().SetTunnelDst(tunnelPeer).                   // Flow based tunnel. Set tunnel destination.
			Action().LoadRegMark(ToTunnelRegMark).
			Action().GotoTable(L3DecTTLTable.GetID()).
			Done(),
		// This generates the flow to forward cross-cluster reply traffic based
		// on Gateway IP.
		L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchDstIP(remoteGatewayIP).
			MatchCTStateRpl(true).
			MatchCTStateTrk(true).
			Action().SetSrcMAC(localGatewayMAC).
			Action().SetDstMAC(GlobalVirtualMACForMulticluster).
			Action().SetTunnelDst(tunnelPeer). // Flow based tunnel. Set tunnel destination.
			Action().LoadRegMark(ToTunnelRegMark).
			Action().GotoTable(L3DecTTLTable.GetID()).
			Done(),
	)
	return flows
}

func (f *featureMulticluster) tunnelClassifierFlow(category cookie.Category, tunnelOFPort uint32) binding.Flow {
	return ClassifierTable.ofTable.BuildFlow(priorityHigh).
		Cookie(f.cookieAllocator.Request(category).Raw()).
		MatchInPort(tunnelOFPort).
		MatchDstMAC(GlobalVirtualMACForMulticluster).
		Action().LoadRegMark(FromTunnelRegMark).
		Action().LoadRegMark(RewriteMACRegMark).
		Action().GotoStage(stageConntrackState).
		Done()
}

func (f *featureMulticluster) outputFlow(category cookie.Category, tunnelOFPort uint32) binding.Flow {
	return L2ForwardingOutTable.ofTable.BuildFlow(priorityHigh).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchRegMark(RewriteMACRegMark).
		MatchRegMark(OutputToTunnelRegMark).
		MatchInPort(tunnelOFPort).
		Action().OutputInPort().
		Done()
}

func (f *featureMulticluster) snatConntrackFlows(serviceCIDR net.IPNet, localGatewayIP net.IP) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	ipProtocol := getIPProtocol(localGatewayIP)
	flows = append(flows,
		// This generates the flow to restore destination IP of reply packets of cross-cluster Service
		// connections committed in the SNAT CT zone
		SNATConntrackTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchDstIP(localGatewayIP).
			Action().CT(false, SNATConntrackTable.GetNext(), f.snatCtZones[ipProtocol], nil).
			NAT().
			CTDone().
			Done(),
		SNATConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchDstIPNet(serviceCIDR).
			Action().CT(true, SNATConntrackCommitTable.GetNext(), f.snatCtZones[ipProtocol], nil).
			MoveToCtMarkField(PktSourceField, ConnSourceCTMarkField).
			SNAT(&binding.IPRange{StartIP: localGatewayIP, EndIP: localGatewayIP}, nil).
			CTDone().
			Done(),
		ConntrackTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchSrcIPNet(serviceCIDR).
			MatchCTMark(FromTunnelCTMark).
			Action().GotoTable(PreRoutingClassifierTable.GetID()).
			Done(),
		ConntrackCommitTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchCTMark(FromTunnelCTMark).
			Action().GotoTable(L2ForwardingOutTable.GetID()).
			Done(),
	)
	return flows
}
