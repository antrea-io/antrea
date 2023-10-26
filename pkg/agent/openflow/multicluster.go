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

	"antrea.io/libOpenflow/openflow15"

	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

// GlobalVirtualMACForMulticluster is a vritual MAC which will be used only
// for cross-cluster traffic to distinguish from in-cluster traffic.
var GlobalVirtualMACForMulticluster, _ = net.ParseMAC("aa:bb:cc:dd:ee:f0")

// UnknownLabelIdentity represents an unknown label identity.
// 24 bits in VNI are used for label identity. The max value is reserved for
// UnknownLabelIdentity.
const UnknownLabelIdentity = uint32(0xffffff)

type featureMulticluster struct {
	cookieAllocator cookie.Allocator
	cachedFlows     *flowCategoryCache
	cachedPodFlows  *flowCategoryCache
	category        cookie.Category
	ipProtocols     []binding.Protocol
	dnatCtZones     map[binding.Protocol]int
	snatCtZones     map[binding.Protocol]int
}

func (f *featureMulticluster) getFeatureName() string {
	return "Multicluster"
}

func newFeatureMulticluster(cookieAllocator cookie.Allocator, ipProtocols []binding.Protocol) *featureMulticluster {
	snatCtZones := make(map[binding.Protocol]int)
	dnatCtZones := make(map[binding.Protocol]int)
	snatCtZones[ipProtocols[0]] = SNATCtZone
	dnatCtZones[ipProtocols[0]] = CtZone
	return &featureMulticluster{
		cookieAllocator: cookieAllocator,
		cachedFlows:     newFlowCategoryCache(),
		cachedPodFlows:  newFlowCategoryCache(),
		category:        cookie.Multicluster,
		ipProtocols:     ipProtocols,
		snatCtZones:     snatCtZones,
		dnatCtZones:     dnatCtZones,
	}
}

func (f *featureMulticluster) initFlows() []*openflow15.FlowMod {
	return []*openflow15.FlowMod{}
}

func (f *featureMulticluster) replayFlows() []*openflow15.FlowMod {
	return getCachedFlowMessages(f.cachedFlows)
}

func (f *featureMulticluster) initGroups() []binding.OFEntry {
	return nil
}

func (f *featureMulticluster) replayGroups() []binding.OFEntry {
	return nil
}

func (f *featureMulticluster) replayMeters() []binding.OFEntry {
	return nil
}

func (f *featureMulticluster) l3FwdFlowToRemoteGateway(
	localGatewayMAC net.HardwareAddr,
	peerServiceCIDR net.IPNet,
	tunnelPeer net.IP,
	remoteGatewayIP net.IP,
	enableStretchedNetworkPolicy bool) []binding.Flow {
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
			Action().SetSrcMAC(localGatewayMAC).                 // Rewrite src MAC to local gateway MAC.
			Action().SetDstMAC(GlobalVirtualMACForMulticluster). // Rewrite dst MAC to virtual MC MAC.
			Action().SetTunnelDst(tunnelPeer).                   // Flow based tunnel. Set tunnel destination.
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
	if enableStretchedNetworkPolicy {
		flows = append(flows,
			// This generates the flow to forward cross-cluster reject traffic based
			// on Gateway IP and reg.
			L3ForwardingTable.ofTable.BuildFlow(priorityNormal-1).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegMark(GeneratedRejectPacketOutRegMark).
				MatchDstIP(remoteGatewayIP).
				Action().SetSrcMAC(localGatewayMAC).
				Action().SetDstMAC(GlobalVirtualMACForMulticluster).
				Action().SetTunnelDst(tunnelPeer). // Flow based tunnel. Set tunnel destination.
				Action().LoadRegMark(ToTunnelRegMark).
				Action().GotoTable(L3DecTTLTable.GetID()).
				Done(),
		)
	}
	return flows
}

func (f *featureMulticluster) tunnelClassifierFlow(tunnelOFPort uint32) binding.Flow {
	return ClassifierTable.ofTable.BuildFlow(priorityHigh).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchInPort(tunnelOFPort).
		MatchDstMAC(GlobalVirtualMACForMulticluster).
		Action().LoadRegMark(FromTunnelRegMark).
		Action().LoadRegMark(RewriteMACRegMark).
		Action().GotoStage(stageConntrackState).
		Done()
}

func (f *featureMulticluster) outputHairpinTunnelFlow(tunnelOFPort uint32) binding.Flow {
	return OutputTable.ofTable.BuildFlow(priorityHigh).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchRegFieldWithValue(TargetOFPortField, tunnelOFPort).
		MatchInPort(tunnelOFPort).
		Action().OutputInPort().
		Done()
}

// snatConntrackFlows generates flows on a multi-cluster Gateway Node to perform SNAT for cross-cluster connections.
func (f *featureMulticluster) snatConntrackFlows(serviceCIDR net.IPNet, localGatewayIP net.IP) []binding.Flow {
	var flows []binding.Flow
	ipProtocol := getIPProtocol(localGatewayIP)
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	flows = append(flows,
		// This generates the flow to match the first packet of multi-cluster Service connection, and commit them into
		// DNAT zone to make sure DNAT is performed before SNAT for any remote cluster traffic.
		SNATMarkTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchDstIPNet(serviceCIDR).
			MatchCTStateNew(true).
			MatchCTStateTrk(true).
			Action().CT(true, SNATMarkTable.GetNext(), f.dnatCtZones[ipProtocol], nil).
			LoadToCtMark(ConnSNATCTMark).
			CTDone().
			Done(),
		// This generates the flow to perform SNAT for the cross-cluster Service connections.
		SNATTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(true).
			MatchCTStateTrk(true).
			MatchDstIPNet(serviceCIDR).
			Action().CT(true, SNATTable.GetNext(), f.snatCtZones[ipProtocol], nil).
			SNAT(&binding.IPRange{StartIP: localGatewayIP, EndIP: localGatewayIP}, nil).
			CTDone().
			Done(),
		// This generates the flow to unSNAT reply packets of connections committed in SNAT CT zone by the above flows.
		UnSNATTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchDstIP(localGatewayIP).
			Action().CT(false, UnSNATTable.GetNext(), f.snatCtZones[ipProtocol], nil).
			NAT().
			CTDone().
			Done(),
	)
	return flows
}

func (f *featureMulticluster) l3FwdFlowToPodViaTun(
	localGatewayMAC net.HardwareAddr,
	podIP net.IP,
	tunnelPeer net.IP) binding.Flow {
	ipProtocol := getIPProtocol(podIP)
	// This generates the flow to forward cross-cluster request packets based
	// on Pod IP.
	return L3ForwardingTable.ofTable.BuildFlow(priorityHigh).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(ipProtocol).
		MatchDstIP(podIP).
		MatchDstMAC(GlobalVirtualMACForMulticluster).
		Action().SetSrcMAC(localGatewayMAC). // Rewrite src MAC to local gateway MAC.
		Action().SetTunnelDst(tunnelPeer).   // Flow based tunnel. Set tunnel destination.
		Action().LoadRegMark(ToTunnelRegMark).
		Action().GotoTable(L3DecTTLTable.GetID()).
		Done()
}
