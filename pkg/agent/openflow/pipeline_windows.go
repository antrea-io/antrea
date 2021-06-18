// +build windows

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

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	"antrea.io/antrea/pkg/agent/types"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

const (
	markTrafficFromBridge = 5

	// ctZoneSNAT is only used on Windows and only when AntreaProxy is enabled.
	// When a Pod access a ClusterIP Service, and the IP of the selected endpoint
	// is not in "cluster-cidr". The request packets need to be SNAT'd(set src IP to local Node IP)
	// after have been DNAT'd(set dst IP to endpoint IP).
	// For example, the endpoint Pod may run in hostNetwork mode and the IP of the endpoint
	// will is the current Node IP.
	// We need to use a different ct_zone to track the SNAT'd connection because OVS
	// does not support doing both DNAT and SNAT in the same ct_zone.
	//
	// An example of the connection is a Pod accesses kubernetes API service:
	// Pod --> DNAT(CtZone) --> SNAT(ctZoneSNAT) --> Endpoint(API server NodeIP)
	// Pod <-- unDNAT(CtZone) <-- unSNAT(ctZoneSNAT) <-- Endpoint(API server NodeIP)
	ctZoneSNAT = 0xffdc

	// snatDefaultMark indicates the packet should be SNAT'd with the default
	// SNAT IP (the Node IP).
	snatDefaultMark = 0b1

	// snatCTMark indicates SNAT is performed for packets of the connection.
	snatCTMark = 0x40
)

var (
	// snatMarkRange takes the 17th bit of register marksReg to indicate if
	// the packet needs to be SNATed with Node's IP or not.
	snatMarkRange = binding.Range{17, 17}
)

// uplinkSNATFlows installs flows for traffic from the uplink port that help
// the SNAT implementation of the external traffic.
func (c *client) uplinkSNATFlows(localSubnet net.IPNet, category cookie.Category) []binding.Flow {
	ctStateNext := dnatTable
	if c.enableProxy {
		ctStateNext = endpointDNATTable
	}
	bridgeOFPort := uint32(config.BridgeOFPort)
	flows := []binding.Flow{
		// Mark the packet to indicate its destination MAC should be
		// rewritten to the real MAC in the L3Forwarding table, if the
		// packet is a reply to a local Pod from an external address.
		c.pipeline[conntrackStateTable].BuildFlow(priorityHigh).
			MatchProtocol(binding.ProtocolIP).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			MatchCTMark(snatCTMark, nil).
			MatchRegRange(int(marksReg), markTrafficFromUplink, binding.Range{0, 15}).
			Action().LoadRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Action().GotoTable(ctStateNext).
			Done(),
		// Output the non-SNAT packet to the bridge interface directly
		// if it is received from the uplink interface.
		c.pipeline[conntrackStateTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromUplink, binding.Range{0, 15}).
			Action().Output(int(bridgeOFPort)).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	}
	// Forward the IP packets from the uplink interface to
	// conntrackTable. This is for unSNAT the traffic from the local
	// Pod subnet to the external network. Non-SNAT packets will be
	// output to the bridge port in conntrackStateTable.
	if c.enableProxy {
		// For the connection which is both applied DNAT and SNAT, the reply packtets
		// are received from uplink and need to enter ctZoneSNAT first to do unSNAT.
		//   Pod --> DNAT(CtZone) --> SNAT(ctZoneSNAT) --> ExternalServer
		//   Pod <-- unDNAT(CtZone) <-- unSNAT(ctZoneSNAT) <-- ExternalServer
		flows = append(flows, c.pipeline[uplinkTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromUplink, binding.Range{0, 15}).
			Action().CT(false, conntrackTable, ctZoneSNAT).NAT().CTDone().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	} else {
		flows = append(flows, c.pipeline[uplinkTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromUplink, binding.Range{0, 15}).
			Action().GotoTable(conntrackTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

// snatImplementationFlows installs flows that implement SNAT with OVS NAT.
func (c *client) snatImplementationFlows(nodeIP net.IP, category cookie.Category) []binding.Flow {
	snatIPRange := &binding.IPRange{StartIP: nodeIP, EndIP: nodeIP}
	l3FwdTable := c.pipeline[l3ForwardingTable]
	nextTable := l3FwdTable.GetNext()
	ctCommitTable := c.pipeline[conntrackCommitTable]
	ccNextTable := ctCommitTable.GetNext()
	flows := []binding.Flow{
		// Default to using Node IP as the SNAT IP for local Pods.
		c.pipeline[snatTable].BuildFlow(priorityLow).
			MatchProtocol(binding.ProtocolIP).
			MatchCTStateNew(true).MatchCTStateTrk(true).
			MatchRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
			Action().LoadRegRange(int(marksReg), snatDefaultMark, snatMarkRange).
			Action().GotoTable(nextTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Force IP packet into the conntrack zone with SNAT. If the connection is SNATed, the reply packet should use
		// Pod IP as the destination, and then is forwarded to conntrackStateTable.
		c.pipeline[conntrackTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Action().CT(false, conntrackStateTable, CtZone).NAT().CTDone().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Perform SNAT with the default SNAT IP (the Node IP). A SNAT
		// packet has these characteristics: 1) the ct_state is
		// "+new+trk", 2) reg0[17] is set to 1; 3) ct_mark is set to
		// 0x40.
		ctCommitTable.BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchCTStateNew(true).MatchCTStateTrk(true).MatchCTStateDNAT(false).
			MatchRegRange(int(marksReg), snatDefaultMark, snatMarkRange).
			Action().CT(true, ccNextTable, CtZone).
			SNAT(snatIPRange, nil).
			LoadToMark(snatCTMark).CTDone().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	}
	// The following flows are for both apply DNAT + SNAT for packets.
	// If AntreaProxy is disabled, no DNAT happens in OVS pipeline.
	if c.enableProxy {
		flows = append(flows, []binding.Flow{
			// If the SNAT is needed after DNAT, mark the
			// snatDefaultMark even the connection is not new,
			// because this kind of packets need to enter ctZoneSNAT
			// to make sure the SNAT can be applied before leaving
			// the pipeline.
			l3FwdTable.BuildFlow(priorityLow).
				MatchProtocol(binding.ProtocolIP).
				MatchCTStateNew(false).MatchCTStateTrk(true).MatchCTStateDNAT(true).
				MatchRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
				Action().LoadRegRange(int(marksReg), snatDefaultMark, snatMarkRange).
				Action().GotoTable(nextTable).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
			// If SNAT is needed after DNAT:
			//   - For new connection: commit to ctZoneSNAT
			//   - For existing connection: enter ctZoneSNAT to apply SNAT
			ctCommitTable.BuildFlow(priorityNormal).
				MatchProtocol(binding.ProtocolIP).
				MatchCTStateNew(true).MatchCTStateTrk(true).MatchCTStateDNAT(true).
				MatchRegRange(int(marksReg), snatDefaultMark, snatMarkRange).
				Action().CT(true, ccNextTable, ctZoneSNAT).
				SNAT(snatIPRange, nil).
				LoadToMark(snatCTMark).CTDone().
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
			ctCommitTable.BuildFlow(priorityNormal).
				MatchProtocol(binding.ProtocolIP).
				MatchCTStateNew(false).MatchCTStateTrk(true).MatchCTStateDNAT(true).
				MatchRegRange(int(marksReg), snatDefaultMark, snatMarkRange).
				Action().CT(false, ccNextTable, ctZoneSNAT).NAT().CTDone().
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
		}...)
	}
	return flows
}

// externalFlows returns the flows needed to enable SNAT for external traffic.
func (c *client) externalFlows(nodeIP net.IP, localSubnet net.IPNet, localGatewayMAC net.HardwareAddr) []binding.Flow {
	flows := c.snatCommonFlows(nodeIP, localSubnet, localGatewayMAC, cookie.SNAT)
	flows = append(flows, c.uplinkSNATFlows(localSubnet, cookie.SNAT)...)
	flows = append(flows, c.snatImplementationFlows(nodeIP, cookie.SNAT)...)
	return flows
}

func (c *client) snatMarkFlows(snatIP net.IP, mark uint32) []binding.Flow {
	snatIPRange := &binding.IPRange{StartIP: snatIP, EndIP: snatIP}
	ctCommitTable := c.pipeline[conntrackCommitTable]
	nextTable := ctCommitTable.GetNext()
	flows := []binding.Flow{
		c.snatIPFromTunnelFlow(snatIP, mark),
		ctCommitTable.BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchCTStateNew(true).MatchCTStateTrk(true).MatchCTStateDNAT(false).
			MatchPktMark(mark, &types.SNATIPMarkMask).
			Action().CT(true, nextTable, CtZone).
			SNAT(snatIPRange, nil).
			LoadToMark(snatCTMark).CTDone().
			Cookie(c.cookieAllocator.Request(cookie.SNAT).Raw()).
			Done(),
	}

	if c.enableProxy {
		flows = append(flows, ctCommitTable.BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchCTStateNew(true).MatchCTStateTrk(true).MatchCTStateDNAT(true).
			MatchPktMark(mark, &types.SNATIPMarkMask).
			Action().CT(true, nextTable, ctZoneSNAT).
			SNAT(snatIPRange, nil).
			LoadToMark(snatCTMark).CTDone().
			Cookie(c.cookieAllocator.Request(cookie.SNAT).Raw()).
			Done())
	}
	return flows
}

// hostBridgeUplinkFlows generates the flows that forward traffic between the
// bridge local port and the uplink port to support the host traffic with
// outside.
func (c *client) hostBridgeUplinkFlows(localSubnet net.IPNet, category cookie.Category) (flows []binding.Flow) {
	bridgeOFPort := uint32(config.BridgeOFPort)
	flows = []binding.Flow{
		c.pipeline[ClassifierTable].BuildFlow(priorityNormal).
			MatchInPort(config.UplinkOFPort).
			Action().LoadRegRange(int(marksReg), markTrafficFromUplink, binding.Range{0, 15}).
			Action().GotoTable(uplinkTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		c.pipeline[ClassifierTable].BuildFlow(priorityNormal).
			MatchInPort(config.BridgeOFPort).
			Action().LoadRegRange(int(marksReg), markTrafficFromBridge, binding.Range{0, 15}).
			Action().GotoTable(uplinkTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Output non-IP packets to the bridge port directly. IP packets
		// are redirected to conntrackTable in uplinkSNATFlows() (in
		// case they need unSNAT).
		c.pipeline[uplinkTable].BuildFlow(priorityLow).
			MatchRegRange(int(marksReg), markTrafficFromUplink, binding.Range{0, 15}).
			Action().Output(int(bridgeOFPort)).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Forward the packet to conntrackTable if it enters the OVS
		// pipeline from the bridge interface and is sent to the local
		// Pod subnet. Mark the packet to indicate its destination MAC
		// should be rewritten to the real MAC in the L3Frowarding
		// table. This is for the case a Pod accesses a NodePort Service
		// using the local Node's IP, and then the return traffic after
		// the kube-proxy processing will enter the bridge from the
		// bridge interface (but not the gateway interface. This is
		// probably because we do not enable IP forwarding on the bridge
		// interface).
		c.pipeline[uplinkTable].BuildFlow(priorityHigh).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromBridge, binding.Range{0, 15}).
			MatchDstIPNet(localSubnet).
			Action().LoadRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
			Action().GotoTable(conntrackTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Output other packets from the bridge port to the uplink port
		// directly.
		c.pipeline[uplinkTable].BuildFlow(priorityLow).
			MatchRegRange(int(marksReg), markTrafficFromBridge, binding.Range{0, 15}).
			Action().Output(config.UplinkOFPort).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	}
	if c.encapMode.SupportsNoEncap() {
		// If NoEncap is enabled, the reply packets from remote Pod can be forwarded to local Pod directly.
		// by explicitly resubmitting them to endpointDNATTable and marking "macRewriteMark" at same time.
		flows = append(flows, c.pipeline[conntrackStateTable].BuildFlow(priorityHigh).MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromUplink, binding.Range{0, 15}).
			MatchDstIPNet(localSubnet).
			Action().LoadRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
			Action().GotoTable(endpointDNATTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

func (c *client) l3FwdFlowToRemoteViaRouting(localGatewayMAC net.HardwareAddr, remoteGatewayMAC net.HardwareAddr,
	category cookie.Category, peerIP net.IP, peerPodCIDR *net.IPNet) []binding.Flow {
	if !c.encapMode.NeedsRoutingToPeer(peerIP, c.nodeConfig.NodeIPAddr) && remoteGatewayMAC != nil {
		// It enhances Windows Noencap mode performance by bypassing host network.
		flows := []binding.Flow{c.pipeline[l2ForwardingCalcTable].BuildFlow(priorityNormal).
			MatchDstMAC(remoteGatewayMAC).
			Action().LoadRegRange(int(PortCacheReg), config.UplinkOFPort, ofPortRegRange).
			Action().LoadRegRange(int(marksReg), macRewriteMark, ofPortMarkRange).
			Action().GotoTable(conntrackCommitTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done()}
		flows = append(flows, c.l3FwdFlowToRemoteViaGW(remoteGatewayMAC, *peerPodCIDR, category))
		return flows
	}
	return []binding.Flow{c.l3FwdFlowToRemoteViaGW(localGatewayMAC, *peerPodCIDR, category)}
}
