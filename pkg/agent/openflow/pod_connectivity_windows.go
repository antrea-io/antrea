//go:build windows
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
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

// Stage: ClassifierStage
// Tables: ClassifierTable
// Refactored from:
//   - `func (c *client) hostBridgeUplinkFlows(localSubnet net.IPNet, category cookie.Category) (flows []binding.Flow)`
// hostBridgeUplinkFlows generates the flows that forward traffic between the bridge local port and the uplink port to
// support the host traffic with outside.
func (c *featurePodConnectivity) hostBridgeUplinkFlows(category cookie.Category, localSubnet net.IPNet) (flows []binding.Flow) {
	flows = []binding.Flow{
		ClassifierTable.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchInPort(config.UplinkOFPort).
			Action().Output(config.BridgeOFPort).
			Done(),
		ClassifierTable.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchInPort(config.BridgeOFPort).
			Action().Output(config.UplinkOFPort).
			Done(),
	}

	if c.networkConfig.TrafficEncapMode.SupportsNoEncap() {
		// If NoEncap is enabled, the reply packets from remote Pod can be forwarded to local Pod directly.
		// by explicitly resubmitting them to ServiceHairpinTable and marking "macRewriteMark" at same time.
		flows = append(flows, ClassifierTable.ofTable.BuildFlow(priorityHigh).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(binding.ProtocolIP).
			MatchInPort(config.UplinkOFPort).
			MatchDstIPNet(localSubnet).
			Action().LoadRegMark(FromUplinkRegMark).
			Action().LoadRegMark(RewriteMACRegMark).
			Action().GotoStage(binding.ConntrackStateStage).
			Done())
	}
	return flows
}

// Stage: RoutingStage
// Tables: L3ForwardingTable
// Stage: SwitchingStage
// Tables: L3ForwardingTable, L2ForwardingCalcTable
// Refactored from:
//   - `func (c *client) l3FwdFlowToRemoteViaRouting(localGatewayMAC net.HardwareAddr, remoteGatewayMAC net.HardwareAddr,
//	    category cookie.Category, peerIP net.IP, peerPodCIDR *net.IPNet) []binding.Flow`
func (c *featurePodConnectivity) l3FwdFlowToRemoteViaRouting(
	category cookie.Category,
	localGatewayMAC net.HardwareAddr,
	remoteGatewayMAC net.HardwareAddr,
	peerIP net.IP,
	peerPodCIDR *net.IPNet) []binding.Flow {
	flows := []binding.Flow{c.l3FwdFlowToRemoteViaGW(category, localGatewayMAC, *peerPodCIDR, false)}

	if c.networkConfig.NeedsDirectRoutingToPeer(peerIP, c.nodeConfig.NodeTransportIPv4Addr) && remoteGatewayMAC != nil {
		ipProtocol := getIPProtocol(peerIP)
		// It enhances Windows Noencap mode performance by bypassing host network.
		flows = append(flows,
			// Output the reply packet to the uplink interface if the destination is another Node's IP.
			// This is for the scenario that another Node directly accesses Pods on this Node. Since the request
			// packet enters OVS from the uplink interface, the reply should go back in the same path. Otherwise,
			// Windows host will perform stateless SNAT on the reply, and the packets are possibly dropped on peer
			// Node because of the wrong source address.
			L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchDstIP(peerIP).
				MatchCTStateRpl(true).
				MatchCTStateTrk(true).
				Action().SetDstMAC(remoteGatewayMAC).
				Action().LoadRegMark(ToUplinkRegMark).
				Action().NextTable().
				Done(),
			L2ForwardingCalcTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchDstMAC(remoteGatewayMAC).
				Action().LoadToRegField(TargetOFPortField, config.UplinkOFPort).
				Action().LoadRegMark(OFPortFoundRegMark).
				Action().GotoStage(binding.ConntrackStage).
				Done(),
		)
	}
	return flows
}
