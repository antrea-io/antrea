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

// hostBridgeUplinkFlows generates the flows that forward traffic between the
// bridge local port and the uplink port to support the host traffic with
// outside.
func (c *client) hostBridgeUplinkFlows(localSubnetMap map[binding.Protocol]net.IPNet, category cookie.Category) (flows []binding.Flow) {
	flows = []binding.Flow{
		ClassifierTable.BuildFlow(priorityNormal).
			MatchInPort(config.UplinkOFPort).
			Action().Output(config.BridgeOFPort).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		ClassifierTable.BuildFlow(priorityNormal).
			MatchInPort(config.BridgeOFPort).
			Action().Output(config.UplinkOFPort).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	}
	if c.networkConfig.TrafficEncapMode.SupportsNoEncap() {
		// If NoEncap is enabled, the reply packets from remote Pod can be forwarded to local Pod directly.
		// by explicitly resubmitting them to ServiceHairpinTable and marking "macRewriteMark" at same time.
		for ipProtocol, localSubnet := range localSubnetMap {
			flows = append(flows, ClassifierTable.BuildFlow(priorityHigh).
				MatchProtocol(ipProtocol).
				MatchInPort(config.UplinkOFPort).
				MatchDstIPNet(localSubnet).
				Action().LoadRegMark(FromUplinkRegMark).
				Action().LoadRegMark(RewriteMACRegMark).
				Action().GotoTable(ServiceHairpinTable.GetID()).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done())
		}
	}
	return flows
}

func (c *client) l3FwdFlowToRemoteViaRouting(localGatewayMAC net.HardwareAddr, remoteGatewayMAC net.HardwareAddr,
	category cookie.Category, peerIP net.IP, peerPodCIDR *net.IPNet) []binding.Flow {
	if c.networkConfig.NeedsDirectRoutingToPeer(peerIP, c.nodeConfig.NodeTransportIPv4Addr) && remoteGatewayMAC != nil {
		ipProto := getIPProtocol(peerIP)
		// It enhances Windows Noencap mode performance by bypassing host network.
		flows := []binding.Flow{L2ForwardingCalcTable.BuildFlow(priorityNormal).
			MatchDstMAC(remoteGatewayMAC).
			Action().LoadToRegField(TargetOFPortField, config.UplinkOFPort).
			Action().LoadRegMark(OFPortFoundRegMark).
			Action().GotoTable(ConntrackCommitTable.GetID()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
			// Output the reply packet to the uplink interface if the destination is another Node's IP.
			// This is for the scenario that another Node directly accesses Pods on this Node. Since the request
			// packet enters OVS from the uplink interface, the reply should go back in the same path. Otherwise,
			// Windows host will perform stateless SNAT on the reply, and the packets are possibly dropped on peer
			// Node because of the wrong source address.
			L3ForwardingTable.BuildFlow(priorityNormal).MatchProtocol(ipProto).
				MatchDstIP(peerIP).
				MatchCTStateRpl(true).MatchCTStateTrk(true).
				Action().SetDstMAC(remoteGatewayMAC).
				Action().GotoTable(L3ForwardingTable.GetNext()).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
		}
		flows = append(flows, c.l3FwdFlowToRemoteViaGW(remoteGatewayMAC, *peerPodCIDR, category, false))
		return flows
	}
	return []binding.Flow{c.l3FwdFlowToRemoteViaGW(localGatewayMAC, *peerPodCIDR, category, false)}
}
