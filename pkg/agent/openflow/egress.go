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

	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featureEgress struct {
	cookieAllocator cookie.Allocator

	snatFlowCache       *flowCategoryCache
	hostNetworkingFlows []binding.Flow

	enableProxy bool
}

func (c *featureEgress) getFeatureID() featureID {
	return Egress
}

func newFeatureEgress(cookieAllocator cookie.Allocator, enableProxy bool) feature {
	return &featureEgress{
		snatFlowCache:   newFlowCategoryCache(),
		cookieAllocator: cookieAllocator,
		enableProxy:     enableProxy,
	}
}

// Stage: RoutingStage
// Tables: L3ForwardingTable
// Stage: PostRoutingStage
// Tables: SNATTable
// Refactored from:
//   - `func (c *client) externalFlows(nodeIP net.IP, localSubnet net.IPNet, localGatewayMAC net.HardwareAddr,
//     exceptCIDRs []net.IPNet) []binding.Flow`
// externalFlows installs the default flows for performing SNAT for traffic to the external network. The flows identify
// the packets to external, and send them to SNATTable, where SNAT IPs are looked up for the packets.
func (c *featureEgress) externalFlows(
	category cookie.Category,
	nodeIP net.IP,
	localSubnet net.IPNet,
	localGatewayMAC net.HardwareAddr,
	exceptCIDRs []net.IPNet) []binding.Flow {
	ipProtocol := getIPProtocol(localSubnet.IP)
	flows := []binding.Flow{
		// First install flows for traffic that should bypass SNAT.
		// This flow is for traffic to the local Pod subnet that don't need MAC rewriting (L2 forwarding case). Other
		// traffic to the local Pod subnet will be handled by L3 forwarding rules.
		L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchRegFieldWithValue(RewriteMACRegMark.GetField(), 0).
			MatchDstIPNet(localSubnet).
			Action().GotoStage(binding.SwitchingStage).
			Done(),
		// This flow is for the traffic to the local Node IP.
		L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchRegMark(FromLocalRegMark).
			MatchDstIP(nodeIP).
			Action().GotoStage(binding.PostRoutingStage).
			Done(),
		// The return traffic of connections to a local Pod through the gateway interface (so FromGatewayCTMark is set)
		// should bypass SNAT too. But it has been covered by the gatewayCT related flow generated in l3FwdFlowToGateway
		// which forwards all reply traffic for such connections back to the gateway interface with the high priority.

		// Send the traffic to external to SNATTable.
		L3ForwardingTable.ofTable.BuildFlow(priorityLow).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchRegMark(FromLocalRegMark).
			Action().GotoStage(binding.PostRoutingStage).
			Done(),
		// For the traffic tunneled from remote Nodes, rewrite the destination MAC to the gateway interface MAC.
		L3ForwardingTable.ofTable.BuildFlow(priorityLow).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchRegMark(FromTunnelRegMark).
			Action().SetDstMAC(localGatewayMAC).
			Action().GotoStage(binding.PostRoutingStage).
			Done(),

		// Drop the traffic from remote Nodes if no matched SNAT policy.
		SNATTable.ofTable.BuildFlow(priorityLow).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(true).
			MatchCTStateTrk(true).
			MatchRegMark(FromTunnelRegMark).
			Action().Drop().
			Done(),
	}
	for _, cidr := range exceptCIDRs {
		flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
			MatchProtocol(ipProtocol).
			MatchRegMark(FromLocalRegMark).
			MatchDstIPNet(cidr).
			Action().NextTable().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

// Stage: PostRoutingStage
// Tables: SNATTable
// Refactored from:
//   - `func (c *client) snatIPFromTunnelFlow(snatIP net.IP, mark uint32) binding.Flow`
// snatIPFromTunnelFlow generates a flow that marks SNAT packets tunnelled from remote Nodes. The SNAT IP matches the
// packet's tunnel destination IP.
func (c *featureEgress) snatIPFromTunnelFlow(category cookie.Category, snatIP net.IP, mark uint32) binding.Flow {
	ipProtocol := getIPProtocol(snatIP)
	return SNATTable.ofTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchProtocol(ipProtocol).
		MatchCTStateNew(true).
		MatchCTStateTrk(true).
		MatchTunnelDst(snatIP).
		Action().LoadPktMarkRange(mark, snatPktMarkRange).
		Action().DecTTL().
		Action().GotoStage(binding.SwitchingStage).
		Done()
}

// Stage: PostRoutingStage
// Tables: SNATTable
// Refactored from:
//   - `func (c *client) snatRuleFlow(ofPort uint32, snatIP net.IP, snatMark uint32, localGatewayMAC net.HardwareAddr) binding.Flow`
// snatRuleFlow generates a flow that applies the SNAT rule for a local Pod. If the SNAT IP exists on the local Node,
// it sets the packet mark with the ID of the SNAT IP, for the traffic from the ofPort to external; if the SNAT IP is
// on a remote Node, it tunnels the packets to the SNAT IP.
func (c *featureEgress) snatRuleFlow(category cookie.Category,
	ofPort uint32,
	snatIP net.IP,
	snatMark uint32,
	localGatewayMAC net.HardwareAddr) binding.Flow {
	ipProtocol := getIPProtocol(snatIP)
	if snatMark != 0 {
		// Local SNAT IP.
		return SNATTable.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(true).
			MatchCTStateTrk(true).
			MatchInPort(ofPort).
			Action().LoadPktMarkRange(snatMark, snatPktMarkRange).
			Action().GotoStage(binding.SwitchingStage).
			Done()
	}
	// SNAT IP should be on a remote Node.
	return SNATTable.ofTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchProtocol(ipProtocol).
		MatchInPort(ofPort).
		Action().SetSrcMAC(localGatewayMAC).
		Action().SetDstMAC(GlobalVirtualMAC).
		Action().SetTunnelDst(snatIP). // Set tunnel destination to the SNAT IP.
		Action().DecTTL().
		Action().GotoStage(binding.SwitchingStage).
		Done()
}

// Stage: PostRoutingStage
// Tables: SNATTable
// Refactored from:
//   - `func (c *client) snatRuleFlow(ofPort uint32, snatIP net.IP, snatMark uint32, localGatewayMAC net.HardwareAddr) binding.Flow`
// snatSkipNodeFlow installs a flow to skip SNAT for traffic to the transport IP of the a remote Node.
func (c *featureEgress) snatSkipNodeFlow(category cookie.Category, nodeIP net.IP) binding.Flow {
	ipProtocol := getIPProtocol(nodeIP)
	// This flow is for the traffic to the remote Node IP.
	return L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchProtocol(ipProtocol).
		MatchRegMark(FromLocalRegMark).
		MatchDstIP(nodeIP).
		Action().NextTable().
		Done()
}
