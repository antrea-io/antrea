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
	"antrea.io/antrea/pkg/agent/types"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

const (
	// ctZoneSNAT is only used on Windows and only when AntreaProxy is enabled.
	// When a Pod access a ClusterIP Service, and the IP of the selected endpoint
	// is not in "cluster-cidr". The request packets need to be SNAT'd(set src IP to local Node IP)
	// after have been DNAT'd(set dst IP to endpoint IP).
	// For example, the endpoint Pod may run in hostNetwork mode and the IP of the endpoint
	// will be the current Node IP.
	// We need to use a different ct_zone to track the SNAT'd connection because OVS
	// does not support doing both DNAT and SNAT in the same ct_zone.
	//
	// An example of the connection is a Pod accesses kubernetes API service:
	// Pod --> DNAT(CtZone) --> SNAT(ctZoneSNAT) --> Endpoint(API server NodeIP)
	// Pod <-- unDNAT(CtZone) <-- unSNAT(ctZoneSNAT) <-- Endpoint(API server NodeIP)
	ctZoneSNAT = 0xffdc
)

var (
	// snatCTMark indicates SNAT is performed for packets of the connection.
	snatCTMark = binding.NewCTMark(0x40, 0, 31)
)

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
			LoadToCtMark(snatCTMark).CTDone().
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
			LoadToCtMark(snatCTMark).CTDone().
			Cookie(c.cookieAllocator.Request(cookie.SNAT).Raw()).
			Done())
	}
	return flows
}

// hostBridgeUplinkFlows generates the flows that forward traffic between the
// bridge local port and the uplink port to support the host traffic with
// outside.
func (c *client) hostBridgeUplinkFlows(localSubnet net.IPNet, category cookie.Category) (flows []binding.Flow) {
	flows = []binding.Flow{
		c.pipeline[ClassifierTable].BuildFlow(priorityNormal).
			MatchInPort(config.UplinkOFPort).
			Action().Output(config.BridgeOFPort).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		c.pipeline[ClassifierTable].BuildFlow(priorityNormal).
			MatchInPort(config.BridgeOFPort).
			Action().Output(config.UplinkOFPort).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	}
	if c.networkConfig.TrafficEncapMode.SupportsNoEncap() {
		// If NoEncap is enabled, the reply packets from remote Pod can be forwarded to local Pod directly.
		// by explicitly resubmitting them to serviceHairpinTable and marking "macRewriteMark" at same time.
		flows = append(flows, c.pipeline[ClassifierTable].BuildFlow(priorityHigh).MatchProtocol(binding.ProtocolIP).
			MatchInPort(config.UplinkOFPort).
			MatchDstIPNet(localSubnet).
			Action().LoadRegMark(FromUplinkRegMark).
			Action().LoadRegMark(RewriteMACRegMark).
			Action().GotoTable(serviceHairpinTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

func (c *client) l3FwdFlowToRemoteViaRouting(localGatewayMAC net.HardwareAddr, remoteGatewayMAC net.HardwareAddr,
	category cookie.Category, peerIP net.IP, peerPodCIDR *net.IPNet) []binding.Flow {
	if c.networkConfig.NeedsDirectRoutingToPeer(peerIP, c.nodeConfig.NodeTransportIPv4Addr) && remoteGatewayMAC != nil {
		ipProto := getIPProtocol(peerIP)
		l3FwdTable := c.pipeline[l3ForwardingTable]
		// It enhances Windows Noencap mode performance by bypassing host network.
		flows := []binding.Flow{c.pipeline[l2ForwardingCalcTable].BuildFlow(priorityNormal).
			MatchDstMAC(remoteGatewayMAC).
			Action().LoadToRegField(TargetOFPortField, config.UplinkOFPort).
			Action().LoadRegMark(OFPortFoundRegMark).
			Action().GotoTable(conntrackCommitTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
			// Output the reply packet to the uplink interface if the destination is another Node's IP.
			// This is for the scenario that another Node directly accesses Pods on this Node. Since the request
			// packet enters OVS from the uplink interface, the reply should go back in the same path. Otherwise,
			// Windows host will perform stateless SNAT on the reply, and the packets are possibly dropped on peer
			// Node because of the wrong source address.
			l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(ipProto).
				MatchDstIP(peerIP).
				MatchCTStateRpl(true).MatchCTStateTrk(true).
				Action().SetDstMAC(remoteGatewayMAC).
				Action().GotoTable(l3FwdTable.GetNext()).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
		}
		flows = append(flows, c.l3FwdFlowToRemoteViaGW(remoteGatewayMAC, *peerPodCIDR, category))
		return flows
	}
	return []binding.Flow{c.l3FwdFlowToRemoteViaGW(localGatewayMAC, *peerPodCIDR, category)}
}
