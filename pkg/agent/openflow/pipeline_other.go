//go:build !windows
// +build !windows

// package openflow is needed by antctl which is compiled for macOS too.

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

func (c *client) snatMarkFlows(snatIP net.IP, mark uint32) []binding.Flow {
	return []binding.Flow{c.snatIPFromTunnelFlow(snatIP, mark)}
}

// hostBridgeUplinkFlows generates the flows that forward traffic between the
// bridge local port and the uplink port to support the host traffic.
// TODO(gran): sync latest changes from pipeline_windows.go
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
	// Do not forward packet to per-Node IPAM Pod directly to avoid traffic issue.
	flows = append(flows,
		// Handle incoming ARP request for AntreaFlexibleIPAM Pods.
		c.pipeline[ClassifierTable].BuildFlow(priorityHigh).
			MatchInPort(config.UplinkOFPort).
			MatchProtocol(binding.ProtocolARP).
			Action().Normal().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		c.pipeline[ClassifierTable].BuildFlow(priorityHigh).
			MatchInPort(config.BridgeOFPort).
			MatchProtocol(binding.ProtocolARP).
			Action().Normal().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Handle packet to Node.
		// Must use a separate flow to Output(config.BridgeOFPort), otherwise OVS will drop the packet:
		//   output:NXM_NX_REG1[]
		//   >> output port 4294967294 is out of range
		//   Datapath actions: drop
		// TODO(gran): support Traceflow
		c.pipeline[l2ForwardingCalcTable].BuildFlow(priorityNormal).
			MatchDstMAC(c.nodeConfig.UplinkNetConfig.MAC).
			Action().LoadToRegField(TargetOFPortField, config.BridgeOFPort).
			Action().LoadRegMark(OFPortFoundRegMark).
			Action().GotoTable(conntrackCommitTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		c.pipeline[L2ForwardingOutTable].BuildFlow(priorityHigh).MatchProtocol(binding.ProtocolIP).
			MatchRegMark(ToBridgeRegMark).
			MatchRegMark(OFPortFoundRegMark).
			Action().Output(config.BridgeOFPort).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Handle outgoing packet from AntreaFlexibleIPAM Pods. Broadcast is not supported.
		c.pipeline[l2ForwardingCalcTable].BuildFlow(priorityLow).
			MatchRegMark(AntreaFlexibleIPAMRegMark).
			Action().LoadToRegField(TargetOFPortField, config.UplinkOFPort).
			Action().LoadRegMark(OFPortFoundRegMark).
			Action().GotoTable(conntrackCommitTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	return flows
}

func (c *client) l3FwdFlowToRemoteViaRouting(localGatewayMAC net.HardwareAddr, remoteGatewayMAC net.HardwareAddr,
	category cookie.Category, peerIP net.IP, peerPodCIDR *net.IPNet) []binding.Flow {
	return []binding.Flow{c.l3FwdFlowToRemoteViaGW(localGatewayMAC, *peerPodCIDR, category, false)}
}
