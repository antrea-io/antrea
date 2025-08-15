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
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

func (f *featurePodConnectivity) matchUplinkInPortInClassifierTable(flowBuilder binding.FlowBuilder) binding.FlowBuilder {
	return flowBuilder.MatchInPort(f.uplinkPort)
}

// hostBridgeUplinkFlows generates the flows that forward traffic between the bridge local port and the uplink port to
// support the host traffic.
// TODO(gran): sync latest changes from pipeline_windows.go
func (f *featurePodConnectivity) hostBridgeUplinkFlows() []binding.Flow {
	// outputToBridgeRegMark marks that the output interface is OVS bridge.
	outputToBridgeRegMark := binding.NewRegMark(TargetOFPortField, f.hostIfacePort)
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	flows := f.hostBridgeLocalFlows()
	if f.networkConfig.IPv4Enabled {
		flows = append(flows,
			// This generates the flow to forward ARP packets from uplink port in normal way since uplink port is set to enable
			// flood.
			ARPSpoofGuardTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchInPort(f.uplinkPort).
				MatchProtocol(binding.ProtocolARP).
				Action().Normal().
				Done(),
			// This generates the flow to forward ARP from bridge local port in normal way since bridge port is set to enable
			// flood.
			ARPSpoofGuardTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchInPort(f.hostIfacePort).
				MatchProtocol(binding.ProtocolARP).
				Action().Normal().
				Done())
	}
	flows = append(flows,
		// Handle packet to Node.
		// Must use a separate flow to Output(config.BridgeOFPort), otherwise OVS will drop the packet:
		//   output:NXM_NX_REG1[]
		//   >> output port 4294967294 is out of range
		//   Datapath actions: drop
		// TODO(gran): support Traceflow
		L2ForwardingCalcTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchDstMAC(f.nodeConfig.UplinkNetConfig.MAC).
			Action().LoadToRegField(TargetOFPortField, f.hostIfacePort).
			Action().LoadRegMark(OutputToOFPortRegMark).
			Action().GotoStage(stageConntrack).
			Done(),
		OutputTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(binding.ProtocolIP).
			MatchRegMark(outputToBridgeRegMark, OutputToOFPortRegMark).
			Action().Output(f.hostIfacePort).
			Done(),
		// Handle outgoing packet from AntreaFlexibleIPAM Pods. Broadcast is not supported.
		L2ForwardingCalcTable.ofTable.BuildFlow(priorityLow).
			Cookie(cookieID).
			MatchRegMark(AntreaFlexibleIPAMRegMark).
			Action().LoadToRegField(TargetOFPortField, f.uplinkPort).
			Action().LoadRegMark(OutputToOFPortRegMark).
			Action().GotoStage(stageConntrack).
			Done())
	return flows
}

func (f *featurePodConnectivity) l3FwdFlowToRemoteViaRouting(localGatewayMAC net.HardwareAddr,
	remoteGatewayMAC net.HardwareAddr,
	peerIP net.IP,
	peerPodCIDR *net.IPNet) []binding.Flow {
	var flows []binding.Flow
	if f.networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeNone &&
		!f.connectUplinkToBridge {
		// These two flows are installed only when traffic mode is `noEncap` or `hybrid` and the remote Node is reachable
		// via a Node host route (not via tunnel). They modify MAC addresses on inter‑Node Pod‑to‑Pod packets:
		//  - The source MAC is replaced with the local gateway’s MAC.
		//  - The destination MAC is replaced with the remote transport interface’s MAC.
		// After that, packets are redirected from antrea-gw0 ingress to the transport interface egress, bypassing the Node
		// host network. The remote Node receives the packets correctly via its transport interface.
		// Note: This bypass is supported only in noEncap or hybrid mode. Additionally, the transport interface is not
		// connected to OVS, and the traffic is not encrypted.
		cookieID := f.cookieAllocator.Request(f.category).Raw()
		ipProtocol := getIPProtocol(peerPodCIDR.IP)
		var srcPodCIDR net.IPNet
		if ipProtocol == binding.ProtocolIPv6 {
			srcPodCIDR = *f.nodeConfig.PodIPv6CIDR
		} else {
			srcPodCIDR = *f.nodeConfig.PodIPv4CIDR
		}
		flows = append(flows,
			L3ForwardingTable.ofTable.BuildFlow(priorityHigh+1).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchSrcIPNet(srcPodCIDR).
				MatchDstIPNet(*peerPodCIDR).
				Action().SetSrcMAC(f.nodeConfig.GatewayConfig.MAC).
				Action().SetDstMAC(remoteGatewayMAC).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().GotoTable(L3DecTTLTable.GetID()).
				Done(),
			L2ForwardingCalcTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchDstMAC(remoteGatewayMAC).
				Action().LoadToRegField(TargetOFPortField, f.gatewayPort).
				Action().LoadRegMark(OutputToOFPortRegMark).
				Action().GotoStage(stageConntrack).
				Done())
	}
	flows = append(flows, f.l3FwdFlowToRemoteViaGW(localGatewayMAC, *peerPodCIDR))
	return flows
}
