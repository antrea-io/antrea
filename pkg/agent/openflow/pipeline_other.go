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

	binding "antrea.io/antrea/pkg/ovs/openflow"
)

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
	return []binding.Flow{f.l3FwdFlowToRemoteViaGW(localGatewayMAC, *peerPodCIDR)}
}
