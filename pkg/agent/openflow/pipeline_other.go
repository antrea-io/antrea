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

	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

// externalFlows returns the flows needed to enable SNAT for external traffic.
func (c *client) externalFlows(nodeIP net.IP, localSubnet net.IPNet, localGatewayMAC net.HardwareAddr) []binding.Flow {
	if !c.enableEgress {
		return nil
	}
	return c.snatCommonFlows(nodeIP, localSubnet, localGatewayMAC, cookie.SNAT)
}

func (c *client) snatMarkFlows(snatIP net.IP, mark uint32) []binding.Flow {
	return []binding.Flow{c.snatIPFromTunnelFlow(snatIP, mark)}
}

func (c *client) l3FwdFlowToRemoteViaRouting(localGatewayMAC net.HardwareAddr, remoteGatewayMAC net.HardwareAddr,
	category cookie.Category, peerIP net.IP, peerPodCIDR *net.IPNet) []binding.Flow {
	return []binding.Flow{c.l3FwdFlowToRemoteViaGW(localGatewayMAC, *peerPodCIDR, category)}
}
