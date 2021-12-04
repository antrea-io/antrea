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

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featureEgress struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol

	cachedFlows *flowCategoryCache
	fixedFlows  []binding.Flow

	nodeIPs    map[binding.Protocol]net.IP
	gatewayMAC net.HardwareAddr

	category cookie.Category
}

func (f *featureEgress) getFeatureName() string {
	return "Egress"
}

func newFeatureEgress(cookieAllocator cookie.Allocator,
	ipProtocols []binding.Protocol,
	nodeConfig *config.NodeConfig) *featureEgress {
	nodeIPs := make(map[binding.Protocol]net.IP)
	for _, ipProtocol := range ipProtocols {
		if ipProtocol == binding.ProtocolIP {
			nodeIPs[ipProtocol] = nodeConfig.NodeIPv4Addr.IP
		} else if ipProtocol == binding.ProtocolIPv6 {
			nodeIPs[ipProtocol] = nodeConfig.NodeIPv6Addr.IP
		}
	}
	return &featureEgress{
		cachedFlows:     newFlowCategoryCache(),
		cookieAllocator: cookieAllocator,
		ipProtocols:     ipProtocols,
		nodeIPs:         nodeIPs,
		gatewayMAC:      nodeConfig.GatewayConfig.MAC,
		category:        cookie.Egress,
	}
}

func (f *featureEgress) initFlows() []binding.Flow {
	return []binding.Flow{}
}

func (f *featureEgress) replayFlows() []binding.Flow {
	var flows []binding.Flow

	// Get fixed flows.
	for _, flow := range f.fixedFlows {
		flow.Reset()
		flows = append(flows, flow)
	}
	// Get cached flows.
	flows = append(flows, getCachedFlows(f.cachedFlows)...)

	return flows
}
