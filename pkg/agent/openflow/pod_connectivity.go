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

type featurePodConnectivity struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol

	nodeFlowCache       *flowCategoryCache
	podFlowCache        *flowCategoryCache
	gatewayFlows        []binding.Flow
	defaultTunnelFlows  []binding.Flow
	hostNetworkingFlows []binding.Flow

	gatewayIPs    map[binding.Protocol]net.IP
	ctZones       map[binding.Protocol]int
	nodeConfig    *config.NodeConfig
	networkConfig *config.NetworkConfig

	connectUplinkToBridge bool
}

func (c *featurePodConnectivity) getFeatureID() featureID {
	return PodConnectivity
}

func newFeaturePodConnectivity(
	cookieAllocator cookie.Allocator,
	ipProtocols []binding.Protocol,
	nodeConfig *config.NodeConfig,
	networkConfig *config.NetworkConfig,
	connectUplinkToBridge bool) feature {
	ctZones := make(map[binding.Protocol]int)
	gatewayIPs := make(map[binding.Protocol]net.IP)
	for _, ipProtocol := range ipProtocols {
		if ipProtocol == binding.ProtocolIP {
			ctZones[ipProtocol] = CtZone
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv4
		} else if ipProtocol == binding.ProtocolIPv6 {
			ctZones[ipProtocol] = CtZoneV6
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv6
		}
	}

	return &featurePodConnectivity{
		cookieAllocator:       cookieAllocator,
		ipProtocols:           ipProtocols,
		nodeFlowCache:         newFlowCategoryCache(),
		podFlowCache:          newFlowCategoryCache(),
		gatewayIPs:            gatewayIPs,
		ctZones:               ctZones,
		nodeConfig:            nodeConfig,
		networkConfig:         networkConfig,
		connectUplinkToBridge: connectUplinkToBridge,
	}
}
