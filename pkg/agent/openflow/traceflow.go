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
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

type featureTraceflow struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol

	tfFlowCache *flowCategoryCache

	gatewayIPs            map[binding.Protocol]net.IP
	ovsMetersAreSupported bool
	enableProxy           bool
	enableAntreaPolicy    bool
	supportEncap          bool
}

func (c *featureTraceflow) getFeatureID() featureID {
	return Traceflow
}

func newFeatureTraceflow(cookieAllocator cookie.Allocator,
	ipProtocols []binding.Protocol,
	ovsDatapathType ovsconfig.OVSDatapathType,
	nodeConfig *config.NodeConfig,
	enableProxy,
	enableAntreaPolicy,
	supportEncap bool) feature {
	gatewayIPs := make(map[binding.Protocol]net.IP)
	for _, ipProtocol := range ipProtocols {
		if ipProtocol == binding.ProtocolIP && nodeConfig.GatewayConfig.IPv4 != nil {
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv4
		} else if ipProtocol == binding.ProtocolIPv6 && nodeConfig.GatewayConfig.IPv6 != nil {
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv6
		}
	}

	return &featureTraceflow{
		cookieAllocator:       cookieAllocator,
		ipProtocols:           ipProtocols,
		tfFlowCache:           newFlowCategoryCache(),
		ovsMetersAreSupported: ovsMetersAreSupported(ovsDatapathType),
		enableProxy:           enableProxy,
		enableAntreaPolicy:    enableAntreaPolicy,
		supportEncap:          supportEncap,
	}
}
