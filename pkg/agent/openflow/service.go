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
	"sync"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featureService struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol
	bridge          binding.Bridge

	serviceFlowCache    *flowCategoryCache
	defaultServiceFlows []binding.Flow
	groupCache          sync.Map

	gatewayIPs  map[binding.Protocol]net.IP
	virtualIPs  map[binding.Protocol]net.IP
	dnatCtZones map[binding.Protocol]int
	snatCtZones map[binding.Protocol]int
	gatewayMAC  net.HardwareAddr

	enableProxy bool
	proxyAll    bool
}

func (c *featureService) getFeatureID() featureID {
	return Service
}

func newFeatureService(
	cookieAllocator cookie.Allocator,
	ipProtocols []binding.Protocol,
	nodeConfig *config.NodeConfig,
	bridge binding.Bridge,
	enableProxy,
	proxyAll bool) feature {
	gatewayIPs := make(map[binding.Protocol]net.IP)
	virtualIPs := make(map[binding.Protocol]net.IP)
	dnatCtZones := make(map[binding.Protocol]int)
	snatCtZones := make(map[binding.Protocol]int)
	for _, ipProtocol := range ipProtocols {
		if ipProtocol == binding.ProtocolIP {
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv4
			virtualIPs[ipProtocol] = config.VirtualServiceIPv4
			dnatCtZones[ipProtocol] = CtZone
			snatCtZones[ipProtocol] = SNATCtZone
		} else if ipProtocol == binding.ProtocolIPv6 {
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv6
			virtualIPs[ipProtocol] = config.VirtualServiceIPv6
			dnatCtZones[ipProtocol] = CtZoneV6
			snatCtZones[ipProtocol] = SNATCtZoneV6
		}
	}

	return &featureService{
		cookieAllocator:  cookieAllocator,
		ipProtocols:      ipProtocols,
		bridge:           bridge,
		serviceFlowCache: newFlowCategoryCache(),
		groupCache:       sync.Map{},
		gatewayIPs:       gatewayIPs,
		virtualIPs:       virtualIPs,
		dnatCtZones:      dnatCtZones,
		snatCtZones:      snatCtZones,
		gatewayMAC:       nodeConfig.GatewayConfig.MAC,
		enableProxy:      enableProxy,
		proxyAll:         proxyAll,
	}
}
