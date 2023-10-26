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
	"sync"

	"antrea.io/libOpenflow/openflow15"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featureEgress struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol

	cachedFlows *flowCategoryCache
	cachedMeter sync.Map

	exceptCIDRs map[binding.Protocol][]net.IPNet
	nodeIPs     map[binding.Protocol]net.IP
	gatewayMAC  net.HardwareAddr

	category                   cookie.Category
	enableEgressTrafficShaping bool
}

func (f *featureEgress) getFeatureName() string {
	return "Egress"
}

func newFeatureEgress(cookieAllocator cookie.Allocator,
	ipProtocols []binding.Protocol,
	nodeConfig *config.NodeConfig,
	egressConfig *config.EgressConfig,
	enableEgressTrafficShaping bool) *featureEgress {
	exceptCIDRs := make(map[binding.Protocol][]net.IPNet)
	for _, cidr := range egressConfig.ExceptCIDRs {
		if cidr.IP.To4() == nil {
			exceptCIDRs[binding.ProtocolIPv6] = append(exceptCIDRs[binding.ProtocolIPv6], cidr)
		} else {
			exceptCIDRs[binding.ProtocolIP] = append(exceptCIDRs[binding.ProtocolIP], cidr)
		}
	}

	nodeIPs := make(map[binding.Protocol]net.IP)
	for _, ipProtocol := range ipProtocols {
		if ipProtocol == binding.ProtocolIP {
			nodeIPs[ipProtocol] = nodeConfig.NodeIPv4Addr.IP
		} else if ipProtocol == binding.ProtocolIPv6 {
			nodeIPs[ipProtocol] = nodeConfig.NodeIPv6Addr.IP
		}
	}
	return &featureEgress{
		cachedFlows:                newFlowCategoryCache(),
		cachedMeter:                sync.Map{},
		cookieAllocator:            cookieAllocator,
		exceptCIDRs:                exceptCIDRs,
		ipProtocols:                ipProtocols,
		nodeIPs:                    nodeIPs,
		gatewayMAC:                 nodeConfig.GatewayConfig.MAC,
		category:                   cookie.Egress,
		enableEgressTrafficShaping: enableEgressTrafficShaping,
	}
}

func (f *featureEgress) initFlows() []*openflow15.FlowMod {
	// This installs the flows to enable Pods to communicate to the external IP addresses. The flows identify the packets
	// from local Pods to the external IP address, and mark the packets to be SNAT'd with the configured SNAT IPs.
	initialFlows := f.externalFlows()
	if f.enableEgressTrafficShaping {
		initialFlows = append(initialFlows, f.egressQoSDefaultFlow())
	}
	return GetFlowModMessages(initialFlows, binding.AddMessage)
}

func (f *featureEgress) replayFlows() []*openflow15.FlowMod {
	return getCachedFlowMessages(f.cachedFlows)
}

func (f *featureEgress) initGroups() []binding.OFEntry {
	return nil
}

func (f *featureEgress) replayGroups() []binding.OFEntry {
	return nil
}

func (f *featureEgress) replayMeters() []binding.OFEntry {
	var meters []binding.OFEntry
	f.cachedMeter.Range(func(id, value interface{}) bool {
		meter := value.(binding.Meter)
		meter.Reset()
		meters = append(meters, meter)
		return true
	})
	return meters
}
