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

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featureService struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol
	bridge          binding.Bridge

	cachedFlows *flowCategoryCache
	fixedFlows  []binding.Flow
	groupCache  sync.Map

	gatewayIPs  map[binding.Protocol]net.IP
	virtualIPs  map[binding.Protocol]net.IP
	dnatCtZones map[binding.Protocol]int
	snatCtZones map[binding.Protocol]int
	gatewayMAC  net.HardwareAddr

	enableProxy           bool
	proxyAll              bool
	connectUplinkToBridge bool
	ctZoneSrcField        *binding.RegField

	category cookie.Category
}

func (f *featureService) getFeatureName() string {
	return "Service"
}

func newFeatureService(
	cookieAllocator cookie.Allocator,
	ipProtocols []binding.Protocol,
	nodeConfig *config.NodeConfig,
	bridge binding.Bridge,
	enableProxy,
	proxyAll,
	connectUplinkToBridge bool) *featureService {
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
		cookieAllocator:       cookieAllocator,
		ipProtocols:           ipProtocols,
		bridge:                bridge,
		cachedFlows:           newFlowCategoryCache(),
		groupCache:            sync.Map{},
		gatewayIPs:            gatewayIPs,
		virtualIPs:            virtualIPs,
		dnatCtZones:           dnatCtZones,
		snatCtZones:           snatCtZones,
		gatewayMAC:            nodeConfig.GatewayConfig.MAC,
		enableProxy:           enableProxy,
		proxyAll:              proxyAll,
		connectUplinkToBridge: connectUplinkToBridge,
		ctZoneSrcField:        getZoneSrcField(connectUplinkToBridge),
		category:              cookie.Service,
	}
}

func (f *featureService) initFlows() []binding.Flow {
	var flows []binding.Flow
	if f.enableProxy {
		flows = append(flows, f.conntrackFlows()...)
		flows = append(flows, f.preRoutingClassifierFlows()...)
		flows = append(flows, f.l3FwdFlowsToExternalEndpoint()...)
		flows = append(flows, f.gatewaySNATFlows()...)
		flows = append(flows, f.snatConntrackFlows()...)
	}
	return flows
}

func (f *featureService) replayFlows() []binding.Flow {
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

func (f *featureService) replayGroups() {
	f.groupCache.Range(func(id, value interface{}) bool {
		group := value.(binding.Group)
		group.Reset()
		if err := group.Add(); err != nil {
			klog.Errorf("Error when replaying cached group %d: %v", id, err)
		}
		return true
	})
}
