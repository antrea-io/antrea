// Copyright 2019 Antrea Authors
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

package flexible

import (
	"net"
	"sync"

	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featureNetworkPolicy struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol
	bridge          binding.Bridge

	// globalConjMatchFlowCache is a global map for conjMatchFlowContext. The key is a string generated from the
	// conjMatchFlowContext.
	globalConjMatchFlowCache map[string]*conjMatchFlowContext
	conjMatchFlowLock        sync.Mutex // Lock for access globalConjMatchFlowCache
	// policyCache is a storage that supports listing policyRuleConjunction with different indexers.
	// It's guaranteed that one policyRuleConjunction is processed by at most one goroutine at any given time.
	policyCache       cache.Indexer
	flowCategoryCache *flowCategoryCache
	packetInHandlers  map[uint8]map[string]PacketInHandler

	gatewayIPs map[binding.Protocol]net.IP

	proxyAll              bool
	ovsMetersAreSupported bool
	enableDenyTracking    bool
	enableAntreaPolicy    bool
	// deterministic represents whether to generate flows deterministically.
	// For example, if a flow has multiple actions, setting it to true can get consistent flow.
	// Enabling it may carry a performance impact. It's disabled by default and should only be used in testing.
	deterministic bool
}

func (c *featureNetworkPolicy) getFeatureID() featureID {
	return NetworkPolicy
}
