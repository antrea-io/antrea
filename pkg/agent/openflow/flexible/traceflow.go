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

package flexible

import (
	"net"

	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
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
