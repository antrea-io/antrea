// Copyright 2023 Antrea Authors
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

package types

import (
	"net"

	"antrea.io/antrea/pkg/ovs/openflow"
)

// ServiceConfig contains the configuration needed to install flows for a given Service entrypoint.
type ServiceConfig struct {
	ServiceIP          net.IP
	ServicePort        uint16
	Protocol           openflow.Protocol
	TrafficPolicyLocal bool
	LocalGroupID       openflow.GroupIDType
	ClusterGroupID     openflow.GroupIDType
	AffinityTimeout    uint16
	// IsExternal indicates that whether the Service is externally accessible.
	// It's true for NodePort, LoadBalancerIP and ExternalIP.
	IsExternal bool
	IsNodePort bool
	// IsNested indicates the whether Service's Endpoints are ClusterIPs of other Services. It's used in multi-cluster.
	IsNested bool
	// IsDSR indicates that whether the Service works in Direct Server Return mode.
	IsDSR bool
}

func (c *ServiceConfig) TrafficPolicyGroupID() openflow.GroupIDType {
	if c.TrafficPolicyLocal {
		return c.LocalGroupID
	} else {
		return c.ClusterGroupID
	}
}
